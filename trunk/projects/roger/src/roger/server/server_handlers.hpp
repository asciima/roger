#ifndef _SERVER_HANDLERS_HPP
#define _SERVER_HANDLERS_HPP

#include <wawo.h>

#include "dns_resolver.hpp"
#include "../shared/shared.hpp"

namespace roger {

	void flush_up_done(WWRP<forward_ctx> const& fctx, int flushrt);
	inline void _do_flush_up(WWRP<forward_ctx> const& fctx) {
		WAWO_ASSERT(fctx->ch_stream_ctx->event_poller()->in_event_loop());
		WAWO_ASSERT(fctx->up_state == ctx_write_state::WS_IDLE);
		switch (fctx->state) {
			case LOOKUP_SERVER_NAME:
			case DIAL_SERVER:
			case SERVER_CONNECTED:
			{
				if (fctx->up_to_server_packets.size()) {
					WWRP<wawo::net::channel_promise> f = fctx->ch_server_ctx->make_channel_promise();
					f->add_listener([fctx](WWRP<wawo::net::channel_future> const& f) {
						fctx->ch_stream_ctx->event_poller()->execute([fctx, rt = f->get()]() {
							flush_up_done(fctx, rt);
						});
					});

					WAWO_ASSERT(fctx->up_state == ctx_write_state::WS_IDLE);
					fctx->up_state = ctx_write_state::WS_WRITING;
					WAWO_ASSERT(fctx->up_to_server_packets.size());
					WWRP<packet>& outp = fctx->up_to_server_packets.front();
					fctx->ch_server_ctx->write(outp, f);
				}
				else {
					if (fctx->stream_read_closed) {
						if (fctx->ch_server_ctx != NULL) {
							TRACE_SERVER_SIDE_CTX("[server][s%u]no up to server packets left and stream read closed, close server write", fctx->ch_stream_ctx->ch->ch_id());
							fctx->ch_server_ctx->shutdown_write();
						}
					}
				}
			}
			break;
			default:
			{
				TRACE_SERVER_SIDE_CTX("[server][s%u][%s]cancel dialing server", fctx->ch_stream_ctx->ch->ch_id(), server_state_str[fctx->state]);
				WAWO_ASSERT(fctx->ch_server_ctx == NULL);
				fctx->ch_stream_ctx->close();
			}
			break;
		}
	}
	inline void flush_up_done(WWRP<forward_ctx> const& fctx, int flushrt ) {
		WAWO_ASSERT(fctx->ch_stream_ctx->event_poller()->in_event_loop());
		WAWO_ASSERT(fctx->up_state == ctx_write_state::WS_WRITING);
		fctx->up_state = ctx_write_state::WS_IDLE;
		if (flushrt == wawo::OK) {
			TRACE_SERVER_SIDE_CTX("[server][s%u]write to server done: %u",fctx->ch_stream_ctx->ch->ch_id(), fctx->up_to_server_packets.front()->len() );
			WAWO_ASSERT(fctx->up_to_server_packets.size());
			fctx->up_to_server_packets.pop();
			_do_flush_up(fctx);
		}
		else if (flushrt == wawo::E_CHANNEL_WRITE_BLOCK) {
			//IGNORE
			//fctx->up_state = forward_ctx_write_state::WS_BLOCKED;
		}
		else {
			fctx->ch_server_ctx->close();
		}
	}
	inline void flush_up(WWRP<forward_ctx> const& fctx, WWRP<wawo::packet> const& income, bool flush = true ) {
		WAWO_ASSERT(fctx->ch_stream_ctx->event_poller()->in_event_loop());
		if (income != NULL) {
			fctx->up_to_server_packets.push(income);
		}
		if (fctx->up_state == ctx_write_state::WS_WRITING && flush ) {
			return;
		}
		_do_flush_up(fctx);
	}
	
	void flush_down_done(WWRP<forward_ctx> const& fctx, int flushrt);
	inline void _do_flush_down(WWRP<forward_ctx> const& fctx) {
		WAWO_ASSERT(fctx->ch_stream_ctx->event_poller()->in_event_loop());
		if (fctx->down_to_stream_packets.size()) {
			WWRP<wawo::net::channel_promise> f = fctx->ch_stream_ctx->make_channel_promise();
			f->add_listener([fctx](WWRP<wawo::net::channel_future> const& f) {
				fctx->ch_stream_ctx->event_poller()->execute([fctx,rt=f->get()]() {
					flush_down_done(fctx, rt);
				});
			});

			WAWO_ASSERT(fctx->down_state == ctx_write_state::WS_IDLE);
			fctx->down_state = ctx_write_state::WS_WRITING;
			WAWO_ASSERT(fctx->down_to_stream_packets.size());
			WWRP<packet> outp = fctx->down_to_stream_packets.front();
			fctx->ch_stream_ctx->write(outp, f);
		} else {
			if (fctx->server_read_closed) {
				TRACE_SERVER_SIDE_CTX("[server][s%u]no down packets left and server_read_closed, close stream write", fctx->ch_stream_ctx->ch->ch_id());
				WAWO_ASSERT(fctx->ch_stream_ctx != NULL);
				fctx->ch_stream_ctx->shutdown_write();
			}
		}
	}

	inline void flush_down_done(WWRP<forward_ctx> const& fctx, int flushrt) {
		WAWO_ASSERT(fctx->ch_stream_ctx->event_poller()->in_event_loop());
		WAWO_ASSERT(fctx->down_state == ctx_write_state::WS_WRITING);
		fctx->down_state = ctx_write_state::WS_IDLE;
		if (flushrt == wawo::OK) {
			WAWO_ASSERT(fctx->down_to_stream_packets.size());
			fctx->down_to_stream_packets.pop();
			_do_flush_down(fctx);
		}
		else if (flushrt == wawo::E_CHANNEL_WRITE_BLOCK) {
			//IGNORE
			//fctx->down_state = forward_ctx_write_state::WS_BLOCKED;
		}
		else {
			//ERROR
			//DO CLOSE
			//fctx->ch_server_ctx->close();
			fctx->ch_stream_ctx->close();
		}
	}

	inline void flush_down(WWRP<forward_ctx> const& fctx, WWRP<wawo::packet> const& income) {
		WAWO_ASSERT(fctx->ch_stream_ctx != NULL);
		WAWO_ASSERT(fctx->ch_stream_ctx->event_poller()->in_event_loop());
		if (income != NULL) {
			fctx->down_to_stream_packets.push(income);
		}
		if (fctx->down_state == ctx_write_state::WS_WRITING ) {
			return;
		}
		_do_flush_down(fctx);
	}

	class server_handler :
		public wawo::net::channel_activity_handler_abstract,
		public wawo::net::channel_inbound_handler_abstract
	{
	public:
		void connected(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WAWO_ASSERT(ctx != NULL);
			WWRP<forward_ctx> fctx = ctx->ch->get_ctx<forward_ctx>();
			WAWO_ASSERT(fctx != NULL);
			WAWO_ASSERT(fctx->ch_stream_ctx != NULL);
			fctx->ch_stream_ctx->event_poller()->execute([fctx,ctx]() {
				TRACE_SERVER_SIDE_CTX("[server][s%u]server connected", fctx->ch_stream_ctx->ch->ch_id());
				WAWO_ASSERT(fctx->ch_server_ctx == NULL);
				WAWO_ASSERT(fctx->state == DIAL_SERVER_OK);
				fctx->state = SERVER_CONNECTED;
				fctx->ch_server_ctx = ctx;
				WWRP<wawo::packet> firstp;
				if (fctx->client_up_first_packet->len()) {
					WWRP<wawo::packet> _firstp = wawo::make_ref<wawo::packet>(fctx->client_up_first_packet->len());
					_firstp->write(fctx->client_up_first_packet->begin(), fctx->client_up_first_packet->len());
					fctx->client_up_first_packet->reset();
					firstp = _firstp;
				}
				//stream close read is included
				flush_up(fctx, firstp);
			});
		}

		void read_shutdowned(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<forward_ctx> fctx = ctx->ch->get_ctx<forward_ctx>();
			WAWO_ASSERT(fctx != NULL);
			WAWO_ASSERT (fctx->ch_stream_ctx != NULL);
			fctx->ch_stream_ctx->event_poller()->execute([fctx]() {
				fctx->server_read_closed = true;
				TRACE_SERVER_SIDE_CTX("[server][s%u]server read shutdown, flush_down", fctx->ch_stream_ctx->ch->ch_id());
				flush_down(fctx, NULL);
			});
		}

		void closed(WWRP<wawo::net::channel_handler_context > const& ctx) {
			WWRP<forward_ctx> fctx = ctx->ch->get_ctx<forward_ctx>();
			WAWO_ASSERT(fctx != NULL);
			fctx->ch_stream_ctx->event_poller()->execute([fctx, ctx]() {
				TRACE_SERVER_SIDE_CTX("[server][s%u]server closed", fctx->ch_stream_ctx->ch->ch_id());
				WAWO_ASSERT(fctx->ch_stream_ctx != NULL);
				WAWO_ASSERT(fctx->server_read_closed == true);
				ctx->ch->set_ctx(NULL);
			});
		}

		void write_block(WWRP<channel_handler_context> const& ctx) {
			WWRP<forward_ctx> fctx = ctx->ch->get_ctx<forward_ctx>();
			WAWO_ASSERT(fctx != NULL);
			fctx->ch_stream_ctx->ch->ch_async_io_end_read();
		}

		void write_unblock(WWRP<channel_handler_context> const& ctx) {
			WWRP<forward_ctx> fctx = ctx->ch->get_ctx<forward_ctx>();
			WAWO_ASSERT(fctx != NULL);
			fctx->ch_stream_ctx->ch->ch_async_io_begin_read();
			flush_up(fctx,NULL);
		}

		void read(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::packet> const& income) {
			WWRP<forward_ctx> fctx = ctx->ch->get_ctx<forward_ctx>();
			WAWO_ASSERT(fctx != NULL);
			fctx->ch_stream_ctx->event_poller()->execute([fctx,income]() {
				flush_down(fctx, income);
			});
		}
	};

	void dial_server_by_ip(WWRP<forward_ctx> const& fctx) {
		WAWO_ASSERT((fctx->dst_addrv4.is_null()));
		WAWO_ASSERT(fctx->dst_port > 0);
		WAWO_ASSERT(fctx->dst_ipv4 > 0);

		fctx->dst_addrv4.setipv4(fctx->dst_ipv4);
		fctx->dst_addrv4.setport(fctx->dst_port);
		fctx->dst_addrv4.setfamily(F_AF_INET);

		fctx->state = DIAL_SERVER;
		fctx->ts_server_connect_start = wawo::time::curr_microseconds();

		std::string dialurl = "tcp://" + fctx->dst_addrv4.dotip() + ":"+ std::to_string(fctx->dst_addrv4.port());
		WWRP<wawo::net::channel_future> dial_f = wawo::net::socket::dial(dialurl, [fctx](WWRP<wawo::net::channel> const& ch) {
			WWRP<server_handler> h = wawo::make_ref<server_handler>();
			ch->pipeline()->add_last(h);
		}, roger::server_cfg );

		dial_f->add_listener([fctx](WWRP<wawo::net::channel_future> const& f) {
			int rt = f->get();
			if (rt == wawo::OK) {
				TRACE_SERVER_SIDE_CTX("[server][forward_ctx][s%u--%s:%u][#%d]dial ok", fctx->ch_stream_ctx->ch->ch_id(), wawo::net::ipv4todotip(fctx->dst_ipv4).c_str(), fctx->dst_port, f->channel()->ch_id() );
				f->channel()->set_ctx(fctx);
			}

			fctx->ch_stream_ctx->event_poller()->execute([fctx,rt]() {
				fctx->ts_server_connect_done = wawo::time::curr_microseconds();
				WAWO_ASSERT(fctx->state == DIAL_SERVER);
				if (rt != wawo::OK) {
					WAWO_ASSERT(fctx != NULL);
					WAWO_ASSERT(fctx->ch_server_ctx == NULL);
					WAWO_ASSERT(fctx->ch_stream_ctx != NULL);
					fctx->state = DIAL_SERVER_FAILED;
					WAWO_ASSERT(fctx->ch_server_ctx == NULL);
					WAWO_ASSERT(fctx->down_to_stream_packets.size() == 0);
					fctx->server_read_closed = true;
					WAWO_ERR("[server][forward_ctx][s%u--%s:%u][%s]dial failed: %d", fctx->ch_stream_ctx->ch->ch_id(), wawo::net::ipv4todotip(fctx->dst_ipv4).c_str(), fctx->dst_port, fctx->dst_domain.c_str(), rt );
				} else {
					//TRACE_SERVER_SIDE_CTX("[server][forward_ctx][s%u--%s:%u][%s]dial ok", fctx->ch_stream_ctx->ch->ch_id(), wawo::net::ipv4todotip(fctx->dst_ipv4).c_str(), fctx->dst_port,fctx->dst_domain.c_str() );
					fctx->state = DIAL_SERVER_OK;
				}

				//write connect rt
				WWRP<packet> outp = wawo::make_ref<packet>(64);
				outp->write<int32_t>(rt);
				flush_down(fctx, outp);

				WAWO_ASSERT(fctx->ts_dns_lookup_done>=fctx->ts_dns_lookup_start);
				u64_t dns_lookup_time = fctx->ts_dns_lookup_done - fctx->ts_dns_lookup_start;
				WAWO_ASSERT(fctx->ts_server_connect_done>=fctx->ts_server_connect_start);
				u64_t server_connect_time = fctx->ts_server_connect_done - fctx->ts_server_connect_start;
				if (dns_lookup_time > 50000) {
					WAWO_INFO("connect statistic: dns_lookup: %.3f ms, connect: %.3f ms, connect result: %d, domain: %s", dns_lookup_time / 1000.0, server_connect_time / 1000.0, rt, fctx->dst_domain.c_str());
				}
			});
		});
	}

	static void dns_resolve_success(std::vector<in_addr> const& in_addrs, WWRP<wawo::ref_base> const& cookie_);
	inline static void dns_resolve_error(int const& code, WWRP<wawo::ref_base > const& cookie_) {
		WAWO_ASSERT(cookie_ != NULL);
		WWRP<forward_ctx> fctx = wawo::static_pointer_cast<forward_ctx>(cookie_);
		fctx->ts_dns_lookup_done = wawo::time::curr_microseconds();
		WAWO_ASSERT(code <= E_DNSLOOKUP_RETURN_NO_IP && code>= E_DNS_BADQUERY );

		if (code == E_DNS_TEMPORARY_ERROR && (fctx->dns_try_time) < 3) {

			WWRP<wawo::timer> retry_timer = wawo::make_ref<wawo::timer>( std::chrono::milliseconds(1*(fctx->dns_try_time+1)<<1), WWRP<ref_base>(NULL),
				[fctx, code] (WWRP<wawo::timer> const& t, WWRP<wawo::ref_base> const& c) {
					WAWO_ASSERT(fctx->query != NULL);
					WAWO_ERR("[server][forward_ctx][%s][s%d]dns(%s) lookup failed: %d, try time: %u", server_state_str[fctx->state], fctx->ch_stream_ctx->ch->ch_id(), fctx->dst_domain.c_str(), code, fctx->dns_try_time);
					fctx->query = dns_resolver::instance()->async_resolve(fctx->dst_domain, fctx, &roger::dns_resolve_success, &roger::dns_resolve_error);
					++fctx->dns_try_time;
					(void)t;
					(void)c;
				});

			fctx->ch_stream_ctx->event_poller()->start_timer(retry_timer);
			return;
		}

		fctx->ch_stream_ctx->event_poller()->execute([fctx,code]() {
			WAWO_ASSERT(fctx->query != NULL);
			fctx->query = NULL;
			WAWO_ASSERT(fctx->ch_stream_ctx != NULL);
			fctx->state = LOOKUP_SERVER_NAEM_FAILED;
			WAWO_ASSERT(code != wawo::OK);
			WAWO_ASSERT(fctx->ch_server_ctx == NULL);
			WAWO_ASSERT(fctx->down_to_stream_packets.size() == 0);
			fctx->server_read_closed = true;
			WWRP<wawo::packet> outp = wawo::make_ref<wawo::packet>(64);
			outp->write<int32_t>(code);
			flush_down(fctx, outp);
			WAWO_ERR("[server][forward_ctx][%s][s%d]dns(%s) lookup failed: %d", server_state_str[fctx->state], fctx->ch_stream_ctx->ch->ch_id(), fctx->dst_domain.c_str(), code);
		});
	}
	inline static void dns_resolve_success(std::vector<in_addr> const& in_addrs, WWRP<wawo::ref_base> const& cookie_) {
		WAWO_ASSERT(cookie_ != NULL);
		WWRP<forward_ctx> fctx = wawo::static_pointer_cast<forward_ctx>(cookie_);
		WAWO_ASSERT(fctx->ch_server_ctx == NULL);

		//sometimes we get 0.0.0.0, I don't know why
		wawo::net::ipv4_t ipv4 = 0;
		const ::size_t in_addrs_size = in_addrs.size();
		WAWO_ASSERT(in_addrs_size >0);
		for (::size_t i = 0; i < in_addrs_size; ++i) {
			ipv4 = ::ntohl(in_addrs[i].s_addr);
			if (ipv4 != 0) {
				break;
			}
		}

		if (ipv4 == 0) {
			dns_resolve_error(roger::E_DNSLOOKUP_RETURN_NO_IP, cookie_);
		} else {
			fctx->ch_stream_ctx->event_poller()->execute([fctx, ipv4]() {
				fctx->ts_dns_lookup_done = wawo::time::curr_microseconds();
				WAWO_ASSERT(fctx->query != NULL);
				fctx->query = NULL;
				fctx->dst_ipv4 = ipv4;
				dial_server_by_ip(fctx);
			});
		}
	}
	class stream_handler :
		public wawo::net::channel_activity_handler_abstract,
		public wawo::net::channel_inbound_handler_abstract
	{
	public:
		void connected(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<forward_ctx> fctx = wawo::make_ref<forward_ctx>();
			ctx->ch->set_ctx(fctx);
			fctx->state = CONNECT;

			fctx->up_state = ctx_write_state::WS_IDLE;
			fctx->down_state = ctx_write_state::WS_IDLE;

			fctx->stream_read_closed = false;
			fctx->server_read_closed = false;

			fctx->ch_stream_ctx = ctx;
			fctx->client_up_first_packet = wawo::make_ref<wawo::packet>(10*1024);

			fctx->ts_dns_lookup_start = 0;
			fctx->ts_dns_lookup_done = 0;
			fctx->ts_server_connect_start = 0;
			fctx->ts_server_connect_done = 0;

			TRACE_SERVER_SIDE_CTX("[server][forward_ctx][s%u]stream_accepted", fctx->ch_stream_ctx->ch->ch_id() );
		}

		void read_shutdowned(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WAWO_ASSERT(ctx != NULL);
			WWRP<forward_ctx> fctx = ctx->ch->get_ctx<forward_ctx>();
			WAWO_ASSERT(fctx != NULL);
			WAWO_ASSERT(fctx->ch_stream_ctx == ctx);

			TRACE_SERVER_SIDE_CTX("[server][s%u]stream read closed, plan a flush", fctx->ch_stream_ctx->ch->ch_id());
			fctx->stream_read_closed = true;
			flush_up(fctx, NULL);
		}

		void closed(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<forward_ctx> fctx = ctx->ch->get_ctx<forward_ctx>();
			WAWO_ASSERT(fctx != NULL);
			WAWO_ASSERT(fctx->ch_stream_ctx == ctx);
			TRACE_SERVER_SIDE_CTX("[server][s%u]stream closed", fctx->ch_stream_ctx->ch->ch_id());

			ctx->ch->set_ctx(NULL);
			WAWO_ASSERT(fctx->stream_read_closed == true);
		}

		void read(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::packet> const& income) {
			WAWO_ASSERT(income->len() > 0);
			WAWO_ASSERT(ctx != NULL);
			WWRP<forward_ctx> fctx = ctx->ch->get_ctx<forward_ctx>();
			WAWO_ASSERT(fctx != NULL);
			WAWO_ASSERT(fctx->ch_stream_ctx == ctx);

			bool write_income_done = false;

		_begin:
			switch (fctx->state)
			{
			case CONNECT:
			{
				fctx->client_up_first_packet->write(income->begin(), income->len());
				write_income_done = true;
				if (fctx->client_up_first_packet->len()<6) {
					return;
				}

				u8_t cmd = fctx->client_up_first_packet->read<u8_t>();
				if (cmd != C_CONNECT) {
					WAWO_ERR("[server][s%u] command: %u", ctx->ch->ch_id(), cmd);
					fctx->server_read_closed = true;
					WWRP<wawo::packet> outp = wawo::make_ref<wawo::packet>();
					outp->write<int32_t>(roger::E_UNKNOWN_CMD);
					flush_down(fctx, outp);
					return;
				}

				fctx->dst_port = fctx->client_up_first_packet->read<u16_t>();
				fctx->address_type = (roger_connect_address_type)fctx->client_up_first_packet->read<u8_t>();
				fctx->state = READ_DST_ADDR;
				if (fctx->client_up_first_packet->len()) { goto _begin; }
			}
			break;
			case READ_DST_ADDR:
			{
				if (!write_income_done) {
					fctx->client_up_first_packet->write(income->begin(), income->len());
					write_income_done = true;
				}

				switch (fctx->address_type) {
				case HOST:
				{
					if (fctx->client_up_first_packet->len()<1) {
						return;
					}

					u8_t dlen[1];
					fctx->client_up_first_packet->peek(dlen, 1);
					if (fctx->client_up_first_packet->len() < dlen[0]) {
						return;
					}

					if ( dlen[0] >= 255 ) {
						WAWO_ERR("[server][s%u]domain len exceed 512 bytes, close stream, domain name: %s", ctx->ch->ch_id(), dlen[0] );
						fctx->server_read_closed = true;
						WWRP<wawo::packet> outp = wawo::make_ref<wawo::packet>();
						outp->write<int32_t>(roger::E_INVALID_DOMAIN);
						flush_down(fctx, outp);
						return;
					}

					fctx->client_up_first_packet->skip(1);
					//refer to https://stackoverflow.com/questions/32290167/what-is-the-maximum-length-of-a-dns-name
					char domain[256] = { 0 };
					u32_t nbytes = fctx->client_up_first_packet->read((byte_t*)domain, dlen[0]);
					WAWO_ASSERT(nbytes == dlen[0]);
					fctx->state = LOOKUP_SERVER_NAME;
					fctx->dst_domain = std::string(domain, nbytes);
					fctx->ts_dns_lookup_start = wawo::time::curr_microseconds();
					fctx->dns_try_time = 1;
					fctx->query = dns_resolver::instance()->async_resolve(fctx->dst_domain, fctx, &dns_resolve_success, &dns_resolve_error);
					WAWO_ASSERT(fctx->query != NULL);
					return;
				}
				break;
				case IPV4:
				{
					if (fctx->client_up_first_packet->len() < sizeof(wawo::net::ipv4_t)) {
						return;
					}
					fctx->dst_ipv4 = fctx->client_up_first_packet->read<wawo::net::ipv4_t>();
					if (fctx->dst_ipv4 == 0) {
						WAWO_ERR("[server][s%u]ipv4==0, close", ctx->ch->ch_id());
						fctx->server_read_closed = true;
						WWRP<wawo::packet> outp = wawo::make_ref<wawo::packet>();
						outp->write<int32_t>(roger::E_INVALID_IPV4);
						flush_down(fctx, outp);
						return;
					}

					WAWO_ASSERT(fctx->ch_server_ctx == NULL);
					WAWO_ASSERT(fctx->up_to_server_packets.size() == 0);
					dial_server_by_ip(fctx);
					return;
				}
				break;
				default:
				{
					WAWO_ERR("[server][s%u]invalid address type", fctx->ch_stream_ctx->ch->ch_id());
					fctx->server_read_closed = true;
					WWRP<wawo::packet> outp = wawo::make_ref<wawo::packet>();
					outp->write<int32_t>(-3);
					flush_down(fctx, outp);
					return;
				}
				}
			}
			break;
			case LOOKUP_SERVER_NAME:
			case DIAL_SERVER:
			case DIAL_SERVER_OK:
			{
				fctx->client_up_first_packet->write(income->begin(), income->len());
			}
			break;
			case SERVER_CONNECTED:
			{
				flush_up(fctx, income);
			}
			break;
			case DIAL_SERVER_FAILED:
			case LOOKUP_SERVER_NAEM_FAILED:
			{
				TRACE_SERVER_SIDE_CTX("[server][s%u][%s]error state, close stream", fctx->ch_stream_ctx->ch->ch_id(), server_state_str[fctx->state]);
				WAWO_ASSERT(fctx->ch_stream_ctx != NULL);
				fctx->ch_stream_ctx->close();
			}
			break;
			default:
			{
				WAWO_ASSERT(!"WHAT");
				WAWO_ERR("[roger]unknown server state: %d", fctx->state);
			}
			break;
			}
		}

		void write_block(WWRP<channel_handler_context> const& ctx) {
			WWRP<forward_ctx> fctx = ctx->ch->get_ctx<forward_ctx>();
			WAWO_ASSERT(fctx != NULL);
			WAWO_ASSERT(fctx->ch_stream_ctx == ctx);
			TRACE_SERVER_SIDE_CTX("[server][s%u]stream write blocked", fctx->ch_stream_ctx->ch->ch_id());
			fctx->ch_server_ctx->ch->ch_async_io_end_read();
		}

		void write_unblock(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<forward_ctx> fctx = ctx->ch->get_ctx<forward_ctx>();
			WAWO_ASSERT(fctx != NULL);
			TRACE_SERVER_SIDE_CTX("[server][s%u]stream write unblocked", fctx->ch_stream_ctx->ch->ch_id());

			fctx->ch_stream_ctx->event_poller()->execute([fctx,ctx]() {
				WAWO_ASSERT(fctx->ch_stream_ctx == ctx);
				fctx->ch_server_ctx->ch->ch_async_io_begin_read();
				flush_down(fctx, NULL);
			});
		}
	};

	void stream_accepted(WWRP<wawo::net::channel> const& ch)
	{
		ch->ch_set_read_buffer_size(roger::mux_stream_sbc.rcv_size);
		ch->ch_set_write_buffer_size(roger::mux_stream_sbc.snd_size);

		WWRP<wawo::net::channel_handler_abstract> h = wawo::make_ref<stream_handler>();
		ch->pipeline()->add_last(h);
	}
}
#endif