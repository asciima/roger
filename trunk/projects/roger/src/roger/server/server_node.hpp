#ifndef ROGER_SERVER_NODE_HPP
#define ROGER_SERVER_NODE_HPP

#include "../shared/shared.hpp"

#ifdef ROGER_USE_LIBUDNS
	#include "dns_resolver.hpp"
#endif

#include <wawo.h>

namespace roger {

	using namespace wawo;

	class roger_server
	{
		enum NodeState {
			S_IDLE,
			S_RUN,
			S_EXIT
		};

		typedef std::vector< WWRP<wawo::net::channel_handler_context> > RepVec;
	private:

		wawo::thread::shared_mutex m_state_mutex;
		NodeState m_state;

		wawo::thread::spin_mutex m_reps_mutex;
		RepVec m_reps;

		wawo::net::socket_addr m_listenaddr;

//		typedef std::vector< WWRP<forward_ctx> > sock_proxy_ctx_vector;
//		sock_proxy_ctx_vector m_ctx_for_async;
//		spin_mutex m_ctx_for_async_standby_mutex;
//		sock_proxy_ctx_vector m_ctx_for_async_standby;

#ifdef ROGER_USE_LIBUDNS

		struct resolve_cookie :
			public ref_base
		{
			WWRP<roger_server> node;
			WWRP<forward_ctx> ctx;
		};

		WWRP<dns_resolver> m_resolver;
#endif

	public:
		roger_server() : m_state(S_IDLE) {}
		~roger_server() {}

		int Start(wawo::net::socket_addr const& laddr) {

			wawo::thread::lock_guard<shared_mutex> lg(m_state_mutex);

			m_listenaddr = laddr;

			int prt = server_node_t::start();
			if (prt != wawo::OK) {
				server_node_t::stop();
				return prt;
			}

			int srt = mux_node_t::start();
			if (srt != wawo::OK) {
				mux_node_t::stop();
				server_node_t::stop();
				return srt;
			}

			int lrt = mux_node_t::start_listen(m_listenaddr, roger::mux_sbc);
			//int lrt = -1;
			if (lrt != wawo::OK) {
				mux_node_t::stop();
				server_node_t::stop();
				WAWO_INFO("[server]listen on: %s failed, protocol: %s, rt: %d", m_listenaddr.so_address.address_info().cstr, protocol_str[m_listenaddr.so_protocol], lrt);
				return lrt;
			}

#ifdef ROGER_USE_LIBUDNS
			std::vector<wawo::len_cstr> ns;
#if WAWO_ISWIN
			ns.push_back("192.168.0.1");
			ns.push_back("192.168.1.1");
			ns.push_back("192.168.2.1");
			ns.push_back("100.64.10.2");
#endif
			m_resolver = wawo::make_ref<dns_resolver>(ns);

			int resolver_init = m_resolver->init();
			if (resolver_init != wawo::OK) {
				mux_node_t::stop();
				server_node_t::stop();
				WAWO_INFO("[server]init resolver failed: %d", resolver_init);
				return resolver_init;
			}
#endif
			m_state = S_RUN;
			return wawo::OK;
		}

		void Stop() {
			{
				wawo::thread::lock_guard<shared_mutex> lg(m_state_mutex);
				m_state = S_EXIT;
			}

			{
				wawo::thread::lock_guard<spin_mutex> lg_reps(m_reps_mutex);
				std::for_each(m_reps.begin(), m_reps.end(), [](WWRP<mux_peer_t> const& rep) {
					rep->close(-111);
				});
				m_reps.clear();
			}


			mux_node_t::stop();
			server_node_t::stop();

#ifdef ROGER_USE_LIBUDNS
			m_resolver->deinit();
#endif
		}

		void on_message(WWRP<sp_evt_t> const& evt) {
			shared_lock_guard<shared_mutex> lg_state(m_state_mutex);
			if (m_state != S_RUN) {
				evt->peer->close(wawo::E_SOCKET_FORCE_CLOSE);
				return;
			}

			WWSP<message::cargo> incoming = evt->message;
			WAWO_ASSERT(incoming != NULL);

			WWRP<forward_ctx> ctx = evt->peer->get_ctx<forward_ctx>();
			WAWO_ASSERT(ctx != NULL);
			lock_guard<spin_mutex> lg(ctx->mutex);
			
			if (ctx->state != SERVER_CONNECTED) {
				WAWO_WARN("[server][s%u]stream closed, write to stream canceled, close peer", ctx->stream_id );
				evt->peer->close();
				return;
			}

			WWSP<packet> const& inpack = incoming->data;

			WAWO_ASSERT(ctx != NULL);
			WAWO_ASSERT(ctx->s != NULL);
			WAWO_ASSERT(ctx->state == SERVER_CONNECTED);

			if (ctx->sp_to_stream_packets.size()) {
				ctx->sp_to_stream_packets.push(inpack);
				return ;
			}

			int retval = ctx->s->write(inpack);
			if (retval == wawo::E_MUX_STREAM_WRITE_BLOCK) {
				WAWO_ASSERT(ctx->sp_to_stream_packets.size() == 0);
				ctx->sp_to_stream_packets.push(inpack);
				WAWO_DEBUG("[server][s%u]write to stream blocked", ctx->s->id );
				return;
			}
			else if (retval == wawo::OK) {
				evt->so->begin_async_read();
			}
			else {
				WAWO_DEBUG("[server][s%u]write to stream blocked, close peer: %d", ctx->s->id, retval);
				evt->peer->close(retval);
			}
		}

		void on_server_connected(WWRP<server_peer_t> const& peer, WWRP<wawo::net::socket> const& so, WWRP<ref_base> const& cookie) {

			shared_lock_guard<shared_mutex> lg_state(m_state_mutex);

			WWRP<forward_ctx> ctx = wawo::static_pointer_cast<forward_ctx>(cookie);
			WAWO_ASSERT(ctx != NULL);

			lock_guard<spin_mutex> lg(ctx->mutex);

			if (m_state != S_RUN) {
				TRACE_SERVER_STREAM("[server][%s]<--->[#%d:%s]server peer connected, but server stoped, close peer and unwatch all evt", so->get_local_addr().address_info().cstr, so->get_fd(), so->get_remote_addr().address_info().cstr);
				server_node_t::unwatch_peer_all_event(peer);
				peer->close();

				WAWO_ASSERT(ctx->s != NULL);
				ctx->s->close();
				return;
			}

			if (ctx->state == STREAM_CLOSED)
			{
				//fin or rst before connected
				server_node_t::unwatch_peer_all_event(peer);
				peer->close();
				return;
			}

			WAWO_ASSERT(ctx->state == CONNECTING_SERVER);
			ctx->state = SERVER_CONNECTED;

			address addr_local = so->get_local_addr();
			WAWO_INFO("[server][s%u][%s]<--->[#%d:%s]server peer connected", ctx->stream_id, addr_local.address_info().cstr, so->get_fd(), so->get_remote_addr().address_info().cstr);

			ctx->server_peer = peer;
			ctx->server_peer->set_ctx(ctx);

			if (((ctx->sflag)&(forward_ctx::F_CLIENT_FIN | forward_ctx::F_SERVER_FIN)) == (forward_ctx::F_CLIENT_FIN | forward_ctx::F_SERVER_FIN)) {
				TRACE_SERVER_STREAM("[server][s%u][%s]<--->[#%d:%s]server peer connected, but stream closed, close sp", ctx->stream_id, addr_local.address_info().cstr, so->get_fd(), so->get_remote_addr().address_info().cstr);
				peer->close();
				return;
			}

			//resp CONNECT ok
			WWSP<packet> connect_ok_or_not = wawo::make_shared<packet>(64);
			connect_ok_or_not->write<u8_t>(0);
			int retval = ctx->s->write(connect_ok_or_not);
			if (retval != wawo::OK) {
				so->close();
				TRACE_SERVER_STREAM("[server][s%u]response cmd connect failed, close socket", ctx->s->id);
				return;
			}
			
			packet_queue outps;
			u32_t slice_size = server_sbc.snd_size >> 1;
			while (ctx->client_up_first_packet->len()) {
				WWSP<packet> outp = wawo::make_shared<packet>(server_sbc.snd_size);
				u32_t copy_c = ctx->client_up_first_packet->len() > slice_size ? slice_size : ctx->client_up_first_packet->len();
				outp->write(ctx->client_up_first_packet->begin(), copy_c);
				ctx->client_up_first_packet->skip(copy_c);					
				outps.push(outp);
			}

			while (outps.size()) {
				WWSP<wawo::packet>& outp = outps.front();
				int flushrt = ctx->flush_packet_to_server(outp);
				if (flushrt == wawo::OK) {
					outps.pop();
				}
				else if (flushrt == wawo::E_SOCKET_SEND_BLOCK) {
					break;
				} else {
					goto _skip_first_packet;
				}			
			}

			while (outps.size()) {
				WWSP<wawo::packet>& outp = outps.front();
				ctx->client_outps.push(outp);
				outps.pop();
			}

_skip_first_packet:
			if (ctx->sflag&forward_ctx::F_CLIENT_FIN) {
				so->shutdown(SHUTDOWN_WR);
			}
		}

		void on_server_connect_error(int const& code, WWRP<ref_base> const& cookie) {

			WWRP<forward_ctx> ctx = wawo::static_pointer_cast<forward_ctx>(cookie);
			WAWO_ASSERT(ctx != NULL);
			TRACE_SERVER_STREAM("[server][s%u]server peer connect error: %d", ctx->stream_id, code );

			lock_guard<spin_mutex> lg(ctx->mutex);
			if (ctx->state == STREAM_CLOSED) {
				return;
			}

			WAWO_ASSERT(ctx->state == CONNECTING_SERVER);
			WAWO_ASSERT(ctx->server_peer == NULL);
			ctx->state = ERR;
			ctx->sflag |= forward_ctx::F_SERVER_FIN;

			if (ctx->s != NULL) {
				WWSP<packet> connect_failed = wawo::make_shared<packet>(64);
				connect_failed->write<u8_t>(CONNECT_SERVER_FAILED);
				int retval = ctx->s->write(connect_failed);

				ctx->s->close();
				TRACE_SERVER_STREAM("[server][s%u]server peer error: %d, close, send CONNECT_SERVER_FAILED, sndrt: %d", ctx->s->id, code, retval);
			}
		}

		void on_socket_read_shutdown(WWRP<sp_evt_t> const& evt) {

			WWRP<forward_ctx> ctx = evt->peer->get_ctx<forward_ctx>();
			WAWO_ASSERT(ctx != NULL);

			lock_guard<spin_mutex> lg(ctx->mutex);
			ctx->sflag |= forward_ctx::F_SERVER_FIN;

			if (ctx->s == NULL) return;

			if (ctx->sp_to_stream_packets.size() == 0) {
				int retval = ctx->s->close_write();
				TRACE_SERVER_STREAM("[server][s%u]server peer read shutdown, s->close_write() = %d", ctx->s->id, retval);
			}
			else {
				TRACE_SERVER_STREAM("[server][s%u]server peer read shutdown, sp_to_stream_packets.size() = %u, s would be closed after sp_to_stream_packets be flushed", ctx->s->id, ctx->sp_to_stream_packets.size() );
			}
			TRACE_SERVER_STREAM("[server][s%u][#%d:%s]server peer read shutdown", ctx->stream_id, evt->so->get_fd(), evt->so->get_local_addr().address_info().cstr);
		}

		void on_socket_write_shutdown(WWRP<sp_evt_t> const& evt) {

			WWRP<forward_ctx> ctx = evt->peer->get_ctx<forward_ctx>();
			WAWO_ASSERT(ctx != NULL);
			lock_guard<spin_mutex> lg(ctx->mutex);

			ctx->sflag |= forward_ctx::F_CLIENT_FIN;

			if (ctx->s != NULL) {
				int retval = ctx->s->close_read();
				TRACE_SERVER_STREAM("[server][s%u]server peer write shutdown, s->close_read() = %d", ctx->s->id, retval);
			}

			TRACE_SERVER_STREAM("[server][s%u][#%d:%s]server peer write shutdown", ctx->stream_id, evt->so->get_fd(), evt->so->get_local_addr().address_info().cstr );
		}

		void on_wr_unblock(WWRP<sp_evt_t> const& evt) {

			WWRP<forward_ctx> ctx = evt->peer->get_ctx<forward_ctx>();
			WAWO_ASSERT(ctx != NULL);
			lock_guard<spin_mutex> lg(ctx->mutex);
			WAWO_ASSERT(ctx->server_peer == evt->peer);

			while (ctx->client_outps.size()) {
				WWSP<packet>& outp = ctx->client_outps.front();
				int flushrt = ctx->flush_packet_to_server(outp);

				if (flushrt != wawo::OK) {
					break;
				}

				ctx->client_outps.pop();
			}

			while (ctx->client_outps.size() == 0) {
				WAWO_ASSERT(ctx->s != NULL);
				WWSP<packet> inpack;
				u32_t rbytes = ctx->s->read(inpack, 128*1024);

				if ( rbytes==0) {
					break;
				}
				WAWO_ASSERT(inpack->len() > 0);
				int flushrt = ctx->flush_packet_to_server(inpack);
				if (flushrt == wawo::E_SOCKET_SEND_BLOCK) {
					ctx->client_outps.push(inpack);
				}
			}
		}

		void on_close(WWRP<sp_evt_t> const& evt) {

			WWRP<forward_ctx> ctx = evt->peer->get_ctx<forward_ctx>();
			WAWO_ASSERT(ctx != NULL);
			lock_guard<spin_mutex> lg(ctx->mutex);
			WAWO_ASSERT(ctx->server_peer == evt->peer);

			ctx->state = SERVER_CLOSED;
			ctx->server_peer = NULL;

			evt->peer->set_ctx(NULL);

			if (ctx->s != NULL) {
				ctx->s->close();
				TRACE_SERVER_STREAM("[server][s%u][%s]<--->[#%d:%s]server peer close, close stream", ctx->s->id, evt->so->get_local_addr().address_info().cstr, evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr);
			}

			TRACE_SERVER_STREAM("[server][s%u][%s]<--->[#%d:%s]server peer close", ctx->stream_id, evt->so->get_local_addr().address_info().cstr, evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr);
		}

		int async_connect_server(WWRP<forward_ctx> const& ctx) {

			WAWO_ASSERT((ctx->dst_addrv4.is_null()));
			WAWO_ASSERT(ctx->dst_port > 0);

			ctx->dst_addrv4.set_netsequence_ulongip(htonl(ctx->dst_ipv4));
			ctx->dst_addrv4.set_netsequence_port(htons(ctx->dst_port));

			socket_addr connect_addr;
			connect_addr.so_family = F_AF_INET;
			connect_addr.so_type = ST_STREAM;
			connect_addr.so_protocol = P_TCP;
			connect_addr.so_address = ctx->dst_addrv4;

			auto success = std::bind(&roger_server::on_server_connected, WWRP<roger_server>(this), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
			auto err = std::bind(&roger_server::on_server_connect_error, WWRP<roger_server>(this), std::placeholders::_1, std::placeholders::_2);
			return server_node_t::async_connect(connect_addr, ctx, success, err, server_sbc, default_keep_alive_vals);
		}

		void on_message(WWRP<mux_evt_t> const& evt) {

			WAWO_ASSERT(evt->message != NULL);

			WWRP<stream>& s = evt->message->s;
			WAWO_ASSERT(s != NULL);

			WWRP<forward_ctx> ctx = wawo::static_pointer_cast<forward_ctx>(evt->message->ctx);
			int stream_message_type = evt->message->type;
			switch (stream_message_type) {

			case message::T_WRITE_BLOCK:
				{}
				break;
			case message::T_WRITE_UNBLOCK:
				{
					wawo::thread::lock_guard<spin_mutex> lg_ctx(ctx->mutex);

					WAWO_ASSERT(ctx->s == s);

					while (ctx->sp_to_stream_packets.size()) {
						WWSP<packet>& outp = ctx->sp_to_stream_packets.front();
						int flushrt = s->write(outp);

						if (flushrt != wawo::OK) {
							break;
						}

						ctx->sp_to_stream_packets.pop();
					}

					if (ctx->sp_to_stream_packets.size() == 0) {
						if (ctx->sflag&forward_ctx::F_SERVER_FIN) {
							WAWO_ASSERT(ctx->s != NULL);
							s->close_write();
						}
						ctx->server_peer->get_socket()->begin_async_read();
					}
				}
				break;
			case message::T_ACCEPTED:
			{
				handle_stream_accepted(s);
			}
			break;
			case message::T_FIN:
			{
				handle_stream_fin(s, ctx);
			}
			break;
			case message::T_DATA:
			{
				if (ctx->client_outps.size()) return;

				WWSP<packet> inpack;
				u32_t rcount = s->read(inpack);

				if (rcount == 0) return;
				handle_stream_content(s, inpack, ctx);
			}
			break;
			case message::T_CLOSED:
			{
				handle_stream_closed(s, ctx);
			}
			break;
			default:
			{
				WAWO_THROW("unknown message type of stream packet");
			}
			}
		}

		void on_accepted(WWRP<mux_peer_t> const& peer, WWRP<wawo::net::socket> const& so) {
			shared_lock_guard<shared_mutex> lg_state(m_state_mutex);
			if (m_state != S_RUN) {
				so->close();
				return;
			}

			wawo::thread::lock_guard<wawo::thread::spin_mutex> lg_reps(m_reps_mutex);
			m_reps.push_back(peer);
			WAWO_INFO("[server][##%u][#%u:%s]roger client accepted, local info: %s", peer.get(), so->get_fd(), so->get_addr_info().cstr, so->get_local_addr().address_info().cstr);

			(void)so;
		}

		void on_close(WWRP<mux_evt_t> const& evt) {
			shared_lock_guard<shared_mutex> lg_state(m_state_mutex);
			if (m_state != S_RUN) {
				return;
			}

			wawo::thread::lock_guard<spin_mutex> lg_reps(m_reps_mutex);
			RepVec::iterator it = std::find(m_reps.begin(), m_reps.end(), evt->peer);
			WAWO_ASSERT(it != m_reps.end());
			m_reps.erase(it);

			WAWO_INFO("[server][##%p]roger client closed", evt->peer.get() );
		}

		void handle_stream_accepted(WWRP<stream> const& s) {
			WAWO_ASSERT(s != NULL);

			WWRP<forward_ctx> _forward_ctx = wawo::make_ref<forward_ctx>();
			_forward_ctx->stream_id = s->id;
			_forward_ctx->s = s;
			_forward_ctx->sflag = forward_ctx::F_NONE;

			_forward_ctx->server_peer = NULL;

			_forward_ctx->client_up_first_packet = wawo::make_shared<wawo::packet>(10*1024);
			_forward_ctx->state = CONNECT;

			_forward_ctx->memory_tag = wawo::make_ref<wawo::bytes_ringbuffer>(3777);

			s->ctx = _forward_ctx;
			TRACE_CTX("[server][forward_ctx][s%u]stream_accepted", s->id);
		}

		void handle_stream_closed(WWRP<stream> const& s, WWRP<forward_ctx> const& ctx) {
			WAWO_ASSERT(ctx != NULL);
			wawo::thread::lock_guard<spin_mutex> lg_ctx(ctx->mutex);
			ctx->sflag |= (forward_ctx::F_CLIENT_FIN | forward_ctx::F_SERVER_FIN);
			ctx->state = STREAM_CLOSED;
			
			if (ctx->server_peer != NULL) {
				ctx->server_peer->close(wawo::E_SOCKET_FORCE_CLOSE);
			}
			WAWO_ASSERT(s->ctx == ctx);

			ctx->s = NULL;
			TRACE_CTX("[server][forward_ctx][s%u]stream_closed", s->id);
		}

		void handle_stream_fin(WWRP<stream> const& s, WWRP<forward_ctx> const& ctx) {

			WAWO_ASSERT(s != NULL);
			WAWO_ASSERT(ctx != NULL);
			WAWO_ASSERT(s == ctx->s, "s: %u, ctx->s: %u, s->flag: %u", s, ctx->s, s->flag );

			wawo::thread::lock_guard<spin_mutex> lg_ctx(ctx->mutex);
			ctx->sflag |= forward_ctx::F_CLIENT_FIN;
			s->close_read();

			TRACE_CTX("[server][forward_ctx][s%u][%s]receive stream T_FIN, close stream read", s->id, server_state_str[ctx->state]);

			switch (ctx->state) {
			case SERVER_CONNECTED:
			{
				WAWO_ASSERT(ctx->client_outps.size() == 0);
				WAWO_ASSERT(ctx->server_peer != NULL);
				ctx->server_peer->shutdown(SHUTDOWN_WR);
			}
			break;
			case LOOKUP_SERVER_NAME:
			case CONNECTING_SERVER:
			{
				WAWO_ASSERT(ctx->server_peer == NULL);
				WAWO_ASSERT(!(ctx->sflag&forward_ctx::F_SERVER_FIN));

				//ctx->sflag |= forward_ctx::F_CLIENT_FIN;
			}
			break;
			case ERR:
			case SERVER_CLOSED:
			{
				WAWO_ASSERT(ctx->sflag == forward_ctx::F_BOTH_FIN);
			}
			break;
			default:
			{
				WAWO_ASSERT(!"what", "state: %u", ctx->state );
			}
			break;
			}
		}

		void handle_stream_content(WWRP<stream> const& s, WWSP<packet> const& inpack, WWRP<forward_ctx> const& ctx) {

			WAWO_ASSERT(inpack->len() > 0);
			WAWO_ASSERT(s != NULL);
			WAWO_ASSERT(ctx != NULL);
			WAWO_ASSERT(s == ctx->s);

			wawo::thread::lock_guard<spin_mutex> lg_ctx(ctx->mutex);
			bool has_write_to_buffer = false;
_again:
			switch (ctx->state)
			{
				case CONNECT:
				{
					ctx->client_up_first_packet->write(inpack->begin(), inpack->len());
					has_write_to_buffer = true;

					if (ctx->client_up_first_packet->len()<5) {
						return;
					}

					u8_t cmd = ctx->client_up_first_packet->read<u8_t>();
					if (cmd != C_CONNECT) {
						WAWO_ERR("[server][s%u]invalid command: %u", s->id, cmd );
						s->close();
						ctx->sflag = forward_ctx::F_SERVER_FIN | forward_ctx::F_CLIENT_FIN;
						ctx->state = ERR;
						return;
					}

					ctx->dst_port = ctx->client_up_first_packet->read<u16_t>();
					ctx->address_type = (roger_connect_address_type)ctx->client_up_first_packet->read<u8_t>();

					ctx->state = READ_DST_ADDR;

					if (ctx->client_up_first_packet->len()) { goto _again; }
				}
				break;
				case READ_DST_ADDR:
				{
					if (!has_write_to_buffer) {
						ctx->client_up_first_packet->write(inpack->begin(), inpack->len());
						has_write_to_buffer = true;
					}

					switch ( ctx->address_type ) {
					case HOST:
					{
						if (ctx->client_up_first_packet->len() < 1) {
							return;
						}

						u8_t dlen[1];
						ctx->client_up_first_packet->peek(dlen, 1);
						if (ctx->client_up_first_packet->len() < dlen[0]) {
							return;
						}
						ctx->client_up_first_packet->skip(1);
						char domain[2048] = { 0 };
						u32_t nbytes = ctx->client_up_first_packet->read((byte_t*)domain, dlen[0]);

						if (nbytes >= 1024) {
							WAWO_ERR("[server][s%u]invalid domain, close stream", s->id);
							s->close();
							ctx->sflag = forward_ctx::F_SERVER_FIN | forward_ctx::F_CLIENT_FIN;
							ctx->state = ERR;
							return;
						}

						WAWO_ASSERT(nbytes == dlen[0]);
						ctx->dst_domain = len_cstr(domain, nbytes);

						WAWO_ASSERT(m_resolver != NULL);

						WWRP<resolve_cookie> cookie = wawo::make_ref<resolve_cookie>();
						cookie->node = WWRP<roger_server>(this);
						cookie->ctx = ctx;

						ctx->query = m_resolver->async_resolve(ctx->dst_domain, cookie, roger_server::dns_resolve_success, roger_server::dns_resolve_error);
						WAWO_ASSERT(ctx->query != NULL);
						ctx->state = LOOKUP_SERVER_NAME;
						TRACE_DNS("[server][s%u]async resolve: %s", s->id, ctx->dst_domain.cstr);
						return;
					}
					break;
					case IPV4:
					{
						if (ctx->client_up_first_packet->len() < sizeof(u32_t)) {
							return;
						}
						ctx->dst_ipv4 = ctx->client_up_first_packet->read<u32_t>();

						WAWO_ASSERT(ctx->server_peer == NULL);
						int connrt = async_connect_server(ctx);
						if (connrt != wawo::OK) {
							ctx->state = ERR;
							ctx->sflag = forward_ctx::F_SERVER_FIN | forward_ctx::F_CLIENT_FIN;
							s->close();
							WAWO_ERR("[server][forward_ctx][s%u][%s]async connect failed: %d", s->id, server_state_str[ctx->state], connrt);
						} else {
							ctx->state = CONNECTING_SERVER;
							TRACE_SERVER_STREAM("[server][s%u][%s]async connecting ...", s->id, ctx->dst_addrv4.address_info().cstr);
						}
						return;
					}
					break;
					default:
					{
						WAWO_ERR("[server][s%u]invalid address type", s->id);
						s->close();
						ctx->sflag = forward_ctx::F_SERVER_FIN | forward_ctx::F_CLIENT_FIN;
						ctx->state = ERR;
						return;
					}
				}
			}
			break;
			case LOOKUP_SERVER_NAME:
			case CONNECTING_SERVER:
			{
				if (!has_write_to_buffer) {
					ctx->client_up_first_packet->write(inpack->begin(), inpack->len());
					has_write_to_buffer = true;
				}
			}
			break;
			case SERVER_CONNECTED:
			{
				int flushrt = ctx->flush_packet_to_server(inpack);
				if (flushrt == wawo::E_SOCKET_SEND_BLOCK) {
					ctx->client_outps.push(inpack);
				}
			}
			break;
			case SERVER_CLOSED:
			{
				s->close();
				WAWO_ERR("[server][forward_ctx][s%u][%s]sp closed already, close stream", s->id,server_state_str[ctx->state]);
			}
			break;
			default:
			{
				WAWO_ERR("[roger]unknown s5pctx state: %d", ctx->state);
			}
			break;
			}
		}

#ifdef ROGER_USE_LIBUDNS
		static void dns_resolve_success(std::vector<in_addr> const& in_addrs, WWRP<wawo::ref_base> const& cookie_) {

			WAWO_ASSERT(cookie_ != NULL);
			WWRP<resolve_cookie> cookie = wawo::static_pointer_cast<resolve_cookie>(cookie_);

			WAWO_ASSERT(cookie->ctx != NULL);
			WAWO_ASSERT(cookie->node != NULL);
			WWRP<forward_ctx>& ctx = cookie->ctx;
			wawo::thread::lock_guard<wawo::thread::spin_mutex> lg(ctx->mutex);
			WAWO_ASSERT(cookie->ctx->query != NULL);

			WAWO_ASSERT(in_addrs.size());

			ctx->dst_ipv4 = ::ntohl(in_addrs[0].s_addr);
			ctx->query = NULL;

			WAWO_ASSERT(ctx->server_peer == NULL);
			int connrt = cookie->node->async_connect_server(ctx);
			if (connrt != wawo::OK) {
				WAWO_ERR("[server][forward_ctx][%s][s%u]async connect failed: %d", server_state_str[ctx->state], ctx->stream_id, connrt);
				if (ctx->s != NULL) {
					ctx->s->close();
				}
				ctx->state = ERR;
				ctx->sflag = forward_ctx::F_SERVER_FIN | forward_ctx::F_CLIENT_FIN;
			} else {
				TRACE_SERVER_STREAM("[server][s%u][%s]async connecting ...", ctx->stream_id, ctx->dst_addrv4.address_info().cstr);
				ctx->state = CONNECTING_SERVER;
			}
		}

		static void dns_resolve_error(int const& code, WWRP < wawo::ref_base > const& cookie_) {
			WAWO_ASSERT(cookie_ != NULL);
			WWRP<resolve_cookie> cookie = wawo::static_pointer_cast<resolve_cookie>(cookie_);

			WAWO_ASSERT(cookie->ctx != NULL);
			WAWO_ASSERT(cookie->node != NULL);
			WWRP<forward_ctx>& ctx = cookie->ctx;

			WAWO_ASSERT(ctx->server_peer == NULL);

			wawo::thread::lock_guard<wawo::thread::spin_mutex> lg(ctx->mutex);
			WAWO_ASSERT(cookie->ctx->query != NULL);

			ctx->query = NULL;
			if (ctx->s != NULL) {
				ctx->s->close();
			}
			ctx->sflag = forward_ctx::F_SERVER_FIN | forward_ctx::F_CLIENT_FIN;
			ctx->state = ERR;
			WAWO_ERR("[server][forward_ctx][%s][s%u]dns(%s) lookup failed: %d", server_state_str[ctx->state], ctx->stream_id, ctx->dst_domain.cstr, code);
		}
#endif
	};
}

#endif
