#include <wawo.h>
#include "../shared/shared.hpp"
#include "protocols.hpp"


namespace roger {
	using namespace wawo::net::protocol::http;

	typedef std::unordered_map <std::string, WWRP<proxy_ctx> > stream_http_proxy_ctx_map_t;
	typedef std::pair <std::string, WWRP<proxy_ctx>> stream_http_proxy_ctx_pair_t;

	struct proxy_ctx :
		public wawo::ref_base
	{
		
		proxy_ctx() {
			TRACE_CLIENT_SIDE_CTX("proxy_ctx::proxy_ctx()");
		}
		~proxy_ctx() {
			TRACE_CLIENT_SIDE_CTX("proxy_ctx::~proxy_ctx()");
		}
		WWRP<proxy_ctx> parent;

		proxy_forward_type type;
		proxy_state state;
		http_req_sub_state sub_state;
		ctx_write_state up_state;
		ctx_write_state down_state;

		bool client_read_closed;
		bool stream_read_closed;

		WWRP<wawo::net::channel_handler_context> ch_client_ctx;
		WWRP<wawo::net::channel_handler_context> ch_stream_ctx;

		WWRP<wawo::packet> protocol_packet;

		packet_queue up_to_stream_packets;
		packet_queue down_to_client_packets;

		roger_connect_address_type address_type;
		ipv4_t dst_ipv4;
		port_t dst_port;
		std::string dst_domain;

		WWRP<wawo::net::protocol::http::parser> http_req_parser;
		stream_http_proxy_ctx_map_t	http_proxy_ctx_map;
		WWSP<wawo::net::protocol::http::message> cur_req;
		WWRP<proxy_ctx> cur_req_ctx;

		WWRP<wawo::net::protocol::http::parser> http_resp_parser;
		WWSP<wawo::net::protocol::http::message> cur_resp;

		std::string resp_http_field_tmp;

		bool resp_in_chunk_body;
		bool resp_header_connection_close;
		u32_t resp_count;

		std::string HP_key; //host and port
		message_queue reqs;
		std::queue<WWRP<wawo::packet>> pending_outp;

		std::string http_req_field_tmp;
		bool cur_req_in_chunk_body;
	};

	inline WWRP<wawo::packet> make_packet_CMD_CONNECT(WWRP<proxy_ctx> const& pctx) {
		WWRP<wawo::packet> outp = wawo::make_ref<wawo::packet>();
		WAWO_ASSERT(pctx->dst_port > 0);
		if (pctx->address_type == IPV4) {
			outp->write<u8_t>(C_CONNECT);
			outp->write<u16_t>(pctx->dst_port);
			outp->write<u8_t>(IPV4);
			outp->write<u32_t>(pctx->dst_ipv4);
		} else {
			WAWO_ASSERT(pctx->dst_domain.length() > 0);
			outp->write<u8_t>(C_CONNECT);
			outp->write<u16_t>(pctx->dst_port);
			outp->write<u8_t>(HOST);
			outp->write<u8_t>((pctx->dst_domain.length()) & 0xFF);
			outp->write((wawo::byte_t*)pctx->dst_domain.c_str(), pctx->dst_domain.length());
		}
		return outp;
	}
	void ctx_up_done(WWRP<proxy_ctx> const& ctx, int flushrt);
	inline void _do_ctx_up(WWRP<proxy_ctx> const& ctx) {
		WAWO_ASSERT(ctx->ch_client_ctx != NULL);
		WAWO_ASSERT(ctx->ch_client_ctx->event_poller()->in_event_loop());

		switch (ctx->state) {
			case PIPE_DIALING_STREAM:
			case PIPE_DIAL_STREAM_OK:
			case PIPE_DIALING_SERVER:
			case PIPE_DIAL_SERVER_OK:
			{
				//check ctx stats first
				if (ctx->up_to_stream_packets.size()) {
					WWRP<wawo::net::channel_promise> f = ctx->ch_stream_ctx->make_channel_promise();
					f->add_listener([ctx](WWRP<wawo::net::channel_future> const& f) {
						int rt = f->get();
						ctx->ch_client_ctx->event_poller()->execute([ctx, rt]() {
							ctx_up_done(ctx, rt);
						});
					});
					WAWO_ASSERT(ctx->up_state == WS_IDLE);
					ctx->up_state = WS_WRITING;
					WWRP<wawo::packet>& outp = ctx->up_to_stream_packets.front();
					WAWO_ASSERT(ctx->ch_stream_ctx != NULL);
					ctx->ch_stream_ctx->write(outp, f);
				} else {
					if (ctx->client_read_closed == true) {
						if (ctx->ch_stream_ctx != NULL) {
							ctx->ch_stream_ctx->shutdown_write();
						}
					}
				}
			}
			break;
			default:
			{
				DEBUG_STREAM("[client][%s]cancel dialing stream", proxy_state_str[ctx->state]);
				WAWO_ASSERT(ctx->ch_stream_ctx == NULL);
				ctx->ch_client_ctx->close();
			}
			break;
		}
	}
	inline void ctx_up_done(WWRP<proxy_ctx> const& ctx, int flushrt) {
		WAWO_ASSERT(ctx->ch_client_ctx != NULL);
		WAWO_ASSERT(ctx->ch_client_ctx->event_poller()->in_event_loop());
		WAWO_ASSERT(ctx->up_state == ctx_write_state::WS_WRITING);
		ctx->up_state = ctx_write_state::WS_IDLE;
		if (flushrt == wawo::OK) {
			WAWO_ASSERT(ctx->up_to_stream_packets.size());
			ctx->up_to_stream_packets.pop();
			_do_ctx_up(ctx);
		}
		else if (flushrt == wawo::E_CHANNEL_WRITE_BLOCK) {
		}
		else {
			ctx->ch_stream_ctx->close();
		}
	}
	inline void ctx_up(WWRP<proxy_ctx> const& ctx, WWRP<wawo::packet> const& income, bool flush = true) {
		WAWO_ASSERT(ctx->ch_client_ctx->event_poller()->in_event_loop());
		if (income != NULL) {
			ctx->up_to_stream_packets.push(income);
		}
		if (ctx->up_state == WS_WRITING || !flush) {
			return;
		}
		_do_ctx_up(ctx);
	}

	void ctx_down_done(WWRP<proxy_ctx> const& ctx, int flushrt);

	inline void _do_ctx_down(WWRP<proxy_ctx> const& ctx) {
		WAWO_ASSERT(ctx->ch_client_ctx->event_poller()->in_event_loop());

		if (ctx->down_to_client_packets.size()) {
			WWRP<wawo::net::channel_promise> f = ctx->ch_client_ctx->make_channel_promise();
			f->add_listener([ctx](WWRP<wawo::net::channel_future> const& f) {
				ctx_down_done(ctx, f->get());
			});
			WAWO_ASSERT(ctx->ch_client_ctx != NULL);
			WAWO_ASSERT(ctx->down_state == WS_IDLE);
			ctx->down_state = WS_WRITING;
			WWRP<wawo::packet>& outp = ctx->down_to_client_packets.front();
			ctx->ch_client_ctx->write(outp, f);
		}
		else {
			if (ctx->stream_read_closed) {
				TRACE_CLIENT_SIDE_CTX("[client]stream read closed, close client write");
				ctx->ch_client_ctx->shutdown_write();
			}
		}
	}

	inline void ctx_down_done(WWRP<proxy_ctx> const& ctx, int flushrt ) {
		WAWO_ASSERT(ctx->ch_client_ctx->event_poller()->in_event_loop());
		WAWO_ASSERT(ctx->down_state == WS_WRITING);
		ctx->down_state = WS_IDLE;
		if (flushrt == wawo::OK) {
			WAWO_ASSERT(ctx->down_to_client_packets.size());
			ctx->down_to_client_packets.pop();
			_do_ctx_down(ctx);
		}
		else if (flushrt == wawo::E_CHANNEL_WRITE_BLOCK)
		{
		}
		else {
			ctx->ch_client_ctx->close();
		}
	}

	inline void ctx_down(WWRP<proxy_ctx> const& ctx, WWRP<wawo::packet> const& income, bool flush = true ) {
		WAWO_ASSERT(ctx->ch_client_ctx->event_poller()->in_event_loop());
		if (income != NULL) {
			ctx->down_to_client_packets.push(income);
		}
		if (ctx->down_state == WS_WRITING || !flush) {
			return;
		}
		_do_ctx_down(ctx);
	}

	namespace http_req {
		int on_message_begin(WWRP<parser> const& p);
		int on_url(WWRP<parser> const& p, const char* data, wawo::u32_t const& len);

		int on_status(WWRP<parser> const& p, const char* data, wawo::u32_t const& len);
		int on_header_field(WWRP<parser> const& p, const char* data, wawo::u32_t const& len);
		int on_header_value(WWRP<parser> const& p, const char* data, wawo::u32_t const& len);
		int on_headers_complete(WWRP<parser> const& p);

		int on_body(WWRP<parser> const& p, const char* data, wawo::u32_t const& len);
		int on_message_complete(WWRP<parser> const& p);
		int on_chunk_header(WWRP<parser> const& p);
		int on_chunk_complete(WWRP<parser> const& p);
	}

	namespace http_resp {
		int on_message_begin(WWRP<parser> const& p);
		int on_url(WWRP<parser> const& p, const char* data, wawo::u32_t const& len);

		int on_status(WWRP<parser> const& p, const char* data, wawo::u32_t const& len);
		int on_header_field(WWRP<parser> const& p, const char* data, wawo::u32_t const& len);
		int on_header_value(WWRP<parser> const& p, const char* data, wawo::u32_t const& len);
		int on_headers_complete(WWRP<parser> const& p);

		int on_body(WWRP<parser> const& p, const char* data, wawo::u32_t const& len);
		int on_message_complete(WWRP<parser> const& p);
		int on_chunk_header(WWRP<parser> const& p);
		int on_chunk_complete(WWRP<parser> const& p);
	}

	static inline WWRP<parser> make_http_req_parser() {
		WWRP<parser> _p = wawo::make_ref<wawo::net::protocol::http::parser>();
		_p->init(wawo::net::protocol::http::PARSER_REQ);

		_p->on_message_begin = http_req::on_message_begin;
		_p->on_url = http_req::on_url;
		_p->on_status = http_req::on_status;
		_p->on_header_field = http_req::on_header_field;
		_p->on_header_value = http_req::on_header_value;
		_p->on_headers_complete = http_req::on_headers_complete;

		_p->on_body = http_req::on_body;
		_p->on_message_complete = http_req::on_message_complete;

		_p->on_chunk_header = http_req::on_chunk_header;
		_p->on_chunk_complete = http_req::on_chunk_complete;
		return _p;
	}

	static inline WWRP<parser> make_http_resp_parser() {
		WWRP<parser> _p = wawo::make_ref<wawo::net::protocol::http::parser>();
		_p->init(PARSER_RESP);

		_p->on_message_begin = http_resp::on_message_begin;
		_p->on_url = http_resp::on_url;
		_p->on_status = http_resp::on_status;
		_p->on_header_field = http_resp::on_header_field;
		_p->on_header_value = http_resp::on_header_value;
		_p->on_headers_complete = http_resp::on_headers_complete;
		_p->on_body = http_resp::on_body;
		_p->on_message_complete = http_resp::on_message_complete;
		_p->on_chunk_header = http_resp::on_chunk_header;
		_p->on_chunk_complete = http_resp::on_chunk_complete;

		return _p;
	}

	static inline void http_up(WWRP<proxy_ctx> const& ctx, WWRP<wawo::packet> const& up) {

		switch (ctx->state) {
		case PIPE_DIALING_STREAM:
		{
			WAWO_ASSERT(ctx->ch_stream_ctx == NULL);
			if (up != NULL) {
				ctx->pending_outp.push(up);
			}
		}
		break;
		case PIPE_DIAL_STREAM_OK:
		case PIPE_DIALING_SERVER:
		case PIPE_DIAL_SERVER_OK:
		{
			while (ctx->pending_outp.size()) {
				WWRP<wawo::packet>& t = ctx->pending_outp.front();
				ctx_up(ctx, t);
				ctx->pending_outp.pop();
			}
			WAWO_ASSERT(ctx->ch_stream_ctx != NULL);

			TRACE_HTTP_PROXY("[roger][s%u]push_back req: %s", pctx->cur_req_ctx->ch_stream_ctx->ch->ch_id(), pctx->cur_req_ctx->cur_req->url.c_str());
			ctx_up(ctx, up);
		}
		break;
		default:
		{
			WAWO_ASSERT(!"http pctx in invalid state");
		}
		break;
		}
	}

	static inline void http_down(WWRP<proxy_ctx> const& ctx, WWRP<wawo::packet> const& down /*NULL to close write*/) {
		if (ctx->http_proxy_ctx_map.size() == 0) {
			ctx->stream_read_closed = true;
		} else {
			stream_http_proxy_ctx_map_t::iterator _it = std::find_if(ctx->http_proxy_ctx_map.begin(), ctx->http_proxy_ctx_map.end(), [](stream_http_proxy_ctx_pair_t const& pair) {
				return pair.second->reqs.size() != 0;
			});
			if (_it == ctx->http_proxy_ctx_map.end()) {
				ctx->stream_read_closed = true;
			}
		}
		ctx_down(ctx, down);
	}

#define _MAX_HTTP_PARSE_STACK (10*1024)
	static inline int http_parse_down( WWRP<proxy_ctx> const& pctx, WWRP<wawo::packet> const& income) {
		WAWO_ASSERT(pctx->http_resp_parser != NULL);
		int ec = 0;
		while (income->len()) {
			u32_t nparsed = pctx->http_resp_parser->parse((char*)income->begin(), income->len(), ec);
			WAWO_ASSERT(nparsed >= 0);
			income->skip(nparsed);

			if (ec != wawo::OK) {
				WAWO_WARN("[roger][s%u]mux resp, parse failed: %u", pctx->ch_stream_ctx->ch->ch_id(), ec);
				break;
			}
		}
		TRACE_HTTP_PROXY("[roger][s%u]parsed bytes: %u, income: %u", pctx->ch_stream_ctx->ch->ch_id(), nparsed, income->len() );
		return ec;
	}

	static inline void cancel_all_ctx_reqs(WWRP<proxy_ctx> const& http_ctx, int const& cancel_code) {
		while (http_ctx->reqs.size()) {
			if (cancel_code >= 0) {
				WAWO_ASSERT(cancel_code < http_request_cancel_code::HTTP_REQUEST_CANCEL_CODE_MAX);
				WWRP<wawo::packet> http_reply = wawo::make_ref<wawo::packet>();
				http_reply->write((wawo::byte_t*) HTTP_RESP_ERROR[cancel_code], wawo::strlen(HTTP_RESP_ERROR[cancel_code]));

				WAWO_ASSERT(http_ctx->ch_client_ctx != NULL);
				http_ctx->ch_client_ctx->write(http_reply);
			}

			WWSP<wawo::net::protocol::http::message>& req = http_ctx->reqs.front();
			WAWO_INFO("[roger][http][s%u]cancel req: %s, cancel code: %u", http_ctx->ch_stream_ctx->ch->ch_id(), req->url.c_str(), cancel_code);
			http_ctx->reqs.pop();
		}
	}

	static void resp_connect_result_to_client(WWRP<proxy_ctx> const& pctx, WWRP<wawo::packet> const& downp, int rcode) {
		switch (pctx->type) {
		case T_SOCKS5:
		{
			socks5_response_code code = rcode == wawo::OK ? S5_SUCCEEDED : S5_GENERAL_SOCKS_SERVER_FAILURE;
			downp->write_left<u16_t>(0);
			downp->write_left<u32_t>(0);
			downp->write_left<u8_t>(ADDR_IPV4);
			downp->write_left<u8_t>(0);
			downp->write_left<u8_t>(code & 0xFF);
			downp->write_left<u8_t>(5);
			ctx_down(pctx, downp);
		}
		break;
		case T_SOCKS4:
		{
			socks4_response_code code = rcode == wawo::OK ? S4_REQUEST_GRANTED : S4_REQUEST_REJECTED_FOR_FAILED;
			downp->write_left<u32_t>(0);
			downp->write_left<u16_t>(0);
			downp->write_left<u8_t>(code & 0xFF);
			downp->write_left<u8_t>(0);
			ctx_down(pctx, downp);
		}
		break;
		case T_HTTPS:
		{
			if (rcode == wawo::OK) {
				downp->write_left((byte_t*)HTTP_RESP_RELAY_SUCCEED, wawo::strlen(HTTP_RESP_RELAY_SUCCEED));
			}
			else {
				WAWO_WARN("[roger][https]connect to url: %s failed for: %d", pctx->cur_req->url.c_str(), rcode);
				downp->write_left((byte_t*)HTTP_RESP_CONNECT_HOST_FAILED, wawo::strlen(HTTP_RESP_CONNECT_HOST_FAILED));
			}
			ctx_down(pctx, downp);
		}
		break;
		case T_HTTP:
		{
			if (rcode != wawo::OK) {
				WAWO_ASSERT(downp->len() == 0);
				WAWO_ASSERT(pctx->reqs.size() != 0);
				WWSP<wawo::net::protocol::http::message>& m = pctx->reqs.front();
				WAWO_WARN("[roger][https]connect to url: %s failed for: %d, cancel reqs: %u", m->url.c_str(), rcode, pctx->reqs.size());
				cancel_all_ctx_reqs(pctx, CANCEL_CODE_CONNECT_HOST_FAILED);
				WAWO_ASSERT(pctx->reqs.size() == 0);
			}
			else {
				int ec = http_parse_down(pctx, downp);
				if (ec != wawo::OK) {
					cancel_all_ctx_reqs(pctx, CANCEL_CODE_SERVER_RESPONSE_PARSE_ERROR);
					pctx->ch_stream_ctx->close();
				}
			}
		}
		break;
		default:
		{
			WAWO_ASSERT(!"WHAT");
		}
		}
	}

	class mux_pool :
		public wawo::singleton<mux_pool>
	{
		typedef std::vector<WWRP<wawo::net::handler::mux>> mux_vector_t;

		wawo::spin_mutex m_mutex;
		mux_vector_t m_muxs;
		wawo::u32_t m_idx;
		std::string m_mux_dialurl;
		std::atomic<bool> m_exit;

	public:
		mux_pool() :
			m_idx(0),
			m_exit(false)
		{}

		~mux_pool() {
		}
		void init(std::string const& url) {
			m_mux_dialurl = url;
			m_exit.store(true);
		}
		void deinit() {
			m_exit.store(false);
		}

		void dial_one_mux() {

			if (m_exit.load() == false) { return; }

			WWRP<wawo::net::channel_future> dial_f = wawo::net::socket::dial(m_mux_dialurl, [](WWRP<wawo::net::channel> const& ch) {
				WWRP<wawo::net::channel_handler_abstract> h_hlen = wawo::make_ref<wawo::net::handler::hlen>();
				ch->pipeline()->add_last(h_hlen);

				WWRP<wawo::net::channel_handler_abstract> h_dh_symmetric = wawo::make_ref<wawo::net::handler::dh_symmetric_encrypt>();
				ch->pipeline()->add_last(h_dh_symmetric);

				WWRP<wawo::net::handler::mux> h_mux = wawo::make_ref<wawo::net::handler::mux>();
				h_mux->bind<wawo::net::handler::fn_mux_evt_t>(wawo::net::handler::E_MUX_CH_CONNECTED, &roger::mux_pool::connected, roger::mux_pool::instance(), std::placeholders::_1);

				ch->pipeline()->add_last(h_mux);
			}, roger::mux_cfg );

			dial_f->add_listener([P=this](WWRP<wawo::net::channel_future> const& f) {
				if (f->get() != wawo::OK) {
					WW_SCHEDULER->schedule([P]() {
						P->dial_one_mux();
					});
				}
			});
		}

		void connected(WWRP<wawo::net::handler::mux> const& mux_)
		{
			wawo::lock_guard<wawo::spin_mutex> lg(m_mutex);
			m_muxs.push_back(mux_);
			mux_->bind<wawo::net::handler::fn_mux_evt_t>(wawo::net::handler::E_MUX_CH_CLOSED, &mux_pool::closed, this, std::placeholders::_1);
		}

		void closed(WWRP<wawo::net::handler::mux> const& mux_)
		{
			wawo::lock_guard<wawo::spin_mutex> lg(m_mutex);
			mux_vector_t::iterator it = m_muxs.begin();
			while (it != m_muxs.end()) {
				if (*it == mux_) {
					m_muxs.erase(it);
					break;
				}
				++it;
			}

			dial_one_mux();
			//connect new
		}

		WWRP<wawo::net::handler::mux> next() {
			wawo::lock_guard<spin_mutex> lg(m_mutex);
			if (m_muxs.size() == 0) {
				return 0;
			}
			m_idx = m_idx % m_muxs.size();
			return m_muxs[m_idx++];
		}

		inline u32_t count() {
			return m_muxs.size();
		}
	};

	class mux_stream_handler:
		public wawo::net::channel_inbound_handler_abstract,
		public wawo::net::channel_activity_handler_abstract
	{
	public:
		void connected(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WAWO_ASSERT(ctx != NULL);
			WWRP<proxy_ctx> pctx = ctx->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);

			pctx->ch_client_ctx->event_poller()->execute([pctx,ctx]() {

				WAWO_ASSERT(pctx->state == PIPE_DIAL_STREAM_OK);
				TRACE_CLIENT_SIDE_CTX("[roger][s%d]stream connected", ctx->ch->ch_id());
				pctx->ch_stream_ctx = ctx;
				pctx->state = PIPE_DIALING_SERVER;

				if (pctx->type == T_HTTP) {
					WAWO_ASSERT(pctx->http_resp_parser == NULL);
					pctx->http_resp_parser = make_http_resp_parser();
					pctx->http_resp_parser->ctx = pctx;
				} else {
					if (pctx->protocol_packet->len()) {
						WWRP<wawo::packet> _up = wawo::make_ref<wawo::packet>(pctx->protocol_packet->len());
						_up->write(pctx->protocol_packet->begin(), pctx->protocol_packet->len());
						pctx->protocol_packet->reset();
						ctx_up(pctx,_up,false);
					}
				}

				WWRP<wawo::packet> outp = make_packet_CMD_CONNECT(pctx);
				WWRP<wawo::net::channel_future> f = pctx->ch_stream_ctx->write(outp);
				f->add_listener([pctx](WWRP<wawo::net::channel_future> const& f) {
					int rt = f->get();
					if (rt != wawo::OK) {
						pctx->state = PIPE_DIAL_SERVER_FAILED;

						WWRP<wawo::packet> downp = wawo::make_ref<wawo::packet>(64);
						resp_connect_result_to_client(pctx, downp, rt);
						WAWO_WARN("[client][#%u]connect server failed:%d, target addr: %s:%u"
							, pctx->ch_stream_ctx->ch->ch_id(), rt, ::ntohl(pctx->dst_ipv4), pctx->dst_port);
					}
				});
			});
		}

		void read_shutdowned(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<proxy_ctx> pctx = ctx->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			WAWO_ASSERT(pctx->ch_client_ctx != NULL);
			pctx->ch_client_ctx->event_poller()->execute([pctx, ctx]() {
				WAWO_ASSERT(pctx->ch_stream_ctx == ctx);
				if (pctx->type == T_HTTP) {
					WAWO_ASSERT(pctx->parent != NULL);
					WWRP<proxy_ctx> ppctx = pctx->parent;
					WAWO_ASSERT(ppctx->type == T_HTTP);
					WAWO_ASSERT(pctx->type == T_HTTP);

					roger::cancel_all_ctx_reqs(pctx, CANCEL_CODE_SERVER_NO_RESPONSE);
					WAWO_ASSERT(pctx->reqs.size() == 0);
					pctx->http_resp_parser->deinit();
					pctx->http_resp_parser->ctx = NULL;
					pctx->http_resp_parser = NULL;

					http_down(ppctx, NULL);
				} else {
					TRACE_CLIENT_SIDE_CTX("[roger][s%d]stream read closed, plan ctx_down", ctx->ch->ch_id());
					pctx->stream_read_closed = true;
					ctx_down(pctx, NULL);
				}
			});
		}

		void closed(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<proxy_ctx> pctx = ctx->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			WAWO_ASSERT(pctx->ch_client_ctx != NULL);
			pctx->ch_client_ctx->event_poller()->execute([pctx,ctx]() {
				ctx->ch->set_ctx(NULL);
				TRACE_CLIENT_SIDE_CTX("[roger][s%d]stream closed", ctx->ch->ch_id());
				if (pctx->type == T_HTTP) {
					WAWO_ASSERT(pctx->parent != NULL);
					WWRP<proxy_ctx> ppctx = pctx->parent;

					WAWO_ASSERT(pctx->reqs.size() == 0);
					WAWO_ASSERT(pctx->http_proxy_ctx_map.size() == 0);
					WAWO_ASSERT(pctx->http_resp_parser == NULL);

					ppctx->http_proxy_ctx_map.erase(pctx->HP_key);
				} else {
					//last time to flush
					WAWO_ASSERT(pctx->stream_read_closed == true);
				}
			});
		}

		void read(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::packet> const& income) {
			WWRP<proxy_ctx> pctx = ctx->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			WAWO_ASSERT(pctx->ch_client_ctx != NULL);

			pctx->ch_client_ctx->event_poller()->execute([ctx,pctx, income]() {
				switch (pctx->state) {
					case PIPE_DIALING_SERVER:
					{
						WAWO_ASSERT(income != NULL);
						WAWO_ASSERT(income->len() >= 1);
						int32_t code = income->read<int32_t>();
						if (WAWO_LIKELY(code == wawo::OK)) {
							pctx->state = PIPE_DIAL_SERVER_OK;

							if (pctx->type == T_HTTP) {
								http_up(pctx, NULL);
							}
							else {
								ctx_up(pctx, NULL);
							}
						}
						resp_connect_result_to_client(pctx, income, code);
					}
					break;
					case PIPE_DIAL_SERVER_OK:
					{
						if (pctx->type == T_HTTP) {
							//@TODO, for HEP_INVALID_CONSTANT ISSUE, need a investigation
							int ec = http_parse_down(pctx, income);
							if (ec != wawo::OK) {
								message_queue empty_q;
								std::swap(empty_q, pctx->reqs);
								pctx->ch_stream_ctx->close();
							}
						} else {
							ctx_down(pctx, income);
						}
					}
					break;
					default:
					{
						WAWO_ASSERT(!"WHAT");
					}
					break;
				}
			});
		}
	};


	class local_proxy_handler :
		public wawo::net::channel_inbound_handler_abstract,
		public wawo::net::channel_activity_handler_abstract
	{
	public:
		void connected(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<proxy_ctx> pctx = wawo::make_ref<proxy_ctx>();
			ctx->ch->set_ctx(pctx);

			pctx->state = WAIT_FIRST_PACK;
			pctx->down_state = WS_IDLE;
			pctx->up_state = WS_IDLE;
			pctx->client_read_closed = false;
			pctx->stream_read_closed = false;
			pctx->ch_client_ctx = ctx;
			pctx->protocol_packet = wawo::make_ref<wawo::packet>();
			pctx->type = T_NONE;
			TRACE_CLIENT_SIDE_CTX("[roger][#%d]client connected", ctx->ch->ch_id());
		}

		void read_shutdowned(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<proxy_ctx> pctx = ctx->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			TRACE_CLIENT_SIDE_CTX("[roger][#%d]client read closed", ctx->ch->ch_id());
			pctx->client_read_closed = true;

			if (pctx->http_req_parser != NULL) {
				WAWO_ASSERT(pctx->type == T_HTTP || pctx->type == T_HTTPS);
				WAWO_ASSERT(pctx->http_req_parser != NULL);
				pctx->http_req_parser->deinit();
				pctx->http_req_parser->ctx = NULL;
				pctx->http_req_parser = NULL;
			}

			if (pctx->type == T_HTTP) {
				std::for_each(pctx->http_proxy_ctx_map.begin(), pctx->http_proxy_ctx_map.end(), [](stream_http_proxy_ctx_pair_t const& pair) {
					WWRP<proxy_ctx> _pctx = pair.second;
					WAWO_ASSERT(_pctx->http_req_parser == NULL);

					WAWO_ASSERT(_pctx->parent != NULL);
					_pctx->client_read_closed = true;
					http_up(_pctx, NULL);
				});
			} else {
				ctx_up(pctx, NULL);
			}
		}

		void closed(WWRP<wawo::net::channel_handler_context > const& ctx) {
			WWRP<proxy_ctx> pctx = ctx->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			WAWO_ASSERT(pctx->client_read_closed == true);
			ctx->ch->set_ctx(NULL);
			TRACE_CLIENT_SIDE_CTX("[roger][#%d]client closed", ctx->ch->ch_id());
		}

		void write_block(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WAWO_ASSERT(!"TODO");
		}

		void write_unblock(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WAWO_ASSERT(!"TODO");
		}

		void read(WWRP<wawo::net::channel_handler_context> const& ctx_ , WWRP<wawo::packet> const& income) {
			WAWO_ASSERT( income != NULL);
			WWRP<proxy_ctx> pctx = ctx_->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			WAWO_ASSERT(pctx->ch_client_ctx == ctx_);

		_begin_check:
			switch (pctx->state) {
			case WAIT_FIRST_PACK:
			{
				if (income->len()) {
					pctx->protocol_packet->write(income->begin(), income->len());
					income->skip(income->len());
				}
				//refer to https://www.ietf.org/rfc/rfc1928.txt
				if (pctx->protocol_packet->len() < 3) {
					goto _end_check;
				}

				wawo::byte_t v_and_nmethods[2];
				pctx->protocol_packet->peek(v_and_nmethods, 2);

				if (v_and_nmethods[0] == 0x05) {
					pctx->type = T_SOCKS5;
					pctx->state = SOCKS5_CHECK_AUTH;
				}
				else if (v_and_nmethods[0] == 0x04) {
					pctx->type = T_SOCKS4;
					pctx->state = SOCKS4_PARSE;
				} else {
					int detect_rt = _detect_http_proxy(pctx);
					if (detect_rt > 0) {
						goto _end_check;
					}
					else if (detect_rt < 0) {
						WAWO_ERR("[client][#%u]unknown proxy type", pctx->ch_client_ctx->ch->ch_id() );
						pctx->ch_client_ctx->close();
						goto _end_check;
					} else {
						income->write_left(pctx->protocol_packet->begin(), pctx->protocol_packet->len());
						pctx->protocol_packet->reset();
						pctx->state = HTTP_REQ_PARSE;
						pctx->http_req_parser = roger::make_http_req_parser();
						pctx->http_req_parser->ctx = pctx;
					}
				}
				goto _begin_check;
			}
			break;
			case SOCKS5_CHECK_AUTH:
			{
				if (income->len()) {
					pctx->protocol_packet->write(income->begin(), income->len());
					income->reset();
				}
				WAWO_ASSERT(pctx->protocol_packet->len() >= 2);
				wawo::byte_t v_and_nmethods[2];
				pctx->protocol_packet->peek(v_and_nmethods, 2);

				WAWO_ASSERT(v_and_nmethods[0] == 0x5);
				u8_t nmethods = (v_and_nmethods[1] & 0xff);
				u32_t hc = nmethods + 2;
				if (pctx->protocol_packet->len() < (hc)) {
					return;
				}
				pctx->protocol_packet->skip(hc);
				pctx->state = SOCKS5_RESP_HANDSHAKE;
				_socks5_check_auth(pctx);
			}
			break;
			case SOCKS5_RESP_HANDSHAKE:
				{
					if (income->len()) {
						pctx->protocol_packet->write(income->begin(), income->len());
						income->skip(income->len());
					}
				}
				break;
			case SOCKS5_CHECK_CMD:
			{
				if (income->len()) {
					pctx->protocol_packet->write(income->begin(), income->len());
					income->skip(income->len());
				}
				int check_rt = _socks5_check_cmd(pctx);
				if (check_rt == E_OK) {
					pctx->state == PIPE_PREPARE;
					goto _begin_check;
				}
				else if (check_rt < 0) {
					pctx->ch_client_ctx->close();
					TRACE_CLIENT_SIDE_CTX("[client][%u]protocol check failed: %d, close client", pctx->ch_client_ctx->ch->ch_id(), check_rt );
				} else {}
			}
			break;//end for SOCKS5_AUTH_DONE
			case SOCKS4_PARSE:
			{
				if (income->len()) {
					pctx->protocol_packet->write(income->begin(), income->len());
					income->skip(income->len());
				}

				//socks4
				int parse_rt = _socks4_parse(pctx);
				if (parse_rt < E_OK) {
					pctx->ch_client_ctx->close();
					WAWO_WARN("[roger]parse socks4 protocol failed: %d, close client", parse_rt);
				}
				else if (parse_rt == E_OK) {
					pctx->state = PIPE_PREPARE;
					goto _begin_check;
				} else {}
			}
			break;
			case PIPE_PREPARE:
			{
				if (pctx->address_type == HOST && wawo::net::is_dotipv4_decimal_notation(pctx->dst_domain.c_str())) {
					wawo::net::ipv4_t _ip;
					int crt = wawo::net::dotiptoip(pctx->dst_domain.c_str(), _ip);
					if (crt != wawo::OK) {
						WAWO_WARN("[client][http_proxy][#%u]invalid ipaddr, close cp", pctx->ch_client_ctx->ch->ch_id() );
						pctx->state = PIPE_DIAL_STREAM_FAILED;
						pctx->ch_client_ctx->close();
						goto _end_check;
					}

					pctx->address_type = IPV4;
					pctx->dst_ipv4 = _ip;
					pctx->dst_domain = "";
				}

				WWRP<wawo::net::handler::mux> mux_ = roger::mux_pool::instance()->next();
				WAWO_ASSERT(mux_ != NULL);
				wawo::net::handler::mux_stream_id_t sid=wawo::net::handler::mux_make_stream_id();

				pctx->state = PIPE_DIALING_STREAM;

				int ec;
				WWRP<wawo::net::handler::mux_stream> muxs = mux_->open_stream(sid,ec);
				WAWO_ASSERT(ec == wawo::OK);

				WWRP<wawo::net::channel_promise> dial_f = muxs->make_promise();
				dial_f->add_listener([pctx, sid](WWRP<wawo::net::channel_future> const& f) {
					int rt = f->get();
					if (rt == wawo::OK) {
						WAWO_ASSERT(f->channel()->event_poller()->in_event_loop());
						f->channel()->set_ctx(pctx);
					}

					pctx->ch_client_ctx->event_poller()->execute([pctx,sid,rt,f]() {
						if (rt == wawo::OK) {
							pctx->state = PIPE_DIAL_STREAM_OK;
						} else {
							pctx->state = PIPE_DIAL_STREAM_FAILED;
							WWRP<packet> downp = wawo::make_ref<packet>(64);
							resp_connect_result_to_client(pctx, downp, rt);
							pctx->ch_client_ctx->close();
							WAWO_INFO("[client][#%u]dial mux_stream failed:%d, target addr: %s:%u"
								, sid, rt, wawo::net::ipv4todotip(pctx->dst_ipv4).c_str(), pctx->dst_port);
						}
					});
				});

				muxs->dial([](WWRP<wawo::net::channel> const& ch) {
					ch->ch_set_read_buffer_size(roger::mux_stream_sbc.rcv_size);
					ch->ch_set_write_buffer_size(roger::mux_stream_sbc.snd_size);
					WWRP<mux_stream_handler> h = wawo::make_ref<mux_stream_handler>();
					ch->pipeline()->add_last(h);
				}, dial_f );
			}
			break;
			case PIPE_DIALING_STREAM:
			case PIPE_DIAL_STREAM_OK:
			{
				pctx->protocol_packet->write(income->begin(), income->len());
			}
			break;
			case PIPE_DIALING_SERVER:
			{
				WAWO_ASSERT(pctx->protocol_packet->len() == 0);
				WAWO_ASSERT(income != NULL);
				ctx_up(pctx, income,false);
			}
			break;
			case PIPE_DIAL_SERVER_OK:
			{
				WAWO_ASSERT(pctx->protocol_packet->len() == 0);
				WAWO_ASSERT(income != NULL);
				ctx_up(pctx, income);
			}
			break;
			case HTTP_REQ_PARSE:
			{
				WAWO_ASSERT(pctx->http_req_parser != NULL);
				int ec = wawo::OK;
				while (income->len() && pctx->state == HTTP_REQ_PARSE) {
					u32_t nparsed = pctx->http_req_parser->parse((char const *)income->begin(), income->len(), ec);
					WAWO_ASSERT(nparsed <= income->len());
					income->skip(nparsed);

					bool is_parse_error = (pctx->type == T_HTTPS && pctx->state == PIPE_PREPARE) ? ec != HPE_CB_message_complete : ec != wawo::OK;
					if (is_parse_error) {
						pctx->state = HTTP_PARSE_ERROR;
						pctx->ch_client_ctx->close();
						WAWO_WARN("[roger][#%u]http request parsed failed: %d", pctx->ch_client_ctx->ch->ch_id(), ec);
						goto _end_check;
					}
				}//end for __HTTP_PARSE tag

				if (pctx->type == T_HTTPS && pctx->sub_state == S_ON_MESSAGE_COMPLETE) {
					WAWO_ASSERT(income->len() == 0);
					WAWO_ASSERT(pctx->state == PIPE_PREPARE);
					WAWO_ASSERT(pctx->cur_req->opt == wawo::net::protocol::http::O_CONNECT);
					goto _begin_check;
				}
			}//end for HTTP_PARSER state
			break;
			case PIPE_DIAL_STREAM_FAILED:
			{
				WAWO_ASSERT(!"PROTOCOL CHECK LOGIC ISSUE");
			}
			break;
			case PIPE_DIAL_SERVER_FAILED:
			{
				WAWO_ASSERT(pctx->type != T_HTTP);
				//ignore this input

				//close flow in this case
				//client resp error to client's client fd, client's client should action on this error(usually close fd),
				//client received FIN and forward to rserver, rserver check current state , do stream->close(), stream close would be result a FIN sent to client
				//client get both side FIN , client close
				//WAWO_ASSERT(!"TODO"); //check whether code has been forwarded
			}
			break;
			case HTTP_PARSE_ERROR:
			{
				WAWO_ASSERT(!"HTTP PARSE LOGIC ISSUE");
			}
			break;
			default:
			{
				WAWO_THROW("WHAT")
			}
			break;
			}

		_end_check:
			(void)1;
		}
	};

	
	inline int load_file_into_len_cstr(std::string& file, std::string const& file_path_name) {
		FILE* fp = fopen(file_path_name.c_str(), "rb");
		if (fp == NULL) {
			return wawo::get_last_errno();
		}

		int seekrt = fseek(fp, 0L, SEEK_END);
		long end = ftell(fp);
		int seekbeg = fseek(fp, 0L, SEEK_SET);

		(void)seekrt;
		(void)seekbeg;

		WWRP<wawo::packet> file_bytes = wawo::make_ref<wawo::packet>(end);
		::size_t rbytes = fread((char*)file_bytes->begin(), 1, end, fp);
		file_bytes->forward_write_index(rbytes);

		std::string _file((char*)file_bytes->begin(), file_bytes->len());
		file = _file;
		WAWO_ASSERT((long)file.length() == end);
		return file.length();
	}

	class http_server_handler :
		public wawo::ref_base
	{

	public:
		void on_request(WWRP<wawo::net::channel_handler_context> const& ctx, WWSP<wawo::net::protocol::http::message> const& m) {
			WAWO_ASSERT(m->type == wawo::net::protocol::http::T_REQ);
			WAWO_INFO("[http_server]request uri: %s", m->url.c_str());

			std::string proxy_type = std::string("PROXY");
			int is_socks5_url = wawo::strpos(m->url.c_str(), "socks5.pac");
			if (is_socks5_url != -1) {
				proxy_type = std::string("SOCKS5");
			}

			WWSP<wawo::net::protocol::http::message> resp = wawo::make_shared<wawo::net::protocol::http::message>();
			resp->type = wawo::net::protocol::http::T_RESP;

			resp->ver = { 1,1 };;
			resp->h.set("Content-Type", "application/x-ns-proxy-autoconfig");
			resp->h.set("Connection", "close");

			std::string pac_file_content;
			int load_rt = load_file_into_len_cstr(pac_file_content, "proxy.pac");

			//#define TEST_302
#ifdef TEST_302
			resp->code = 302;
			resp->status = "Found";
			resp->body = "file moved";
			int resprt_ = peer->respond(resp, message);
			WAWO_INFO("[http_server]resp: %d", resprt_);
			peer->close();

			return;
#endif

			if (load_rt < 0 || pac_file_content.length() == 0) {
				resp->status_code = 404;
				resp->status = "File not found";
				WWRP<wawo::packet> body = wawo::make_ref<wawo::packet>();
				const char* tmp = "file not found";
				body->write((wawo::byte_t*)tmp, (u32_t)wawo::strlen((char*)tmp));
				resp->body = body;
			}
			else {

				std::string host = m->h.get("Host");

				if (host.length() == 0) {
					resp->status_code = 403;
					resp->status = "access forbidden";

					WWRP<wawo::packet> body = wawo::make_ref<wawo::packet>();
					const char* tmp = "access forbidden";
					body->write((wawo::byte_t*)tmp, (u32_t)wawo::strlen((char*)tmp));

					resp->body = body;
				} else {

					resp->status_code = 200;
					resp->status = "OK";

					std::vector<std::string> host_and_port;
					wawo::split(host, ":", host_and_port);

					if (host_and_port.size() != 2) {
						WAWO_ERR("[http_server]invalid http request");
						ctx->close();
						return;
					}

					WAWO_ASSERT(host_and_port.size() == 2);

					std::string REPLACE_IP = "ROGER_HTTP_SERVER_ADDR";
					std::string REPLACE_TYPE = "PROXY_TYPE";

					std::string new_content_phase_1;
					std::string new_content_phase_2;

					int rep_rt1 = wawo::replace(pac_file_content, REPLACE_IP, host_and_port[0], new_content_phase_1);
					WAWO_ASSERT(rep_rt1 >= 1);

					int rep_rt2 = wawo::replace(new_content_phase_1, REPLACE_TYPE, proxy_type, new_content_phase_2);
					WAWO_ASSERT(rep_rt2 == 1);

					WWRP<wawo::packet> bodyp = wawo::make_ref<wawo::packet>(new_content_phase_2.length());
					bodyp->write((byte_t*)new_content_phase_2.c_str(), new_content_phase_2.length());
					resp->body = bodyp;
				}
			}

			WWRP<wawo::packet> outp;
			resp->encode(outp);
			ctx->write(outp);
			ctx->close();
		}
	};
}