#include <wawo.h>
#include "../shared/shared.hpp"
#include "proxy_socks.hpp"


namespace roger {
	using namespace wawo::net::http;

	typedef std::unordered_map <std::string, WWRP<proxy_ctx> > stream_http_proxy_ctx_map_t;
	typedef std::pair <std::string, WWRP<proxy_ctx>> stream_http_proxy_ctx_pair_t;

	typedef std::chrono::steady_clock roger_http_clock_t;
	typedef std::chrono::time_point<roger_http_clock_t, std::chrono::milliseconds> roger_http_timepoint_t;
	typedef std::chrono::milliseconds roger_http_dur_t;

	struct proxy_ctx :
		public wawo::ref_base
	{
		proxy_ctx():ndownbytes(0) {
			TRACE_CLIENT_SIDE_CTX("proxy_ctx::proxy_ctx()");
		}
		~proxy_ctx() {
			TRACE_CLIENT_SIDE_CTX("proxy_ctx::~proxy_ctx()");
		}

		WWRP<proxy_ctx> parent;
		channel_id_t stream_id;
		proxy_forward_type type;
		proxy_state state;

		ctx_write_state up_state;
		ctx_write_state down_state;

		bool client_read_closed;
		bool stream_read_closed;

		WWRP<wawo::net::channel_handler_context> ch_client_ctx;
		WWRP<wawo::net::channel_handler_context> ch_stream_ctx;

		WWRP<wawo::packet> protocol_packet;

		packet_queue up_to_stream_packets;
		packet_queue down_to_client_packets;
		u32_t ndownbytes;
		roger_connect_address_type address_type;
		ipv4_t dst_ipv4;
		port_t dst_port;
		std::string dst_domain;

		roger_http_timepoint_t http_tp_last_req;
		WWRP<wawo::net::http::parser> http_req_parser;
		stream_http_proxy_ctx_map_t	http_proxy_ctx_map;

		WWRP<wawo::net::http::message> cur_req;
		WWRP<proxy_ctx> cur_req_ctx;

		WWRP<wawo::net::http::parser> http_resp_parser;
		WWRP<wawo::net::http::message> cur_resp;

		std::string resp_http_field_tmp;

		bool resp_has_chunk_body;
		bool resp_in_chunk_body;
		bool resp_header_connection_close;
		u32_t resp_count;
		u32_t resp_cur_body_len;
		u32_t resp_expected_len;

		std::string HP_key; //host and port
		message_queue reqs;
		std::queue<WWRP<wawo::packet>> pending_outp;

		std::string http_req_field_tmp;
		bool cur_req_in_chunk_body;
		bool cur_req_has_chunk_body;
	};

	inline WWRP<wawo::packet> make_packet_CMD_CONNECT(WWRP<proxy_ctx> const& pctx) {
		WWRP<wawo::packet> outp = wawo::make_ref<wawo::packet>();
		WAWO_ASSERT(pctx->dst_port > 0);
		if (pctx->address_type == IPV4) {
			WAWO_ASSERT(pctx->dst_ipv4 != 0);
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
			{//WAIT DIALING STREA RESULT, OR WAIT DIAL_SERVER RESULT
			}
			break;
			case PIPE_DIALING_SERVER:
			case PIPE_DIAL_SERVER_OK:
			{
				//check ctx stats first
				WAWO_ASSERT(ctx->ch_stream_ctx != NULL);
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
							ctx->ch_stream_ctx->close_write();
						}
					}
				}
			}
			break;
			case PIPE_DIAL_SERVER_FAILED:
			{
				WAWO_ASSERT(ctx->client_read_closed == true);
				WAWO_ASSERT(ctx->ch_stream_ctx != NULL);
				ctx->ch_stream_ctx->close_write();
			}
			break;
			default:
			{
				WAWO_TRACE_STREAM("[client][%s]cancel dialing stream", proxy_state_str[ctx->state]);
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
			ctx->ch_client_ctx->close_read();
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
			WAWO_ASSERT(outp->len() > 0);
			ctx->ch_client_ctx->write(outp, f);
		}
		else {
			if (ctx->stream_read_closed) {
				TRACE_CLIENT_SIDE_CTX("[client][#%u]stream read closed, close client write", ctx->ch_client_ctx->ch->ch_id() );
				ctx->ch_client_ctx->close_write();
			}
		}
	}

	inline void ctx_down_done(WWRP<proxy_ctx> const& ctx, int flushrt ) {
		WAWO_ASSERT(ctx->ch_client_ctx->event_poller()->in_event_loop());
		WAWO_ASSERT(ctx->down_state == WS_WRITING);
		ctx->down_state = WS_IDLE;
		if (flushrt == wawo::OK) {
			WAWO_ASSERT(ctx->down_to_client_packets.size());
			ctx->ndownbytes += ctx->down_to_client_packets.front()->len();
			ctx->down_to_client_packets.pop();
			_do_ctx_down(ctx);
		}
		else if (flushrt == wawo::E_CHANNEL_WRITE_BLOCK)
		{
		}
		else {
			if (ctx->ch_stream_ctx != NULL) {
				ctx->ch_stream_ctx->close_read();
			}
			ctx->ch_client_ctx->close();
		}
	}

	inline void ctx_down(WWRP<proxy_ctx> const& ctx, WWRP<wawo::packet> const& income, bool flush = true ) {
		WAWO_ASSERT(ctx->ch_client_ctx->event_poller()->in_event_loop());

		if (income != NULL) {
			WAWO_ASSERT(income->len() > 0);
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
		WWRP<parser> _p = wawo::make_ref<wawo::net::http::parser>();
		_p->init(wawo::net::http::HPT_REQ);

		_p->on_message_begin = http_req::on_message_begin;
		_p->on_url = http_req::on_url;
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
		WWRP<parser> _p = wawo::make_ref<wawo::net::http::parser>();
		_p->init(wawo::net::http::HPT_RESP);

		_p->on_message_begin = http_resp::on_message_begin;
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
		}
		case PIPE_DIAL_STREAM_OK:
		{
			if (up != NULL) {
				ctx->pending_outp.push(up);
			}
		}
		break;
		case PIPE_DIALING_SERVER:
		case PIPE_DIAL_SERVER_OK:
		{
			while (ctx->pending_outp.size()) {
				WWRP<wawo::packet>& t = ctx->pending_outp.front();
				ctx_up(ctx, t);
				ctx->pending_outp.pop();
			}
			WAWO_ASSERT(ctx->ch_stream_ctx != NULL);
			ctx_up(ctx, up);
		}
		break;
		case PIPE_DIAL_SERVER_FAILED:
		{
			WAWO_ASSERT(ctx->ch_stream_ctx != NULL);
			WAWO_ASSERT(up == NULL);
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

	static inline void http_down(WWRP<proxy_ctx> const& ppctx, WWRP<wawo::packet> const& down) {
		ctx_down(ppctx, down);
	}

	static inline int http_parse_down( WWRP<proxy_ctx> const& pctx, WWRP<wawo::packet> const& income) {
		WAWO_ASSERT(pctx->http_resp_parser != NULL);
		int ec = 0;
		u32_t nparsed_total = 0;
		while (income->len()) {
			u32_t nparsed = pctx->http_resp_parser->parse((char*)income->begin(), income->len(), ec);
			WAWO_ASSERT(nparsed >=0 );
			income->skip(nparsed);
			nparsed_total += nparsed;
			if (ec != wawo::OK) {
				WAWO_ERR("[roger][s%u]mux_stream resp, parse failed: %u", pctx->ch_stream_ctx->ch->ch_id(), ec);
				break;
			}
		}
		TRACE_HTTP_PROXY("[roger][s%u]parsed bytes: %u, income: %u, ec: %d", pctx->ch_stream_ctx->ch->ch_id(), nparsed_total, income->len() ,ec );
		return ec;
	}

	static inline void cancel_all_ctx_reqs(WWRP<proxy_ctx> const& pctx, int const& cancel_code) {
		WAWO_ASSERT(pctx->type == T_HTTP);
		while (pctx->reqs.size()) {
			if (cancel_code == CANCEL_CODE_SERVER_NO_RESPONSE) {
				pctx->reqs.pop();
				continue;
			}

			WWRP<wawo::packet> http_reply = wawo::make_ref<wawo::packet>();
			if (cancel_code >= CANCEL_CODE_PROXY_NOT_AVAILABLE && cancel_code <= CANCEL_CODE_PROXY_PIPE_ERROR) {
				http_reply->write((wawo::byte_t*) HTTP_RESP_ERROR[cancel_code], wawo::strlen(HTTP_RESP_ERROR[cancel_code]));
			} else {
				http_reply->write((wawo::byte_t*) HTTP_RESP_ERROR[CANCEL_CODE_PROXY_PIPE_ERROR], wawo::strlen(HTTP_RESP_ERROR[CANCEL_CODE_PROXY_PIPE_ERROR]));
			}

			WAWO_ASSERT(pctx->parent != NULL);
			http_down(pctx->parent, http_reply);
			TRACE_HTTP_PROXY("[roger][#%u][s%u][%s]http cancel req, code: %u, total resp count: %u, url: %s", pctx->ch_client_ctx->ch->ch_id(), pctx->ch_stream_ctx->ch->ch_id(), pctx->HP_key.c_str(), cancel_code, pctx->resp_count, pctx->reqs.front()->url.c_str());

			pctx->reqs.pop();
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
			if (rcode != wawo::OK) {
				WAWO_WARN("[roger][https]connect to host: %s:%u failed for: %d", pctx->dst_domain.c_str(), pctx->dst_port, rcode);
			}

			switch (rcode) {
				case wawo::OK:
				{
					downp->write_left((byte_t*)HTTP_RESP_RELAY_SUCCEED, wawo::strlen(HTTP_RESP_RELAY_SUCCEED));
				}
				break;
				case roger::E_DNS_TEMPORARY_ERROR:
				case roger::E_DNSLOOKUP_RETURN_NO_IP:
				case roger::E_DNS_BADQUERY:
				case roger::E_DNS_PROTOCOL_ERROR:
				{
					downp->write_left((byte_t*)HTTP_RESP_CONNECT_HOST_FAILED, wawo::strlen(HTTP_RESP_CONNECT_HOST_FAILED));
				}
				break;
				case roger::E_DNS_DOMAIN_NO_DATA:
				case roger::E_DNS_DOMAIN_NAME_NOT_EXISTS:
				{
					downp->write_left((byte_t*)HTTP_RESP_BAD_REQUEST, wawo::strlen(HTTP_RESP_BAD_REQUEST));
				}
				break;
				default:
				{
					downp->write_left((byte_t*)HTTP_RESP_CONNECT_HOST_FAILED, wawo::strlen(HTTP_RESP_CONNECT_HOST_FAILED));
				}
				break;
			}
			ctx_down(pctx, downp);
		}
		break;
		case T_HTTP:
		{
			if (rcode == wawo::OK) {
				WAWO_ASSERT(pctx->reqs.size() != 0);
				int ec = http_parse_down(pctx, downp);
				if (ec != wawo::OK) {
					cancel_all_ctx_reqs(pctx, CANCEL_CODE_SERVER_RESPONSE_PARSE_ERROR);
					pctx->ch_stream_ctx->close();
				}
			} else {
				WAWO_ASSERT(downp->len() == 0);
				if (pctx->reqs.size()) {
					WWRP<wawo::net::http::message>& m = pctx->reqs.front();
					WAWO_WARN("[roger][https]connect to url: %s failed for: %d, cancel reqs: %u", m->url.c_str(), rcode, pctx->reqs.size());
					cancel_all_ctx_reqs(pctx, CANCEL_CODE_CONNECT_HOST_FAILED);
					WAWO_ASSERT(pctx->reqs.size() == 0);
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

			if (m_exit.load() == false) {
				WAWO_WARN("[mux_pool]exit checked, cancel dial");
				return; 
			}

			WWRP<wawo::net::channel_future> dial_f = wawo::net::socket::dial(m_mux_dialurl, [](WWRP<wawo::net::channel> const& ch) {
				WWRP<wawo::net::channel_handler_abstract> h_hlen = wawo::make_ref<wawo::net::handler::hlen>();
				ch->pipeline()->add_last(h_hlen);

				WWRP<wawo::net::channel_handler_abstract> h_dh_symmetric = wawo::make_ref<wawo::net::handler::dh_symmetric_encrypt>();
				ch->pipeline()->add_last(h_dh_symmetric);

				WWRP<wawo::net::handler::mux> h_mux = wawo::make_ref<wawo::net::handler::mux>();
				h_mux->bind<wawo::net::handler::fn_mux_evt_t>(wawo::net::handler::E_MUX_CH_CONNECTED, &roger::mux_pool::connected, roger::mux_pool::instance(), std::placeholders::_1);
				h_mux->bind<wawo::net::handler::fn_mux_evt_t>(wawo::net::handler::E_MUX_CH_CLOSED, &roger::mux_pool::closed, roger::mux_pool::instance(), std::placeholders::_1);
				h_mux->bind<wawo::net::handler::fn_mux_evt_t>(wawo::net::handler::E_MUX_CH_ERROR, &roger::mux_pool::error, roger::mux_pool::instance(), std::placeholders::_1);

				ch->pipeline()->add_last(h_mux);
			}, roger::mux_cfg );

			dial_f->add_listener([P=this](WWRP<wawo::net::channel_future> const& f) {
				if (f->get() != wawo::OK) {
					WWRP<timer> t_dial = wawo::make_ref<timer>(std::chrono::seconds(2), [](WWRP<timer> const& t) {
						mux_pool::instance()->dial_one_mux();
					});
					WAWO_WARN("[mux_pool]mux dial failed with: %d, schedule another dial", f->get());
					wawo::global_timer_manager::instance()->start(t_dial);
				}
			});
		}

		void connected(WWRP<wawo::net::handler::mux> const& mux_)
		{
			wawo::lock_guard<wawo::spin_mutex> lg(m_mutex);
			m_muxs.push_back(mux_);
			WAWO_INFO("[mux_pool]mux dial done, add to pool");
		}

		void error(WWRP < wawo::net::handler::mux> const& mux_) {
			WWRP<timer> t_dial = wawo::make_ref<timer>(std::chrono::seconds(2), [](WWRP<timer> const& t) {
				mux_pool::instance()->dial_one_mux();
			});
			WAWO_ERR("[mux_pool]mux dial with error, schedule another dial");
			wawo::global_timer_manager::instance()->start(t_dial);
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
			WAWO_WARN("[mux_pool]mux closed, schedule another dial");
			WWRP<timer> t_dial = wawo::make_ref<timer>(std::chrono::seconds(2), [](WWRP<timer> const& t) {
				mux_pool::instance()->dial_one_mux();
			});
			wawo::global_timer_manager::instance()->start(t_dial);
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
				TRACE_CLIENT_SIDE_CTX("[roger][http][#%u][s%d]stream connected", pctx->ch_client_ctx->ch->ch_id(), ctx->ch->ch_id());
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

				TRACE_CLIENT_SIDE_CTX("[client][http][#%u][s%u]connect server: %s:%u",pctx->ch_client_ctx->ch->ch_id(), pctx->ch_stream_ctx->ch->ch_id(), pctx->dst_domain.c_str(), pctx->dst_port);

				WWRP<wawo::packet> outp = make_packet_CMD_CONNECT(pctx);
				WWRP<wawo::net::channel_future> f = pctx->ch_stream_ctx->write(outp);
				f->add_listener([pctx](WWRP<wawo::net::channel_future> const& f) {
					const int code = f->get();
					if (code != wawo::OK) {
						pctx->ch_client_ctx->event_poller()->execute([pctx, code]() {
							pctx->state = PIPE_DIAL_SERVER_FAILED;
							WWRP<wawo::packet> downp = wawo::make_ref<wawo::packet>(64);
							resp_connect_result_to_client(pctx, downp, code);
							//in case client read closed before stream established
							if (pctx->client_read_closed == true) {
								if (pctx->type == T_HTTP) {
									http_up(pctx, NULL);
								} else {
									ctx_up(pctx, NULL);
								}
							}
							WAWO_WARN("[client][#%u][s%u][%s][%s:%u]send connect cmd failed:%d", pctx->ch_client_ctx->ch->ch_id(), pctx->ch_stream_ctx->ch->ch_id(), pctx->dst_domain.c_str(), wawo::net::ipv4todotip(pctx->dst_ipv4).c_str(), pctx->dst_port, code);
						});
					}
				});
			});
		}

		void read_closed(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<proxy_ctx> pctx = ctx->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			WAWO_ASSERT(pctx->ch_client_ctx != NULL);
			pctx->ch_client_ctx->event_poller()->execute([pctx, ctx]() {
				WAWO_ASSERT(pctx->ch_stream_ctx == ctx);
				TRACE_CLIENT_SIDE_CTX("[roger][#%u][s%u]stream read closed", pctx->ch_client_ctx->ch->ch_id(), ctx->ch->ch_id() );
				pctx->stream_read_closed = true;

				if (pctx->type == T_HTTP) {
					WWRP<proxy_ctx> ppctx = pctx->parent;
					WAWO_ASSERT(ppctx != NULL);
					WAWO_ASSERT(ppctx->type == T_HTTP);
					WAWO_ASSERT(pctx->type == T_HTTP);
					WAWO_ASSERT(pctx->parent != NULL);

					//@TODO schedule another req
					roger::cancel_all_ctx_reqs(pctx, CANCEL_CODE_SERVER_NO_RESPONSE);

					ppctx->http_proxy_ctx_map.erase(pctx->HP_key);
					TRACE_HTTP_PROXY("[roger][#%u][s%u][%s]erase from ppctx", pctx->ch_client_ctx->ch->ch_id(), pctx->ch_stream_ctx->ch->ch_id(), pctx->HP_key.c_str());

					//have to fake client read close to recycle stream
					pctx->client_read_closed = true;
					http_up(pctx, NULL);
				} else {
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
				TRACE_CLIENT_SIDE_CTX("[roger][#%u][s%d]stream closed", pctx->ch_client_ctx->ch->ch_id(), ctx->ch->ch_id());
				if (pctx->type == T_HTTP) {
					WAWO_ASSERT(pctx->parent != NULL);
					//only parent has this
					WAWO_ASSERT(pctx->http_req_parser == NULL);
					WAWO_ASSERT(pctx->http_resp_parser != NULL);

					WAWO_ASSERT(pctx->http_proxy_ctx_map.size() == 0);
					WAWO_ASSERT(pctx->client_read_closed == true);
					WAWO_ASSERT(pctx->stream_read_closed == true);
					WAWO_ASSERT(pctx->reqs.size() == 0);

					pctx->http_resp_parser->deinit();
					pctx->http_resp_parser->ctx = NULL;
					pctx->http_resp_parser = NULL;
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
				WAWO_ASSERT(pctx->stream_read_closed == false);

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
							} else {
								ctx_up(pctx, NULL);
							}
						} else {
							WAWO_WARN("[client][#%u][s%u][%s][%s:%u]connect failed: %d", pctx->ch_client_ctx->ch->ch_id(), pctx->ch_stream_ctx->ch->ch_id(), pctx->dst_domain.c_str(), wawo::net::ipv4todotip(pctx->dst_ipv4).c_str(), pctx->dst_port, code );
							pctx->state = PIPE_DIAL_SERVER_FAILED;
							if (pctx->client_read_closed == true) {
								if (pctx->type == T_HTTP) {
									http_up(pctx, NULL);
								}
								else {
									ctx_up(pctx, NULL);
								}
							}
						}
						resp_connect_result_to_client(pctx, income, code);
					}
					break;
					case PIPE_DIAL_SERVER_OK:
					{
						if (pctx->type == T_HTTP) {
							WAWO_ASSERT(pctx->stream_read_closed == false);
							WAWO_ASSERT(pctx->reqs.size() > 0);
							//@TODO, for HEP_INVALID_CONSTANT ISSUE, need a investigation
							int ec = http_parse_down(pctx, income);
							if (ec != wawo::OK) {
								//stream read close would trigger req cancel
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

		void write_block(WWRP<channel_handler_context> const& ctx) {
			WWRP<proxy_ctx> pctx = ctx->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			WAWO_ASSERT(pctx->ch_client_ctx != NULL);
			pctx->ch_client_ctx->ch->ch_async_io_end_read();
		}

		void write_unblock(WWRP<channel_handler_context> const& ctx) {
			WWRP<proxy_ctx> pctx = ctx->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			WAWO_ASSERT(pctx->ch_client_ctx != NULL);
			pctx->ch_client_ctx->ch->ch_async_io_begin_read();
			pctx->ch_client_ctx->event_poller()->execute([pctx]() {
				ctx_up(pctx, NULL);
			});
		}
	};

	class local_proxy_handler :
		public wawo::net::channel_inbound_handler_abstract,
		public wawo::net::channel_activity_handler_abstract
	{
	public:
		void connected(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<proxy_ctx> ppctx = wawo::make_ref<proxy_ctx>();
			ctx->ch->set_ctx(ppctx);

			ppctx->state = WAIT_FIRST_PACK;
			ppctx->down_state = WS_IDLE;
			ppctx->up_state = WS_IDLE;
			ppctx->client_read_closed = false;
			ppctx->stream_read_closed = false;
			ppctx->ch_client_ctx = ctx;
			ppctx->protocol_packet = wawo::make_ref<wawo::packet>();
			ppctx->type = T_NONE;

			TRACE_CLIENT_SIDE_CTX("[roger][#%u]client connected", ctx->ch->ch_id());
		}

		void read_closed(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<proxy_ctx> ppctx = ctx->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(ppctx != NULL);
			TRACE_CLIENT_SIDE_CTX("[roger][#%u]client read closed", ctx->ch->ch_id());
			ppctx->client_read_closed = true;

			if (ppctx->type == T_HTTP) {
				std::for_each(ppctx->http_proxy_ctx_map.begin(), ppctx->http_proxy_ctx_map.end(), [](stream_http_proxy_ctx_pair_t const& pair) {
					WWRP<proxy_ctx> _pctx = pair.second;
					WAWO_ASSERT(_pctx->http_req_parser == NULL);

					_pctx->client_read_closed = true;
					http_up(_pctx, NULL);
				});
			} else {
				ctx_up(ppctx, NULL);
			}
		}

		void closed(WWRP<wawo::net::channel_handler_context > const& ctx) {
			WWRP<proxy_ctx> ppctx = ctx->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(ppctx != NULL);
			WAWO_ASSERT(ppctx->client_read_closed == true);
			ctx->ch->set_ctx(NULL);

			//in case of connection closed before http detected, we don't have req_parser
			if (ppctx->http_req_parser != NULL) {
				ppctx->http_req_parser->deinit();
				ppctx->http_req_parser->ctx = NULL;
				ppctx->http_req_parser = NULL;
			}
			TRACE_CLIENT_SIDE_CTX("[roger][#%u]client closed", ctx->ch->ch_id());
		}

		void write_block(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<proxy_ctx> ppctx = ctx->ch->get_ctx<proxy_ctx>();
			if (ppctx->ch_stream_ctx != NULL) {
				ppctx->ch_stream_ctx->ch->ch_async_io_end_read();
			}
		}

		void write_unblock(WWRP<wawo::net::channel_handler_context> const& ctx) {
			WWRP<proxy_ctx> ppctx = ctx->ch->get_ctx<proxy_ctx>();
			if (ppctx->ch_stream_ctx != NULL) {
				ppctx->ch_stream_ctx->ch->ch_async_io_begin_read();
			}
			//TRY TO FLUSH IF NECESSARY
			if (ppctx->type == T_HTTP) {
				http_down(ppctx, NULL );
			}
			else {
				ctx_down(ppctx, NULL);
			}
		}

		void read(WWRP<wawo::net::channel_handler_context> const& ctx_ , WWRP<wawo::packet> const& income) {
			WAWO_ASSERT( income != NULL);
			WWRP<proxy_ctx> ppctx = ctx_->ch->get_ctx<proxy_ctx>();
			WAWO_ASSERT(ppctx != NULL);
			WAWO_ASSERT(ppctx->ch_client_ctx == ctx_);
			WAWO_ASSERT(ppctx->client_read_closed == false);
		_begin_check:
			switch (ppctx->state) {
			case WAIT_FIRST_PACK:
			{
				if (income->len()) {
					ppctx->protocol_packet->write(income->begin(), income->len());
					income->skip(income->len());
				}
				//refer to https://www.ietf.org/rfc/rfc1928.txt
				if (ppctx->protocol_packet->len() < 3) {
					goto _end_check;
				}

				wawo::byte_t v_and_nmethods[2];
				ppctx->protocol_packet->peek(v_and_nmethods, 2);

				if (v_and_nmethods[0] == 0x05) {
					ppctx->type = T_SOCKS5;
					ppctx->state = SOCKS5_CHECK_AUTH;
				}
				else if (v_and_nmethods[0] == 0x04) {
					ppctx->type = T_SOCKS4;
					ppctx->state = SOCKS4_PARSE;
				} else {
					int detect_rt = _detect_http_proxy(ppctx);
					if (detect_rt == E_WAIT_BYTES_ARRIVE ) {
						goto _end_check;
					}
					else if (detect_rt == E_UNKNOWN_HTTP_METHOD) {
						WAWO_ERR("[client][#%u]unknown proxy type, force close", ppctx->ch_client_ctx->ch->ch_id() );
						ppctx->ch_client_ctx->close();
						goto _end_check;
					} else {
						income->write_left(ppctx->protocol_packet->begin(), ppctx->protocol_packet->len());
						ppctx->protocol_packet->reset();
						ppctx->state = HTTP_REQ_PARSE;
						ppctx->http_req_parser = roger::make_http_req_parser();
						ppctx->http_req_parser->ctx = ppctx;

						if (ppctx->type == T_HTTP) {
							ppctx->http_tp_last_req = std::chrono::time_point_cast<roger_http_dur_t>(roger_http_clock_t::now());
							WWRP<timer> _http_timer = wawo::make_ref<timer>(roger_http_dur_t(15), [ppctx](WWRP<timer> const& t) {
								if (ppctx->stream_read_closed == true) {
									return;
								}
								if (ppctx->http_proxy_ctx_map.size() != 0) {
									ppctx->ch_client_ctx->event_poller()->start_timer(t);
									return;
								}
								const roger_http_timepoint_t now = std::chrono::time_point_cast<roger_http_dur_t>(roger_http_clock_t::now());
								const roger_http_dur_t diff = now - ppctx->http_tp_last_req;
								if (diff.count() < 30) {
									ppctx->ch_client_ctx->event_poller()->start_timer(t);
									return;
								}

								ppctx->stream_read_closed = true;
								http_down(ppctx, NULL);
							});
							ppctx->ch_client_ctx->event_poller()->start_timer(_http_timer);
						}
					}
				}
				goto _begin_check;
			}
			break;
			case SOCKS5_CHECK_AUTH:
			{
				if (income->len()) {
					ppctx->protocol_packet->write(income->begin(), income->len());
					income->reset();
				}
				WAWO_ASSERT(ppctx->protocol_packet->len() >= 2);
				wawo::byte_t v_and_nmethods[2];
				ppctx->protocol_packet->peek(v_and_nmethods, 2);

				WAWO_ASSERT(v_and_nmethods[0] == 0x5);
				u8_t nmethods = (v_and_nmethods[1] & 0xff);
				u32_t hc = nmethods + 2;
				if (ppctx->protocol_packet->len() < (hc)) {
					return;
				}
				ppctx->protocol_packet->skip(hc);
				ppctx->state = SOCKS5_RESP_HANDSHAKE;
				_socks5_check_auth(ppctx);
			}
			break;
			case SOCKS5_RESP_HANDSHAKE:
				{
					if (income->len()) {
						ppctx->protocol_packet->write(income->begin(), income->len());
						income->skip(income->len());
					}
				}
				break;
			case SOCKS5_CHECK_CMD:
			{
				if (income->len()) {
					ppctx->protocol_packet->write(income->begin(), income->len());
					income->skip(income->len());
				}
				int check_rt = _socks5_check_cmd(ppctx);
				if (check_rt == E_OK) {
					ppctx->state = PIPE_PREPARE;
					goto _begin_check;
				}
				else if (check_rt < 0) {
					ppctx->ch_client_ctx->close();
					TRACE_CLIENT_SIDE_CTX("[client][%u]protocol check failed: %d, close client", ppctx->ch_client_ctx->ch->ch_id(), check_rt );
				} else {}
			}
			break;//end for SOCKS5_AUTH_DONE
			case SOCKS4_PARSE:
			{
				if (income->len()) {
					ppctx->protocol_packet->write(income->begin(), income->len());
					income->skip(income->len());
				}

				//socks4
				int parse_rt = _socks4_parse(ppctx);
				if (parse_rt < E_OK) {
					ppctx->ch_client_ctx->close();
					WAWO_WARN("[roger]parse socks4 protocol failed: %d, close client", parse_rt);
				}
				else if (parse_rt == E_OK) {
					ppctx->state = PIPE_PREPARE;
					goto _begin_check;
				} else {}
			}
			break;
			case PIPE_PREPARE:
			{
				WAWO_ASSERT(ppctx->type != T_HTTP);
				if (ppctx->address_type == HOST && wawo::net::is_dotipv4_decimal_notation(ppctx->dst_domain.c_str())) {
					wawo::net::ipv4_t _ip;
					int crt = wawo::net::dotiptoip(ppctx->dst_domain.c_str(), _ip);
					if (crt != wawo::OK) {
						WAWO_WARN("[client][http_proxy][#%u]invalid ipaddr, close cp", ppctx->ch_client_ctx->ch->ch_id() );
						ppctx->state = PIPE_DIAL_STREAM_FAILED;
						ppctx->ch_client_ctx->close();
						goto _end_check;
					}

					ppctx->address_type = IPV4;
					ppctx->dst_ipv4 = _ip;
					ppctx->dst_domain = "";
				}

				WWRP<wawo::net::handler::mux> mux_ = roger::mux_pool::instance()->next();

				if (mux_ == NULL) {
					WAWO_ERR("[client][#%u]no mux connected", ppctx->ch_client_ctx->ch->ch_id());
					ppctx->state = PIPE_DIAL_STREAM_FAILED;
					ppctx->ch_client_ctx->close();
					goto _end_check;
				}

				WAWO_ASSERT(mux_ != NULL);
				wawo::net::handler::mux_stream_id_t sid=wawo::net::handler::mux_make_stream_id();
				ppctx->state = PIPE_DIALING_STREAM;

				int ec;
				WWRP<wawo::net::handler::mux_stream> muxs = mux_->open_stream(sid,ec);
				if (ec != wawo::OK) {
					ppctx->state = PIPE_DIAL_STREAM_FAILED;
					WWRP<packet> downp = wawo::make_ref<packet>(64);
					resp_connect_result_to_client(ppctx, downp, ec);
					ppctx->ch_client_ctx->close();
					WAWO_INFO("[client][#%u]dial mux_stream failed:%d, target addr: %s:%u"
						, sid, ec, wawo::net::ipv4todotip(ppctx->dst_ipv4).c_str(), ppctx->dst_port);
					return;
				}

				WWRP<wawo::net::channel_promise> dial_f = muxs->make_promise();
				dial_f->add_listener([ppctx, sid](WWRP<wawo::net::channel_future> const& f) {
					int rt = f->get();
					if (rt == wawo::OK) {
						WAWO_ASSERT(f->channel()->event_poller()->in_event_loop());
						f->channel()->set_ctx(ppctx);
					}

					ppctx->ch_client_ctx->event_poller()->execute([ppctx,sid,rt,f]() {
						if (rt == wawo::OK) {
							ppctx->state = PIPE_DIAL_STREAM_OK;
						} else {
							ppctx->state = PIPE_DIAL_STREAM_FAILED;
							WWRP<packet> downp = wawo::make_ref<packet>(64);
							resp_connect_result_to_client(ppctx, downp, rt);
							ppctx->ch_client_ctx->close();
							WAWO_INFO("[client][#%u]dial mux_stream failed:%d, target addr: %s:%u"
								, sid, rt, wawo::net::ipv4todotip(ppctx->dst_ipv4).c_str(), ppctx->dst_port);
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
				ppctx->protocol_packet->write(income->begin(), income->len());
			}
			break;
			case PIPE_DIALING_SERVER:
			{
				WAWO_ASSERT(ppctx->protocol_packet->len() == 0);
				WAWO_ASSERT(income != NULL);
				ctx_up(ppctx, income,false);
			}
			break;
			case PIPE_DIAL_SERVER_OK:
			{
				WAWO_ASSERT(ppctx->protocol_packet->len() == 0);
				WAWO_ASSERT(income != NULL);
				ctx_up(ppctx, income);
			}
			break;
			case HTTP_REQ_PARSE:
			{
				if (ppctx->stream_read_closed == true) {
					WWRP<wawo::packet> downp = wawo::make_ref<packet>(128);
					downp->write((wawo::byte_t*)HTTP_RESP_PROXY_NOT_AVAILABLE_FAILED, wawo::strlen(HTTP_RESP_PROXY_NOT_AVAILABLE_FAILED));
					http_down(ppctx, downp);
					return;
				}

				WAWO_ASSERT(ppctx->http_req_parser != NULL);
				WAWO_ASSERT(ppctx->stream_read_closed == false);

				int ec = wawo::OK;
				while (income->len() && ppctx->state == HTTP_REQ_PARSE) {
					u32_t nparsed = ppctx->http_req_parser->parse((char const *)income->begin(), income->len(), ec);
					WAWO_ASSERT(nparsed <= income->len());
					income->skip(nparsed);

					if (ec != wawo::OK) {
						WWRP<wawo::packet> downp = wawo::make_ref<packet>(64);
						downp->write((wawo::byte_t*)HTTP_RESP_BAD_REQUEST, wawo::strlen(HTTP_RESP_BAD_REQUEST) );
						http_down(ppctx, downp);
						ppctx->state = HTTP_PARSE_ERROR;
						ppctx->stream_read_closed = true;
						http_down(ppctx, NULL);
						//double confirm close immediately
						ppctx->ch_client_ctx->close();
						WAWO_WARN("[roger][#%u]http request parsed failed: %d", ppctx->ch_client_ctx->ch->ch_id(), ec);
						goto _end_check;
					}
				}//end for __HTTP_PARSE tag
				if (ppctx->type == T_HTTPS) {
					if(ppctx->state == HTTP_REQ_PARSE) {
						WAWO_ASSERT(income->len() == 0);
						return;
					}
					WAWO_ASSERT(ppctx->state == PIPE_PREPARE, "[roger][https]ppctx->state: %d, ppctx->cur_req: %llu", ppctx->state, ppctx->cur_req.get() );

					if (income->len()) {
						ppctx->protocol_packet->write(income->begin(), income->len());
						WAWO_WARN("[roger][https]income->len() == %d after protocol check" , income->len() );
						income->reset();
					}
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
				WAWO_ASSERT(ppctx->type != T_HTTP);
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
		void on_request(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::net::http::message> const& m) {
			WAWO_ASSERT(m->type == wawo::net::http::T_REQ);
			WAWO_INFO("[http_server]request uri: %s", m->url.c_str());

			std::string proxy_type = std::string("PROXY");
			int is_socks5_url = wawo::strpos(m->url.c_str(), "socks5.pac");
			if (is_socks5_url != -1) {
				proxy_type = std::string("SOCKS5");
			}

			WWRP<wawo::net::http::message> resp = wawo::make_ref<wawo::net::http::message>();
			resp->H = wawo::make_ref<wawo::net::http::header>();
			resp->type = wawo::net::http::T_RESP;

			resp->ver = { 1,1 };;
			resp->H->set("Content-Type", "application/x-ns-proxy-autoconfig");
			resp->H->set("Connection", "close");

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

				std::string host = m->H->get("Host");

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