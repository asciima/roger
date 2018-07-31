
#include "../shared/shared.hpp"
#include "client_handlers.hpp"

#include <stack>

namespace roger { namespace http {

	inline int int_to_hex_string(int n, char* const hex_string, wawo::u32_t len) {
		char* start = hex_string;

		static char _HEX_CHAR_[] = {
			'0','1','2','3',
			'4','5','6','7',
			'8','9','A','B',
			'C','D','E','F'
		};

		std::stack<char> char_stack;

		while (n != 0) {
			wawo::u32_t mode_v = n % 16;
			char_stack.push(_HEX_CHAR_[mode_v]);
			n /= 16;
		}

		u32_t i = 0;
		while (char_stack.size()) {
			WAWO_ASSERT(i < len);
			*(start + i++) = char_stack.top();
			char_stack.pop();
		}

		return i;
	}

	int hex_string_to_int(char const* hex, u32_t len) {
		u32_t _t = 0;
		u32_t _i = 0;
		u32_t _b = 1;

		while (_i < len) {
			char tt = *(hex + ((len - 1) - _i));

			if (tt >= '0' && tt <= '9') {
				tt -= '0';
			}
			else if (tt >= 'A' && tt <= 'F') {
				tt = (tt - 'A') + 10;
			}
			else {}

			_t += (tt*_b);
			_b *= 16;
			_i++;
		}
		return _t;
	}

	inline void encode_http_header(WWSP<wawo::net::protocol::http::message> const& m, WWRP<wawo::packet>& o) {
		char request_line[8192] = { 0 };
		int nrequest;
		if (m->urlfields.query.length()) {
			nrequest = snprintf(request_line, 8192, "%s %s?%s HTTP/%d.%d\r\n"
				, wawo::net::protocol::http::option_name[m->opt]
				, m->urlfields.path.c_str()
				, m->urlfields.query.c_str()
				, m->ver.major
				, m->ver.minor);
		} else {
			nrequest = snprintf(request_line, 8192, "%s %s HTTP/%d.%d\r\n"
				, wawo::net::protocol::http::option_name[m->opt]
				, m->urlfields.path.c_str()
				, m->ver.major
				, m->ver.minor);
		}

		WAWO_ASSERT(nrequest > 0);

		WWRP<packet> H;
		m->h.encode(H);
		H->write_left((byte_t*)request_line, nrequest);
		o = H;
	}
	
	namespace req {
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

	namespace resp {
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

	WWRP<parser> make_http_req_parser() {
		WWRP<parser> _p = wawo::make_ref<wawo::net::protocol::http::parser>();
		_p->init(wawo::net::protocol::http::PARSER_REQ);

		_p->on_message_begin = req::on_message_begin;
		_p->on_url = req::on_url;
		_p->on_status = req::on_status;
		_p->on_header_field = req::on_header_field;
		_p->on_header_value = req::on_header_value;
		_p->on_headers_complete = req::on_headers_complete;

		_p->on_body = http::req::on_body;
		_p->on_message_complete = req::on_message_complete;

		_p->on_chunk_header = req::on_chunk_header;
		_p->on_chunk_complete = req::on_chunk_complete;
		return _p;
	}

	WWRP<parser> make_http_resp_parser() {
		WWRP<parser> _p = wawo::make_ref<wawo::net::protocol::http::parser>();
		_p->init(PARSER_RESP);

		_p->on_message_begin = resp::on_message_begin;
		_p->on_url = resp::on_url;
		_p->on_status = resp::on_status;
		_p->on_header_field = resp::on_header_field;
		_p->on_header_value = resp::on_header_value;
		_p->on_headers_complete = resp::on_headers_complete;
		_p->on_body = resp::on_body;
		_p->on_message_complete = resp::on_message_complete;
		_p->on_chunk_header = resp::on_chunk_header;
		_p->on_chunk_complete = resp::on_chunk_complete;

		return _p;
	}

	namespace req {

		int on_message_begin(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);
			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);

			WAWO_ASSERT(pctx->cur_req == NULL);
			pctx->cur_req = wawo::make_shared<protocol::http::message>();
			pctx->cur_req->type = T_REQ;
			pctx->cur_req->is_header_contain_connection_close = false;
			pctx->sub_state = S_ON_MESSAGE_BEGIN;

			return wawo::OK;
		}

		int on_url(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_req != NULL);

			pctx->cur_req->opt = p->opt;
			pctx->cur_req->url = std::string(data, len);

			int parsert = protocol::http::parse_url(pctx->cur_req->url, pctx->cur_req->urlfields, p->opt == O_CONNECT);
			WAWO_RETURN_V_IF_NOT_MATCH(parsert, parsert == wawo::OK);

			//@TODO
			//check url:https://tools.ietf.org/html/rfc2616#page-128 to process a empty host string
			if( pctx->cur_req->urlfields.host.length() == 0 ){
				WAWO_WARN("opt: %s, data: %s", wawo::net::protocol::http::option_name[pctx->cur_req->opt], data);
			}	

			WAWO_ASSERT(pctx->cur_req->urlfields.host.length() > 0);
			return wawo::OK;
		}

		int on_status(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(!"what, http request message should not have this header line");

			(void)p;
			(void)data;
			(void)len;

			return wawo::OK;
		}

		int on_header_field(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_req != NULL);
			pctx->http_req_field_tmp = std::string(data, len);
			return wawo::OK;
		}

		int on_header_value(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_req != NULL);

			pctx->cur_req->h.set(pctx->http_req_field_tmp, std::string(data, len));
			pctx->http_req_field_tmp = "";
			return wawo::OK;
		}

		int on_headers_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_req != NULL);

			pctx->cur_req->ver = p->ver;
			WAWO_ASSERT(pctx->dst_domain.length() ==0 );
			pctx->sub_state = S_ON_HEADERS_COMPLETE;
			pctx->address_type = HOST;
			pctx->dst_domain = pctx->cur_req->urlfields.host;
			pctx->dst_port = pctx->cur_req->urlfields.port;
			WAWO_ASSERT(pctx->dst_domain.length() > 0);
			WAWO_ASSERT(pctx->dst_port > 0);

			//adjust for xx.xx.xx.xx
			if (wawo::net::is_dotipv4_decimal_notation(pctx->dst_domain.c_str())) {
				wawo::net::ipv4_t _ip;
				wawo::net::dotiptoip(pctx->dst_domain.c_str(), _ip);
				pctx->dst_ipv4 = ::ntohl(_ip);
				pctx->address_type = IPV4;
			}

			if (pctx->type == T_HTTPS) {
				//for https connection, on client on mux stream
				WAWO_ASSERT(pctx->cur_req->opt == wawo::net::protocol::http::O_CONNECT);
				return OK;
			}

			/*refer to RFC7230 , clients are not encouraged to send Proxy-Connection*/
			pctx->cur_req->h.remove("Proxy-Connection");
			pctx->cur_req->h.remove("proxy-connection");

			if (pctx->cur_req->h.get("Connection") == "close" ||
				pctx->cur_req->h.get("connection") == "close"
				) {
				pctx->cur_req->is_header_contain_connection_close = true;
			}

			if (pctx->dst_domain.length()>4096) {
				WAWO_ERR("[roger][s%u]invalid url: %s, len exceed 4096", pctx->dst_domain.c_str() );
				//invalid http url host
				return WAWO_NEGATIVE(HPE_INVALID_URL);
			}

			std::string _HP_key = pctx->dst_domain + std::to_string(pctx->dst_port);
			stream_http_proxy_ctx_map_t::iterator it = pctx->http_proxy_ctx_map.find(_HP_key);
			if (it == pctx->http_proxy_ctx_map.end()) {
				//no entry for this request, create new and append to parent
				WWRP<proxy_ctx> _pctx = wawo::make_ref<proxy_ctx>();
				_pctx->type = T_HTTP;
				_pctx->state = PIPE_DIALING_STREAM;

				_pctx->HP_key = _HP_key;
				_pctx->dst_port = pctx->cur_req->urlfields.port;
				_pctx->ch_client_ctx = pctx->ch_client_ctx;
				_pctx->resp_count = 0;
				_pctx->in_chunk_body = false;

				_pctx->address_type = pctx->address_type;
				_pctx->dst_domain = pctx->dst_domain;
				_pctx->dst_ipv4 = pctx->dst_ipv4;
				_pctx->dst_port = pctx->dst_port;

				_pctx->resp_rb = wawo::make_ref<wawo::bytes_ringbuffer>(roger::http_resp_rb_size);
				WAWO_ALLOC_CHECK(_pctx->resp_rb, roger::http_resp_rb_size);

				_pctx->http_resp_parser = make_http_resp_parser();
				WAWO_ASSERT(_pctx->http_resp_parser != NULL);
				_pctx->http_resp_parser->ctx = _pctx;

				pctx->http_proxy_ctx_map.insert({ _HP_key, _pctx });
				_pctx->parent = pctx;
				pctx->cur_req_ctx = _pctx;

				WWRP<wawo::net::handler::mux> mux_ = mux_pool::instance()->next();
				wawo::net::handler::mux_stream_id_t id = wawo::net::handler::mux_make_stream_id();
				WWRP<wawo::net::channel_future> ch_muxs_f = mux_->dial_stream(id, [](WWRP<wawo::net::channel> const& ch) {
					ch->ch_set_read_buffer_size(roger::mux_stream_sbc.rcv_size);
					ch->ch_set_write_buffer_size(roger::mux_stream_sbc.snd_size);
					WWRP<mux_stream_handler> h = wawo::make_ref<mux_stream_handler>();
					ch->pipeline()->add_last(h);
				});

				ch_muxs_f->add_listener([_pctx](WWRP<wawo::net::channel_future> const& f) {
					int rt = f->get();
					if (rt == wawo::OK) {
						_pctx->state = PIPE_DIAL_STREAM_OK;
						f->channel()->set_ctx(_pctx);
					} else {
						WAWO_INFO("[proxy_http]make stream failed for: %s", _pctx->cur_req->url.c_str());
						_pctx->state = PIPE_DIAL_STREAM_FAILED;
					}
				});
			} else {
				pctx->cur_req_ctx = it->second;
			}

			WAWO_ASSERT(pctx->cur_req_ctx->ch_stream_ctx != NULL);

			switch (pctx->cur_req_ctx->state) {
				case PIPE_DIALING_STREAM:
				case PIPE_DIAL_STREAM_OK:
				case PIPE_DIALING_SERVER:
				case HTTP_PARSE:
				{
					TRACE_HTTP_PROXY("[roger][s%u]push_back req: %s", pctx->cur_req_ctx->ch_stream_ctx->ch->ch_id(), pctx->cur_req_ctx->cur_req->url.c_str());
					pctx->cur_req_ctx->reqs.push(pctx->cur_req);

					WWRP<wawo::packet> H;
					encode_http_header(pctx->cur_req, H);
					ctx_up(pctx->cur_req_ctx, H);
					return wawo::OK;
				}
				break;
			default:
				{
					WAWO_ASSERT(!"WHAT, SUB PCTX in invalid state");
				}
				break;
			}

			return wawo::OK;
		}

		int on_body(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_req != NULL);
			WAWO_ASSERT(pctx->type == T_HTTP);

			WAWO_ASSERT(pctx->cur_req_ctx != NULL);

			WWRP<packet> http_body = wawo::make_ref<wawo::packet>(len + 64); //64 for chunk

			http_body->write((byte_t*)data, len);
			WAWO_ASSERT(pctx->cur_req_ctx != NULL);

			if (pctx->cur_req_ctx->in_chunk_body) {
				char hex_string[16] = { 0 };
				int i = int_to_hex_string(len, hex_string, 16);

				http_body->write_left((byte_t*)WAWO_HTTP_CRLF, 2);
				http_body->write_left((byte_t*)hex_string, i);

				http_body->write((byte_t*)WAWO_HTTP_CRLF, 2);
			}
			ctx_up(pctx->cur_req_ctx, http_body);
			return wawo::OK;
		}

		int on_message_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_req != NULL);
			pctx->sub_state = S_ON_MESSAGE_COMPLETE;

			if (pctx->type == T_HTTPS) {
				WAWO_ASSERT(pctx->state == HTTP_PARSE);
				pctx->state = PIPE_PREPARE;
				return -99999;
			}

			WAWO_ASSERT(pctx->cur_req != NULL);
			WAWO_ASSERT(pctx->cur_req_ctx != NULL);

			if (pctx->cur_req_ctx->in_chunk_body) {
				pctx->cur_req_ctx->in_chunk_body = false;
				//forward trailing
				WWRP<packet> chunk_trailing = wawo::make_ref<packet>();

				static const char* chunk_body_trailing = "0\r\n\r\n";
				chunk_trailing->write((byte_t*)chunk_body_trailing, 5);
				ctx_up(pctx->cur_req_ctx, chunk_trailing);
			}

			if (pctx->cur_req->is_header_contain_connection_close == true) {
				pctx->cur_req_ctx->ch_stream_ctx->shutdown_write();
			}

			pctx->cur_req_ctx = NULL;
			pctx->cur_req = NULL;

			return wawo::OK;
		}

		int on_chunk_header(WWRP<parser> const& p) {
			//@todo, post chunk
			(void)p;
			WAWO_ASSERT(p != NULL);
			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_req_ctx != NULL);
			pctx->cur_req_ctx->in_chunk_body = true;
			return wawo::OK;
		}

		int on_chunk_complete(WWRP<parser> const& p) {
			(void)p;
			WAWO_ASSERT(p != NULL);
			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_req_ctx != NULL);
			WAWO_ASSERT(pctx->cur_req_ctx->in_chunk_body == true );
			//http_ctx->in_chunk_body = true;
			return wawo::OK;
		}
	}

	namespace resp {

		int on_message_begin(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);
			WWRP<proxy_ctx> ctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);

			WAWO_ASSERT(ctx != NULL);
			ctx->cur_resp = wawo::make_shared<protocol::http::message>();
			ctx->cur_resp->type = T_RESP;

			TRACE_HTTP_PROXY("[roger][http][s%u]resp message begin", ctx->ch_stream_ctx->ch->ch_id() );
			return wawo::OK;
		}

		int on_url(WWRP<parser> const& p, const char* data, u32_t const& len) {
			(void)p;
			(void)data;
			(void)len;
			WAWO_ASSERT(!"WHAT");
			return wawo::OK;
		}

		int on_status(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);
			WWRP<proxy_ctx> ctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ctx->cur_resp != NULL);

			ctx->cur_resp->ver = p->ver;
			ctx->cur_resp->status_code = p->status_code;
			ctx->cur_resp->status = std::string(data, len);
			return wawo::OK;
		}

		int on_header_field(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);
			WWRP<proxy_ctx> ctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ctx->cur_resp != NULL);
			ctx->resp_http_field_tmp = std::string(data, len);
			return wawo::OK;
		}

		int on_header_value(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> ctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ctx->cur_resp != NULL);

			u32_t dlen = wawo::strlen(data);
			if (dlen < len) {
				ctx->cur_resp->h.set(ctx->resp_http_field_tmp, std::string(data, dlen));
				WAWO_INFO("[roger][http][s%u]invalid header value len, try to cut len", ctx->ch_stream_ctx->ch->ch_id() );
			} else {
				ctx->cur_resp->h.set(ctx->resp_http_field_tmp, std::string(data, len));
			}

			ctx->resp_http_field_tmp = "";
			return wawo::OK;
		}

		int on_headers_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_resp != NULL);

			switch (pctx->state) {
			case HTTP_PARSE:
			{				
				pctx->resp_header_connection_close = false; //default is false
				if (pctx->cur_resp->h.get("Connection") == "close" ||
					pctx->cur_resp->h.get("connection") == "close"
					)
				{
					pctx->resp_header_connection_close = true;
				}

				
				/* don't change first resp
				 * for others , keep-alive
				 */

				if ( (pctx->resp_count > 1 ) && pctx->resp_header_connection_close == true ) {
					pctx->cur_resp->h.set("Connection", "keep-alive");
				}

				WWRP<packet> http_reply;
				pctx->cur_resp->h.encode(http_reply);

				char resp_status[4096] = {0};

				int nresp = snprintf(resp_status, 4096, "HTTP/%d.%d %u %s\r\n", pctx->cur_resp->ver.major, pctx->cur_resp->ver.minor, pctx->cur_resp->status_code, pctx->cur_resp->status.c_str());
				WAWO_ASSERT(nresp > 0);

				http_reply->write_left((byte_t*)resp_status, nresp);
				WAWO_ASSERT(pctx->ch_client_ctx != NULL);

				ctx_down(pctx, http_reply);

				pctx->in_chunk_body = false;
				TRACE_HTTP_PROXY("[roger][http][s%u]resp header complete", pctx->ch_stream_ctx->ch->ch_id() );
				return wawo::OK ;
			}
			break;
			default:
			{
				WAWO_ASSERT(!"WHAT");
			}
			break;
			}

			return wawo::OK;
		}

		int on_body(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_resp != NULL);

			WWRP<packet> http_body = wawo::make_ref<packet>(len);
			
			http_body->write((byte_t*)data,len);

			if (pctx->in_chunk_body) {
				char hex_string[16] = { 0 };
				int i = int_to_hex_string(len, hex_string, 16);
				http_body->write_left((byte_t*)WAWO_HTTP_CRLF, 2);
				http_body->write_left((byte_t*)hex_string, i);
				http_body->write((byte_t*)WAWO_HTTP_CRLF, 2);
			}

			ctx_down(pctx, http_body);

			TRACE_HTTP_PROXY("[roger][http][s%u]resp body complete", pctx->ch_stream_ctx->ch->ch_id() );
			return wawo::OK;
		}

		int on_message_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_resp != NULL);

			WAWO_ASSERT(pctx->reqs.size());
			if (pctx->cur_resp->status_code != 100 &&
				pctx->cur_resp->status_code != 101 &&
				pctx->cur_resp->status_code != 102 /*RFC2518*/
				) {

				WWSP<wawo::net::protocol::http::message> _m = pctx->reqs.front();
				TRACE_HTTP_PROXY("[roger][s%u]pop req for message complete: %s", pctx->ch_stream_ctx->ch->ch_id(), _m->url.c_str() );

				pctx->reqs.pop();
			}
			else {
				WWSP<wawo::net::protocol::http::message> _m = pctx->reqs.front();
				TRACE_HTTP_PROXY("[roger][s%u]ignore, pop req: %s, for: %u", pctx->ch_stream_ctx->ch->ch_id(), _m->url.c_str() , pctx->cur_resp->status_code );
			}

			pctx->cur_resp = NULL;
			++pctx->resp_count;

			if (pctx->resp_header_connection_close == true ) {
				pctx->ch_stream_ctx->close();
				TRACE_HTTP_PROXY("[roger][s%u]close stream for connection: close", pctx->ch_stream_ctx->ch->ch_id());
				WAWO_ASSERT(pctx->reqs.size() == 0);
			}

			TRACE_HTTP_PROXY("[roger][http][s%u]resp message complete", pctx->ch_stream_ctx->ch->ch_id() );

			if (!pctx->in_chunk_body) {
				return wawo::OK;
			}
			pctx->in_chunk_body = false;

			WWRP<packet> http_chunk_body_trailing = wawo::make_ref<packet>();
			static const char* chunk_trailing = "0\r\n\r\n";
			http_chunk_body_trailing->write( (byte_t*)chunk_trailing,5);
			ctx_down(pctx, http_chunk_body_trailing);
			TRACE_HTTP_PROXY("[roger][http][s%u]resp message complete, finish last chunk flag", pctx->ch_stream_ctx->ch->ch_id() );
			return wawo::OK;
		}

		int on_chunk_header(WWRP<parser> const& p) {
			WAWO_ASSERT(p != NULL);
			WWRP<proxy_ctx> http_ctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);

			http_ctx->in_chunk_body = true;
			return wawo::OK;
		}

		int on_chunk_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p != NULL);
			WWRP<proxy_ctx> http_ctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(http_ctx->in_chunk_body == true);
			//ctx->in_chunk_body = false;
			return wawo::OK;
		}
	}
}}
