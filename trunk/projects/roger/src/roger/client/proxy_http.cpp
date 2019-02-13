
#include "../shared/shared.hpp"
#include "client_handlers.hpp"

#include <stack>

namespace roger {

	static const char* option_name_str[wawo::net::http::O_MAX] = {
		"GET",
		"HEAD",
		"POST",
		"PUT",
		"DELETE",
		"CONNECT",
		"OPTIONS",
		"TRACE"
	};

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

	inline void encode_http_request_header(WWRP<wawo::net::http::message> const& m, WWRP<wawo::packet>& o) {
		WWRP<packet> H;
		m->H->encode(H);
		H->write((wawo::byte_t*)WAWO_HTTP_CRLF, (wawo::u32_t)wawo::strlen(WAWO_HTTP_CRLF));

		WWRP<packet> outp = wawo::make_ref<wawo::packet>( m->url.length() + 32 );

		outp->write((wawo::byte_t*)roger::option_name_str[m->opt],wawo::strlen(roger::option_name_str[m->opt]));
		outp->write((wawo::byte_t*)WAWO_HTTP_SP, wawo::strlen(WAWO_HTTP_SP) );
		outp->write((wawo::byte_t*)m->urlfields.path.c_str(), m->urlfields.path.length());
		if (m->urlfields.query.length()) {
			outp->write((byte_t*)"?", 1);
			outp->write((byte_t*)m->urlfields.query.c_str(), m->urlfields.query.length());
		}

		char tmp[32];
		int n = snprintf(tmp, 32, " HTTP/%d.%d\r\n", m->ver.major, m->ver.minor);
		WAWO_ASSERT(n > 0 && n < 32);
		outp->write((byte_t*)tmp, n);
		outp->write(H->begin(), H->len());

		o = outp;
	}

	int _detect_http_proxy(WWRP<proxy_ctx> const& pctx) {
		byte_t method[WAWO_HTTP_METHOD_NAME_MAX_LEN + 1] = { 0 };
		if (pctx->protocol_packet->len() < WAWO_HTTP_METHOD_NAME_MAX_LEN) {
			return E_WAIT_BYTES_ARRIVE;
		}

		pctx->protocol_packet->peek(method, WAWO_HTTP_METHOD_NAME_MAX_LEN);
		byte_t upper[WAWO_HTTP_METHOD_NAME_MAX_LEN];
		wawo::strtoupper((char*)upper, WAWO_HTTP_METHOD_NAME_MAX_LEN, (char*)method);

		for (u8_t i = 0; i < wawo::net::http::O_MAX; ++i) {
			if (wawo::strpos((char*)upper, option_name_str[i]) != -1) {
				if (i == wawo::net::http::O_CONNECT) {
					pctx->type = T_HTTPS;
					return E_OK;
				}
				else {
					pctx->type = T_HTTP;
					return E_OK;
				}
			}
		}

		return E_UNKNOWN_HTTP_METHOD;
	}
	
	namespace http_req {

		int on_message_begin(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);
			WWRP<proxy_ctx> ppctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ppctx->client_read_closed == false);

			WAWO_ASSERT(ppctx->cur_req == NULL);
			ppctx->cur_req = wawo::make_ref<wawo::net::http::message>();
			ppctx->cur_req->H = wawo::make_ref<wawo::net::http::header>();
			ppctx->cur_req->type = T_REQ;

			ppctx->cur_req_has_chunk_body = false;
			ppctx->cur_req_in_chunk_body = false;
			return wawo::OK;
		}

		int on_url(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);
			WWRP<proxy_ctx> ppctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ppctx->client_read_closed == false);

			WAWO_ASSERT(ppctx->cur_req != NULL);

			ppctx->cur_req->opt = p->opt;
			ppctx->cur_req->url = std::string(data, len);

			int parsert = wawo::net::http::parse_url(ppctx->cur_req->url, ppctx->cur_req->urlfields, p->opt == O_CONNECT);
			if (parsert != wawo::OK) {
				WAWO_ERR("[roger][http][#%u]req url parsed failed: %s", ppctx->ch_client_ctx->ch->ch_id(), ppctx->cur_req->url.c_str() );
				return parsert;
			}

			//check url:https://tools.ietf.org/html/rfc2616#page-128 to process a empty host string
			if(ppctx->cur_req->urlfields.host.length() == 0 ) {
				//we'll check host header later
				WAWO_WARN("[roger][http]opt: %s, data: %s", option_name_str[ppctx->cur_req->opt], data);
			}

			//WAWO_ASSERT(pctx->cur_req->urlfields.host.length() > 0);
			return wawo::OK;
		}

		int on_header_field(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);
			WWRP<proxy_ctx> ppctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ppctx->client_read_closed == false);

			WAWO_ASSERT(ppctx->cur_req != NULL);
			ppctx->http_req_field_tmp = std::string(data, len);
			return wawo::OK;
		}

		int on_header_value(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);
			WWRP<proxy_ctx> ppctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ppctx->client_read_closed == false);

			WAWO_ASSERT(ppctx->cur_req != NULL);

			ppctx->cur_req->H->set(ppctx->http_req_field_tmp, std::string(data, len));
			ppctx->http_req_field_tmp.clear();
			return wawo::OK;
		}

		int on_headers_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);
			WWRP<proxy_ctx> ppctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ppctx->client_read_closed == false);

			WAWO_ASSERT(ppctx->cur_req != NULL);

			ppctx->cur_req->ver = p->ver;

			roger_connect_address_type address_type = HOST;
			std::string host = ppctx->cur_req->urlfields.host;
			port_t port = ppctx->cur_req->urlfields.port;

			if (host.length() == 0) {
				//borrow from header
				if (ppctx->cur_req->H->have("host")) {
					std::string _host = ppctx->cur_req->H->get("host");
					std::string::size_type n = _host.find(":");
					if (n != std::string::npos) {
						const std::string _port = _host.substr(n + 1);
						host = _host.substr(0,n);
						port = wawo::to_u32(_port.c_str()) & 0xFFFF;
					} else {
						host = _host;
						port = 80;
					}
				}
			}

			if (host.length() == 0 || host.length() >=HOST_URL_MAX_LENGTH) {
				WAWO_ERR("[roger][http][#%u]invalid http request: %s", ppctx->ch_client_ctx->ch->ch_id(), host.c_str());
				return WAWO_NEGATIVE(HPE_INVALID_URL);
			}

			//@refer to https://tools.ietf.org/html/rfc2616: 5.1.2 Request-URI
			//The absoluteURI form is REQUIRED when the request is being made to a proxy
			//WAWO_ASSERT(host.length() > 0);
			WAWO_ASSERT(port > 0);

			//adjust for xx.xx.xx.xx
			ipv4_t ipv4 = 0;
			if (wawo::net::is_dotipv4_decimal_notation(host.c_str())) {
				wawo::net::dotiptoip(host.c_str(), ipv4);
				address_type = IPV4;
				if (ipv4 == 0) {
					WAWO_ERR("[roger][http][#%u]invalid host: %s", ppctx->ch_client_ctx->ch->ch_id(), host.c_str());
					return WAWO_NEGATIVE(HPE_INVALID_URL);
				}
			}

			if (ppctx->type == T_HTTPS) {
				ppctx->address_type = address_type;
				ppctx->dst_domain = host;
				ppctx->dst_ipv4 = ipv4;
				ppctx->dst_port = port;
				//for https connection, one client one mux stream
				WAWO_ASSERT(ppctx->cur_req->opt == wawo::net::http::O_CONNECT);
				return OK;
			}

			/*
			 *@refer to RFC7230 , clients are not encouraged to send Proxy-Connection
			 */
			ppctx->cur_req->H->remove("proxy-connection");

			const std::string _HP_key = host + ":"+ std::to_string(port);
			stream_http_proxy_ctx_map_t::iterator it = ppctx->http_proxy_ctx_map.find(_HP_key);

			if (it != ppctx->http_proxy_ctx_map.end() ) {
				WAWO_ASSERT(it->second->client_read_closed == false);
				WAWO_ASSERT(it->second->stream_read_closed == false);
				ppctx->cur_req_ctx = it->second;
			} else {
				WAWO_ASSERT(ppctx->stream_read_closed == false);
				WWRP<wawo::net::handler::mux> mux_ = mux_pool::instance()->next();
				if (mux_ == NULL) {
					WAWO_ERR("[roger][http][#%u]no mux connected", ppctx->ch_client_ctx->ch->ch_id());
					ppctx->state = PIPE_DIAL_STREAM_FAILED;
					WWRP<wawo::packet> downp = wawo::make_ref<wawo::packet>();
					resp_connect_result_to_client(ppctx, downp, CANCEL_CODE_PROXY_NOT_AVAILABLE);
					//force close ch_client
					ppctx->stream_read_closed = true;
					http_down(ppctx, NULL);
					return WAWO_NEGATIVE(HPE_UNKNOWN);
				}

				//no entry for this request, create new and append to parent
				WWRP<proxy_ctx> _pctx = wawo::make_ref<proxy_ctx>();
				_pctx->type = T_HTTP;
				_pctx->state = PIPE_DIALING_STREAM;

				_pctx->up_state = WS_IDLE;
				_pctx->down_state = WS_IDLE;

				_pctx->client_read_closed = false;
				_pctx->stream_read_closed = false;

				_pctx->ch_client_ctx = ppctx->ch_client_ctx;

				_pctx->address_type = address_type;
				_pctx->dst_domain = host;
				_pctx->dst_ipv4 = ipv4;
				_pctx->dst_port = port;

				_pctx->resp_in_chunk_body = false;
				_pctx->resp_header_connection_close = false;
				_pctx->resp_count = 0;

				_pctx->HP_key = _HP_key;
				_pctx->cur_req_in_chunk_body = false;
				_pctx->parent = ppctx;

				ppctx->cur_req_ctx = _pctx;
				ppctx->http_proxy_ctx_map.insert({ _HP_key, _pctx });

				wawo::net::handler::mux_stream_id_t sid = wawo::net::handler::mux_make_stream_id();
				int ec;
				WWRP<wawo::net::handler::mux_stream> muxs = mux_->open_stream(sid, ec);
				WAWO_ASSERT(ec == wawo::OK);
				_pctx->stream_id = sid;
				WWRP<wawo::net::channel_promise> dial_f = muxs->make_promise();

				TRACE_HTTP_PROXY("[roger][http][#%u][s%u][%s]insert into ppctx", ppctx->ch_client_ctx->ch->ch_id(), _pctx->stream_id, ppctx->HP_key.c_str());

				dial_f->add_listener([_HP_key,sid,_pctx, ppctx](WWRP<wawo::net::channel_future> const& f) {
					int rt = f->get();
					if (rt == wawo::OK) {
						WAWO_ASSERT(f->channel()->ch_id() == _pctx->stream_id);
						f->channel()->set_ctx(_pctx);
					}
					_pctx->ch_client_ctx->ch->event_poller()->execute([_HP_key,sid,rt,_pctx, ppctx]() {
						if (rt == wawo::OK) {
							_pctx->state = PIPE_DIAL_STREAM_OK;
						} else { 
							_pctx->state = PIPE_DIAL_STREAM_FAILED;
							WAWO_INFO("[roger][http][#%u]dial mux_stream failed:%d, domain: %s:%u", sid, rt, _pctx->dst_domain.c_str(), _pctx->dst_port);
							WWRP<wawo::packet> downp = wawo::make_ref<wawo::packet>();
							resp_connect_result_to_client(_pctx, downp, CANCEL_CODE_PROXY_NOT_AVAILABLE);
							
							WAWO_ASSERT(_pctx->http_resp_parser == NULL);
							ppctx->http_proxy_ctx_map.erase(_HP_key);
						}
					});
				});
				muxs->dial([](WWRP<wawo::net::channel> const& ch) {
					ch->ch_set_read_buffer_size(roger::mux_stream_sbc.rcv_size);
					ch->ch_set_write_buffer_size(roger::mux_stream_sbc.snd_size);
					WWRP<mux_stream_handler> h = wawo::make_ref<mux_stream_handler>();
					ch->pipeline()->add_last(h);
				}, dial_f);
			}

			WAWO_ASSERT(ppctx->client_read_closed == false);
			ppctx->cur_req_ctx->reqs.push(ppctx->cur_req);
			ppctx->http_tp_last_req = std::chrono::time_point_cast<roger_http_dur_t>(roger_http_clock_t::now());

			WWRP<wawo::packet> H;
			encode_http_request_header(ppctx->cur_req, H);
			http_up(ppctx->cur_req_ctx, H);

			TRACE_HTTP_PROXY("[roger][http][#%u][s%u][%s]push req, %s, header: \n%s", ppctx->ch_client_ctx->ch->ch_id(), ppctx->cur_req_ctx->stream_id, ppctx->cur_req_ctx->HP_key.c_str(), ppctx->cur_req->url.c_str(), std::string((char*)H->begin(),H->len()).c_str() );
			return wawo::OK;
		}

		int on_body(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> ppctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ppctx->client_read_closed == false);
			WAWO_ASSERT(ppctx->type == T_HTTP);

			WAWO_ASSERT(ppctx->cur_req != NULL);
			WAWO_ASSERT(ppctx->cur_req_ctx != NULL);

			WWRP<packet> downp = wawo::make_ref<wawo::packet>(len + 2); //64 for chunk
			downp->write((byte_t*)data, len);

			if (ppctx->cur_req_in_chunk_body) {
				char hex_string[16] = { 0 };
				int i = int_to_hex_string(len, hex_string, 16);
				downp->write_left((byte_t*)WAWO_HTTP_CRLF, 2);
				downp->write_left((byte_t*)hex_string, i);
				downp->write((byte_t*)WAWO_HTTP_CRLF, 2);
			}
			http_up(ppctx->cur_req_ctx, downp);
			return wawo::OK;
		}

		int on_message_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> ppctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ppctx->client_read_closed == false);
			WAWO_ASSERT(ppctx->cur_req != NULL);

			if (ppctx->type == T_HTTPS) {
				//directly return
				WAWO_ASSERT(ppctx->cur_req->opt == wawo::net::http::O_CONNECT);
				WAWO_ASSERT(ppctx->state == HTTP_REQ_PARSE);
				ppctx->state = PIPE_PREPARE;
			} else {
				WAWO_ASSERT(ppctx->cur_req_ctx != NULL);
				if (ppctx->cur_req_has_chunk_body) {
					//forward trailing
					WWRP<packet> chunk_trailing = wawo::make_ref<packet>(64);
					static const char* chunk_body_trailing = "0\r\n\r\n";
					chunk_trailing->write((byte_t*)chunk_body_trailing, 5);
					http_up(ppctx->cur_req_ctx, chunk_trailing);
				}
			}
			ppctx->cur_req_ctx = NULL;
			ppctx->cur_req = NULL;

			return wawo::OK;
		}

		int on_chunk_header(WWRP<parser> const& p) {
			WAWO_ASSERT(p != NULL);
			WWRP<proxy_ctx> ppctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ppctx->cur_req_ctx != NULL);
			ppctx->cur_req_in_chunk_body = true;
			ppctx->cur_req_has_chunk_body = true;
			return wawo::OK;
		}

		int on_chunk_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p != NULL);
			WWRP<proxy_ctx> ppctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(ppctx->cur_req_ctx != NULL);
			WAWO_ASSERT(ppctx->cur_req_in_chunk_body == true );
			ppctx->cur_req_in_chunk_body = false;
			return wawo::OK;
		}
	}

	namespace http_resp {
		//impl note:
		//1, TE not supported for now
		int on_message_begin(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);
			WWRP<proxy_ctx> ctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);

			WAWO_ASSERT(ctx != NULL);
			ctx->cur_resp = wawo::make_ref<wawo::net::http::message>();
			ctx->cur_resp->H = wawo::make_ref<wawo::net::http::header>();
			ctx->cur_resp->type = T_RESP;
			ctx->resp_in_chunk_body = false;
			ctx->resp_has_chunk_body = false;
			ctx->resp_cur_body_len = 0;
			ctx->resp_expected_len = 0;
			TRACE_HTTP_PROXY("[roger][http][s%u]resp message begin", ctx->ch_stream_ctx->ch->ch_id());
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
				//http_parse sometimes occur in this situation
				ctx->cur_resp->H->set(ctx->resp_http_field_tmp, std::string(data, dlen));
				WAWO_WARN("[roger][http][s%u]invalid header value len, try to cut len", ctx->ch_stream_ctx->ch->ch_id());
			}
			else {
				ctx->cur_resp->H->set(ctx->resp_http_field_tmp, std::string(data, len));
			}

			ctx->resp_http_field_tmp.clear();
			return wawo::OK;
		}

		int on_headers_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_resp != NULL);
			WAWO_ASSERT(pctx->parent != NULL);
			WWRP<proxy_ctx> ppctx = pctx->parent;
			WAWO_ASSERT(pctx->state == PIPE_DIAL_SERVER_OK);

			if (pctx->cur_resp->H->get("connection") == "close")
			{
				/* don't change first resp
				* for others , keep-alive
				*/
				pctx->resp_header_connection_close = true;
				if (pctx->resp_count > 1 ) {
					if( ppctx->http_proxy_ctx_map.size() > 1 || 
						pctx->reqs.size()>1
					)
					pctx->cur_resp->H->set("Connection", "keep-alive");
				}
			}

			if (pctx->cur_resp->H->have("Content-Length")) {
				pctx->resp_expected_len = wawo::to_u32(pctx->cur_resp->H->get("Content-Length").c_str());
			}

			WWRP<packet> H;
			pctx->cur_resp->H->encode(H);
			H->write((wawo::byte_t*)WAWO_HTTP_CRLF, (wawo::u32_t)wawo::strlen(WAWO_HTTP_CRLF));
			char resp_status[2048] = { 0 };
			int nresp = snprintf(resp_status, 2048, "HTTP/%d.%d %u %s\r\n", pctx->cur_resp->ver.major, pctx->cur_resp->ver.minor, pctx->cur_resp->status_code, pctx->cur_resp->status.c_str());
			WAWO_ASSERT(nresp > 0 && nresp < 2048);

			H->write_left((byte_t*)resp_status, nresp);
			WAWO_ASSERT(pctx->ch_client_ctx != NULL);

			http_down(ppctx, H);
			TRACE_HTTP_PROXY("[roger][http][s%u]resp header complete, header:\n%s", pctx->ch_stream_ctx->ch->ch_id(), std::string((char*)H->begin(), H->len()).c_str());
			return wawo::OK;
		}

		int on_body(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_resp != NULL);
			WAWO_ASSERT(pctx->parent != NULL);
			WWRP<proxy_ctx> ppctx = pctx->parent;
			pctx->resp_cur_body_len += len;
			WAWO_ASSERT( pctx->resp_expected_len >0 ? pctx->resp_expected_len>=pctx->resp_cur_body_len: true);
			WWRP<wawo::packet> downp = wawo::make_ref<wawo::packet>(len + 2);
			downp->write((byte_t*)data, len);

			if (pctx->resp_in_chunk_body) {
				char hex_string[16] = { 0 };
				TRACE_CLIENT_SIDE_CTX("[client]write bytes: %u", len);
				int i = int_to_hex_string(len, hex_string, 16);
				downp->write_left((byte_t*)WAWO_HTTP_CRLF, 2);
				downp->write_left((byte_t*)hex_string, i);
				downp->write((byte_t*)WAWO_HTTP_CRLF, 2);
			}

			http_down(ppctx, downp);
			TRACE_HTTP_PROXY("[roger][http][s%u]write body, bytes: %u, total: %u", pctx->ch_stream_ctx->ch->ch_id(), len, pctx->resp_cur_body_len );
			return wawo::OK;
		}

		int on_message_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx != NULL);
			WAWO_ASSERT(pctx->cur_resp != NULL);
			WAWO_ASSERT(pctx->parent != NULL);
			WWRP<proxy_ctx> ppctx = pctx->parent;

			if (pctx->resp_has_chunk_body) {
				WWRP<packet> http_chunk_body_trailing = wawo::make_ref<packet>();
				static const char* chunk_trailing = "0\r\n\r\n";
				http_chunk_body_trailing->write((byte_t*)chunk_trailing, 5);
				http_down(ppctx, http_chunk_body_trailing);
				TRACE_HTTP_PROXY("[roger][http][s%u]resp message complete, finish last chunk flag", pctx->ch_stream_ctx->ch->ch_id());
			}

			WAWO_ASSERT(pctx->reqs.size());
			if (pctx->cur_resp->status_code == 100 ||
				pctx->cur_resp->status_code == 101 ||
				pctx->cur_resp->status_code == 102
				) {
				/*RFC2518*/
				WWRP<wawo::net::http::message> _m = pctx->reqs.front();
				TRACE_HTTP_PROXY("[roger][http][#%u][s%u]ignore pop req: %s, for: %u", pctx->ch_client_ctx->ch->ch_id(), pctx->ch_stream_ctx->ch->ch_id(), _m->url.c_str(), pctx->cur_resp->status_code);
			}
			else {

				WWRP<wawo::net::http::message> _m = pctx->reqs.front();
				if(_m->H->get("connection") == std::string("close")) {
					WAWO_ASSERT(pctx->reqs.size() == 1);

					ppctx->http_proxy_ctx_map.erase(pctx->HP_key);
					//fake a read close
					pctx->client_read_closed = true;
					http_up(pctx, NULL);

					TRACE_HTTP_PROXY("[roger][http][#%u][s%u][%s]erase from ppctx, REACH: reqs.size() == 0 && connection: close", pctx->ch_client_ctx->ch->ch_id(), pctx->ch_stream_ctx->ch->ch_id(), pctx->HP_key.c_str());
				}

				TRACE_HTTP_PROXY("[roger][http][#%u][s%u][%s]pop req: %s", pctx->ch_client_ctx->ch->ch_id(), pctx->ch_stream_ctx->ch->ch_id(), pctx->HP_key.c_str(), _m->url.c_str());
				pctx->reqs.pop();
			}

			if (pctx->resp_header_connection_close == true) {
				WAWO_ASSERT(ppctx->reqs.size() == 0);
			}

			pctx->cur_resp = NULL;
			++pctx->resp_count;

			TRACE_HTTP_PROXY("[roger][http][s%u]resp message complete, body len: %u", pctx->ch_stream_ctx->ch->ch_id(), pctx->resp_cur_body_len);
			return wawo::OK;
		}

		int on_chunk_header(WWRP<parser> const& p) {
			WAWO_ASSERT(p != NULL);
			WWRP<proxy_ctx> http_ctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			http_ctx->resp_in_chunk_body = true;
			http_ctx->resp_has_chunk_body = true;
			return wawo::OK;
		}

		int on_chunk_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p != NULL);
			WWRP<proxy_ctx> http_ctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WWRP<proxy_ctx> ppctx = http_ctx->parent;
			WAWO_ASSERT(http_ctx->resp_in_chunk_body == true);
			WAWO_ASSERT(http_ctx->resp_has_chunk_body == true);
			http_ctx->resp_in_chunk_body = false;
			return wawo::OK;
		}
	}
}