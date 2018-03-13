
#include "../shared/shared.hpp"
#include "client_node.hpp"

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

		int i = 0;
		while (char_stack.size()) {
			WAWO_ASSERT(i < len);
			*(start + i++) = char_stack.top();
			char_stack.pop();
		}

		return i;
	}

	inline WWRP<parser> make_and_init_resp_parser() {
		WWRP<parser> _p = wawo::make_ref<wawo::net::protocol::http::parser>();
		_p->init(PARSER_RESP);

		_p->on_message_begin = http::resp::on_message_begin;
		_p->on_url = http::resp::on_url;
		_p->on_status = http::resp::on_status;
		_p->on_header_field = http::resp::on_header_field;
		_p->on_header_value = http::resp::on_header_value;
		_p->on_headers_complete = http::resp::on_headers_complete;
		_p->on_body = http::resp::on_body;
		_p->on_message_complete = http::resp::on_message_complete;
		_p->on_chunk_header = http::resp::on_chunk_header;
		_p->on_chunk_complete = http::resp::on_chunk_complete;

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
			pctx->cur_req->url = wawo::len_cstr(data, len);

			int parsert = protocol::http::parse_url(pctx->cur_req->url, pctx->cur_req->urlfields, p->opt == O_CONNECT);
			WAWO_RETURN_V_IF_NOT_MATCH(parsert, parsert == wawo::OK);

			//TODO
			//check url:https://tools.ietf.org/html/rfc2616#page-128 to process a empty host string
			//
			//
			//i
			//
			
			if( pctx->cur_req->urlfields.host.len == 0 ){
				WAWO_WARN("opt: %s, data: %s", wawo::net::protocol::http::option_name[pctx->cur_req->opt], data);
			}	

			WAWO_ASSERT(pctx->cur_req->urlfields.host.len > 0);
			return wawo::OK;
		}

		int on_status(WWRP<parser> const& p, const char* data, u32_t const& len) {

			WAWO_ASSERT(!"what");

			(void)p;
			(void)data;
			(void)len;

			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx != NULL);

			return wawo::OK;
		}

		int on_header_field(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_req != NULL);
			pctx->http_field_tmp = wawo::len_cstr(data, len);
			return wawo::OK;
		}

		int on_header_value(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_req != NULL);

			pctx->cur_req->h.set(pctx->http_field_tmp, wawo::len_cstr(data, len));
			pctx->http_field_tmp = "";
			return wawo::OK;
		}

		int on_headers_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WAWO_ASSERT(pctx->cur_req != NULL);

			pctx->cur_req->ver = p->ver;
			pctx->address_type = HOST;
			pctx->dst_domain = pctx->cur_req->urlfields.host;
			pctx->dst_port = pctx->cur_req->urlfields.port;

			WAWO_ASSERT(pctx->dst_domain.len > 0);

			pctx->sub_state = S_ON_HEADERS_COMPLETE;

			if (pctx->type == T_HTTPS) {
				WAWO_ASSERT(pctx->cur_req->opt == wawo::net::protocol::http::O_CONNECT);
				return OK;
			}

			/*RFC7230 , clients are not encouraged to send Proxy-Connection*/
			pctx->cur_req->h.remove("Proxy-Connection");

			if (pctx->cur_req->h.get("Connection") == "close" || 
				pctx->cur_req->h.get("connection") == "close"
			) {
				pctx->cur_req->is_header_contain_connection_close = true;
			}

			char _host_with_port_str[2048] = { 0 };
			snprintf(_host_with_port_str, 2048, "%s:%u", pctx->dst_domain.cstr, pctx->dst_port);

			wawo::len_cstr host_with_port(_host_with_port_str);
			stream_http_conn_map::iterator it = pctx->conn_map.find(host_with_port);

			WWRP<http_conn_ctx> http_ctx;

			if ( it == pctx->conn_map.end() ) {

				int ec = wawo::OK;
				WWRP<stream> _ss = pctx->rclient->_make_stream(pctx, ec);

				if (ec != wawo::OK) {

					WAWO_ASSERT(_ss == NULL);
					WAWO_INFO("[proxy_http]make stream failed for: %s", pctx->cur_req->url.cstr );
					
					pctx->state = PIPE_MAKING_FAILED;
					return ec;
				}
				TRACE_HTTP_PROXY("[proxy_http][#%d:%s]---[s%u]new stream", pctx->client_peer->get_socket()->get_fd(), pctx->client_peer->get_socket()->get_remote_addr().address_info().cstr, _ss->id);

				WWRP<http_conn_ctx> _ctx = wawo::make_ref<http_conn_ctx>();

				_ctx->s = _ss;
				_ctx->host_with_port = host_with_port;
				_ctx->cur_req = pctx->cur_req;
				_ctx->port = pctx->cur_req->urlfields.port;
				_ctx->state = PIPE_PREPARE;
				_ctx->cp = pctx->client_peer;
				_ctx->resp_count = 0;
				_ctx->in_chunk_body = false;

				if ( !wawo::net::is_ipv4_in_dotted_decimal_notation(pctx->dst_domain.cstr)) {
					_ctx->domain = pctx->dst_domain.cstr;
					_ctx->address_type = HOST;
				}
				else {
					wawo::net::ipv4::Ip _ip;
					wawo::net::convert_to_netsequence_ulongip_fromip(pctx->dst_domain.cstr, _ip );
					_ctx->ip = ::ntohl(_ip);
					_ctx->address_type = IPV4;
				}

				_ctx->resp_rb = wawo::make_ref<wawo::bytes_ringbuffer>(roger::http_resp_rb_size);

				_ctx->http_resp_parser = make_and_init_resp_parser();
				WAWO_ASSERT(_ctx->http_resp_parser != NULL);

				_ctx->http_resp_parser->ctx = _ctx;

				WAWO_ALLOC_CHECK(_ctx->resp_rb, roger::http_resp_rb_size);

				pctx->conn_map.insert({ host_with_port, _ctx });
				http_ctx = _ctx;
			}
			else {
				http_ctx = it->second;

				if (http_ctx->s->is_read_write_closed()) {
					http_ctx->s->close();
					http_ctx->http_resp_parser->ctx = NULL;
					http_ctx->http_resp_parser->deinit();

					WAWO_ASSERT(http_ctx->resp_rb->count() == 0);
					WAWO_ASSERT(http_ctx->reqs.size() == 0);

					int ec = wawo::OK;
					WWRP<stream> _ss = pctx->rclient->_make_stream(pctx, ec);

					if (ec != wawo::OK) {
						WAWO_ASSERT(_ss == NULL);
						WAWO_INFO("[proxy_http]make stream failed for: %s", pctx->cur_req->url.cstr );
						pctx->state = PIPE_MAKING_FAILED;
						return ec;
					}

					TRACE_HTTP_PROXY("[proxy_http][#%d:%s]---[s%u]new stream", pctx->client_peer->get_socket()->get_fd(), pctx->client_peer->get_socket()->get_remote_addr().address_info().cstr, _ss->id);

					http_ctx->http_resp_parser = make_and_init_resp_parser();
					WAWO_ASSERT(http_ctx->http_resp_parser != NULL);

					TRACE_HTTP_PROXY("[proxy_http]reset resp ctx, resp_count: %u-> 0, s->id from s%u -> s%u", http_ctx->resp_count, http_ctx->s->id, _ss->id );

					http_ctx->s = _ss;
					http_ctx->http_resp_parser->ctx = http_ctx;
					http_ctx->resp_count = 0;
					http_ctx->resp_rb->reset();
					http_ctx->state = PIPE_PREPARE;
					http_ctx->in_chunk_body = false;
				}
			}

			WAWO_ASSERT(http_ctx != NULL);
			WAWO_ASSERT(http_ctx->s != NULL);

			TRACE_HTTP_PROXY("[roger][s%u]push_back req: %s", http_ctx->s->id, pctx->cur_req->url.cstr );
			http_ctx->reqs.push( pctx->cur_req);
			pctx->cur_http_ctx = http_ctx;

		_http_forward:
			switch (http_ctx->state) {
			case PIPE_PREPARE:
			{
				WAWO_ASSERT(http_ctx->port > 0);
				int connrt;

				if (http_ctx->address_type == HOST) {
					WAWO_ASSERT(http_ctx->domain.len > 0);
					connrt = pctx->rclient->_CMD_connect_server(http_ctx->s, http_ctx->domain, http_ctx->port);
				}
				else {
					WAWO_ASSERT(http_ctx->ip != 0);
					connrt = pctx->rclient->_CMD_connect_server(http_ctx->s, http_ctx->ip, http_ctx->port);
				}

				if (connrt != wawo::OK) {
					http_ctx->state = PIPE_BROKEN;
					roger::cancel_all_ctx_reqs(http_ctx, CANCEL_CODE_PROXY_PIPE_ERROR);

					http_ctx->s->close();
					http_ctx->http_resp_parser->ctx = NULL;
					http_ctx->http_resp_parser->deinit();
					http_ctx->http_resp_parser = NULL;

					pctx->conn_map.erase( host_with_port );

					pctx->client_peer->close(connrt);
					
					TRACE_HTTP_PROXY("[roger][#%u:%s]make stream failed , closert: %d", pctx->client_peer->get_socket()->get_fd(), pctx->client_peer->get_socket()->get_remote_addr().address_info().cstr, connrt);

					return -1;
				}

				http_ctx->state = PIPE_MAKING;
				goto _http_forward;
			}
			break;
			case PIPE_MAKING:
			case HTTP_PARSE:
			{
				char request_line[8192] = {0};
				int nrequest;
				if (pctx->cur_req->urlfields.query.len) {
					nrequest = snprintf(request_line, 8192, "%s %s?%s HTTP/%d.%d\r\n"
						, wawo::net::protocol::http::option_name[pctx->cur_req->opt]
						, pctx->cur_req->urlfields.path.cstr
						, pctx->cur_req->urlfields.query.cstr
						, pctx->cur_req->ver.major
						, pctx->cur_req->ver.minor);
				}
				else {
					nrequest = snprintf(request_line, 8192, "%s %s HTTP/%d.%d\r\n"
						, wawo::net::protocol::http::option_name[pctx->cur_req->opt]
						, pctx->cur_req->urlfields.path.cstr
						, pctx->cur_req->ver.major
						, pctx->cur_req->ver.minor);
				}

				WAWO_ASSERT(nrequest > 0);

				WWSP<packet> opack_header;
				int encrt = pctx->cur_req->h.encode(opack_header);
				WAWO_RETURN_V_IF_NOT_MATCH(encrt, encrt == wawo::OK);

				opack_header->write_left((byte_t*)request_line, nrequest);
				int flushrt = flush_packet_for_http_conn_ctx( http_ctx, opack_header);

				if (flushrt == wawo::E_MUX_STREAM_WRITE_BLOCK) {
					pctx->client_peer->get_socket()->end_async_read();
					return wawo::OK;
				}

				return flushrt;
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
			WAWO_ASSERT(pctx->cur_req != NULL);
			WAWO_ASSERT(pctx->type == T_HTTP);

			WWRP<http_conn_ctx> http_ctx = pctx->cur_http_ctx;
			WAWO_ASSERT(http_ctx != NULL);

			WWSP<packet> opack_body = wawo::make_shared<packet>(len + 64); //64 for chunk

			opack_body->write((byte_t*)data, len);
			WAWO_ASSERT(pctx->cur_http_ctx != NULL);

			if (http_ctx->in_chunk_body) {
				char hex_string[16] = { 0 };
				int i = int_to_hex_string(len, hex_string, 16);

				opack_body->write_left((byte_t*)WAWO_HTTP_CRLF, 2);
				opack_body->write_left((byte_t*)hex_string, i);

				opack_body->write((byte_t*)WAWO_HTTP_CRLF, 2);
			}

			int flushrt = flush_packet_for_http_conn_ctx(pctx->cur_http_ctx, opack_body);
			if (flushrt == wawo::E_MUX_STREAM_WRITE_BLOCK) {
				pctx->client_peer->get_socket()->end_async_read();
				return wawo::OK;
			}

			return flushrt;
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
			WAWO_ASSERT(pctx->cur_http_ctx != NULL);
			WWRP<http_conn_ctx> http_ctx = pctx->cur_http_ctx;

			int flushrt = 0;
			if (http_ctx->in_chunk_body) {
				http_ctx->in_chunk_body = false;
				//forward trailing

				WWSP<packet> chunk_trailing = wawo::make_shared<packet>();

				static const char* chunk_body_trailing = "0\r\n\r\n";
				chunk_trailing->write((byte_t*)chunk_body_trailing, 5);

				flushrt = flush_packet_for_http_conn_ctx(pctx->cur_http_ctx, chunk_trailing);
				if (flushrt == wawo::E_MUX_STREAM_WRITE_BLOCK) {
					pctx->client_peer->get_socket()->end_async_read();
				}
			}

			if (pctx->cur_req->is_header_contain_connection_close == true) {
				pctx->cur_http_ctx->s->close_write();
			}

			pctx->cur_http_ctx = NULL;
			pctx->cur_req = NULL;

			return flushrt;
		}

		int on_chunk_header(WWRP<parser> const& p) {
			//@todo, post chunk
			(void)p;
			WAWO_ASSERT(p != NULL);
			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WWRP<http_conn_ctx> http_ctx = pctx->cur_http_ctx;

			http_ctx->in_chunk_body = true;
			return wawo::OK;
		}

		int on_chunk_complete(WWRP<parser> const& p) {
			(void)p;
			WAWO_ASSERT(p != NULL);
			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(p->ctx);
			WWRP<http_conn_ctx> http_ctx = pctx->cur_http_ctx;

			WAWO_ASSERT( http_ctx->in_chunk_body == true );
			//http_ctx->in_chunk_body = true;
			return wawo::OK;
		}
	}

	namespace resp {

		int on_message_begin(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<http_conn_ctx> ctx = wawo::static_pointer_cast<http_conn_ctx>(p->ctx);

			WAWO_ASSERT(ctx != NULL);
			ctx->cur_resp = wawo::make_shared<protocol::http::message>();
			ctx->cur_resp->type = T_RESP;

			TRACE_HTTP_PROXY("[roger][http][s%u]resp message begin", ctx->s->id );
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
			WWRP<http_conn_ctx> ctx = wawo::static_pointer_cast<http_conn_ctx>(p->ctx);

			ctx->cur_resp->ver = p->ver;
			ctx->cur_resp->status_code = p->status_code;
			ctx->cur_resp->status = wawo::len_cstr(data, len);
			return wawo::OK;
		}

		int on_header_field(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<http_conn_ctx> ctx = wawo::static_pointer_cast<http_conn_ctx>(p->ctx);
			WAWO_ASSERT(ctx->cur_resp != NULL);
			ctx->resp_http_field_tmp = wawo::len_cstr(data, len);
			return wawo::OK;
		}

		int on_header_value(WWRP<parser> const& p, const char* data, u32_t const& len) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<http_conn_ctx> ctx = wawo::static_pointer_cast<http_conn_ctx>(p->ctx);
			WAWO_ASSERT(ctx->cur_resp != NULL);

			u32_t dlen = wawo::strlen(data);
			if (dlen < len) {
				ctx->cur_resp->h.set(ctx->resp_http_field_tmp, wawo::len_cstr(data, dlen));
				WAWO_INFO("[roger][http][s%u]invalid header value len, try to cut len", ctx->s->id);
			}
			else {
				ctx->cur_resp->h.set(ctx->resp_http_field_tmp, wawo::len_cstr(data, len));
			}

			ctx->resp_http_field_tmp = "";
			return wawo::OK;
		}

		int on_headers_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<http_conn_ctx> http_ctx = wawo::static_pointer_cast<http_conn_ctx>(p->ctx);
			WAWO_ASSERT(http_ctx->cur_resp != NULL);

			switch (http_ctx->state) {
			case HTTP_PARSE:
			{
				
				http_ctx->resp_header_connection_close = false; //default is false
				if (http_ctx->cur_resp->h.get("Connection") == "close" ||
					http_ctx->cur_resp->h.get("connection") == "close"
					)
				{
					http_ctx->resp_header_connection_close = true;
				}

				
				/* don't change first resp
				 * for others , keep-alive
				 */

				if ( (http_ctx->resp_count > 1 ) && http_ctx->resp_header_connection_close == true ) {
					http_ctx->cur_resp->h.set("Connection", "keep-alive");
				}

				WWSP<packet> resp_pack;
				int encrt = http_ctx->cur_resp->h.encode(resp_pack);
				WAWO_RETURN_V_IF_NOT_MATCH(encrt, encrt == wawo::OK);

				char resp_status[4096] = {0};

				int nresp = snprintf(resp_status, 4096, "HTTP/%d.%d %u %s\r\n", http_ctx->cur_resp->ver.major, http_ctx->cur_resp->ver.minor, http_ctx->cur_resp->status_code, http_ctx->cur_resp->status.cstr);
				WAWO_ASSERT(nresp > 0);

				resp_pack->write_left((byte_t*)resp_status, nresp);
				WAWO_ASSERT(http_ctx->cp != NULL);

				WWSP<wawo::net::peer::message::cargo> mresp = wawo::make_shared<wawo::net::peer::message::cargo>(resp_pack);
				int sndrt = http_ctx->cp->do_send_message(mresp);
				if (sndrt != wawo::OK) {
					WAWO_WARN("[roger][s%u][%s]receive http resp header, but forward to cp failed, close CP, failed code: %d", http_ctx->s->id, http_ctx->host_with_port.cstr, sndrt );

					cancel_all_ctx_reqs(http_ctx,-1);

					http_ctx->s->close();
					http_ctx->cp->close(sndrt);
					http_ctx->cp = NULL;
					http_ctx->state = CLIENT_CLOSED;

					return sndrt;
				}

				WAWO_ASSERT(sndrt == wawo::OK);
				http_ctx->in_chunk_body = false;

				TRACE_HTTP_PROXY("[roger][http][s%u]resp header complete", http_ctx->s->id);
				return sndrt;
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

			WWRP<http_conn_ctx> http_ctx = wawo::static_pointer_cast<http_conn_ctx>(p->ctx);
			WAWO_ASSERT(http_ctx->cur_resp != NULL);
			WAWO_ASSERT(http_ctx->cp != NULL );

			WWSP<packet> resp_pack = wawo::make_shared<packet>(len);
			
			resp_pack->write((byte_t*)data,len);

			if (http_ctx->in_chunk_body) {
				char hex_string[16] = { 0 };
				int i = int_to_hex_string(len, hex_string, 16);

				resp_pack->write_left((byte_t*)WAWO_HTTP_CRLF, 2);
				resp_pack->write_left((byte_t*)hex_string, i);

				resp_pack->write((byte_t*)WAWO_HTTP_CRLF, 2);
			}

			WWSP<wawo::net::peer::message::cargo> mresp = wawo::make_shared<wawo::net::peer::message::cargo>(resp_pack);
			int sndrt = http_ctx->cp->do_send_message(mresp);
			
			if (sndrt != wawo::OK) {
				WAWO_WARN("[roger][s%u][%s]receive http resp header, but forward to cp failed, close CP, failed code: %d", http_ctx->s->id, http_ctx->host_with_port.cstr, sndrt);
				cancel_all_ctx_reqs(http_ctx,-1);

				http_ctx->s->close();
				http_ctx->cp->close(sndrt);
				http_ctx->cp = NULL;
				http_ctx->state = CLIENT_CLOSED;

				return sndrt;
			}

			TRACE_HTTP_PROXY("[roger][http][s%u]resp body complete", http_ctx->s->id);
			return wawo::OK;
		}

		int on_message_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p->ctx != NULL);

			WWRP<http_conn_ctx> http_ctx = wawo::static_pointer_cast<http_conn_ctx>(p->ctx);
			WAWO_ASSERT(http_ctx->cur_resp != NULL);

			WAWO_ASSERT(http_ctx->reqs.size());
			if (http_ctx->cur_resp->status_code != 100 &&
				http_ctx->cur_resp->status_code != 101 &&
				http_ctx->cur_resp->status_code != 102 /*RFC2518*/
				) {

				WWSP<wawo::net::protocol::http::message> _m = http_ctx->reqs.front();
				TRACE_HTTP_PROXY("[roger][s%u]pop req for message complete: %s", http_ctx->s->id, _m->url.cstr );

				http_ctx->reqs.pop();
			}
			else {
				WWSP<wawo::net::protocol::http::message> _m = http_ctx->reqs.front();
				TRACE_HTTP_PROXY("[roger][s%u]ignore, pop req: %s, for: %u", http_ctx->s->id, _m->url.cstr , http_ctx->cur_resp->status_code );
			}

			http_ctx->cur_resp = NULL;
			++http_ctx->resp_count;

			if (http_ctx->resp_header_connection_close == true ) {
				http_ctx->s->close();
				TRACE_HTTP_PROXY("[roger][s%u]close stream for connection: close", http_ctx->s->id );
				WAWO_ASSERT(http_ctx->reqs.size() == 0);
			}

			TRACE_HTTP_PROXY("[roger][http][s%u]resp message complete", http_ctx->s->id);

			if (!http_ctx->in_chunk_body) {
				return wawo::OK;
			}
			http_ctx->in_chunk_body = false;

			WWSP<packet> resp_pack = wawo::make_shared<packet>();

			static const char* chunk_body_trailing = "0\r\n\r\n";
			resp_pack->write( (byte_t*) chunk_body_trailing,5);

			WWSP<wawo::net::peer::message::cargo> mresp = wawo::make_shared<wawo::net::peer::message::cargo>(resp_pack);
			int sndrt = http_ctx->cp->do_send_message(mresp);

			if (sndrt != wawo::OK) {
				WAWO_WARN("[roger][s%u][%s]receive http resp header, but forward to cp failed, close CP, failed code: %d", http_ctx->s->id, http_ctx->host_with_port.cstr, sndrt);
				cancel_all_ctx_reqs(http_ctx,-1);
				http_ctx->s->close();
				http_ctx->cp->close(sndrt);
				http_ctx->cp = NULL;
				http_ctx->state = CLIENT_CLOSED;

				return sndrt;
			}
			TRACE_HTTP_PROXY("[roger][http][s%u]resp message complete, finish last chunk flag", http_ctx->s->id);

			return wawo::OK;
		}

		int on_chunk_header(WWRP<parser> const& p) {
			WAWO_ASSERT(p != NULL);
			WWRP<http_conn_ctx> http_ctx = wawo::static_pointer_cast<http_conn_ctx>(p->ctx);

			http_ctx->in_chunk_body = true;
			return wawo::OK;
		}

		int on_chunk_complete(WWRP<parser> const& p) {
			WAWO_ASSERT(p != NULL);
			WWRP<http_conn_ctx> http_ctx = wawo::static_pointer_cast<http_conn_ctx>(p->ctx);

			WAWO_ASSERT(http_ctx->in_chunk_body == true);
			//ctx->in_chunk_body = false;

			return wawo::OK;
		}
	}
}}
