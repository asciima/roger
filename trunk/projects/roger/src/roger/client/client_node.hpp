#ifndef ROGER_CLIENT_NODE_HPP
#define ROGER_CLIENT_NODE_HPP


#include <wawo.h>



namespace roger {

		void on_message(WWRP<mux_evt_t> const& evt) {

			shared_lock_guard<shared_mutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				WAWO_ERR("[roger]service exit already ");
				return;
			}

			WWRP<stream> s = evt->message->s;
			WAWO_ASSERT(s != NULL);

			wawo::u16_t stream_message_type = evt->message->type & 0xFFFF;

			WWRP<proxy_ctx> pctx = wawo::static_pointer_cast<proxy_ctx>(evt->message->ctx);
			WAWO_ASSERT(pctx != NULL);
			lock_guard<spin_mutex> lg_ctx(pctx->mutex);

			switch (stream_message_type) {
			case message::T_WRITE_BLOCK:
				{
					if (pctx->type == T_HTTP) {
						stream_http_conn_map::iterator it_http_conn = std::find_if(pctx->conn_map.begin(), pctx->conn_map.end(), [&s](stream_http_conn_pair const& pair_) {
							return pair_.second->s->id == s->id;
						});

						if (it_http_conn == pctx->conn_map.end()) {
							//only client closed should be ok. 
							//cuz, resp with connection: close should be last one
							WAWO_ASSERT(pctx->state == CLIENT_CLOSED);
							s->close();

							WAWO_WARN("[roger][http][s%u]stream unblock, but no ctx found", s->id );
							return;
						}
					} else {
						pctx->stream_write_flag |= STREAM_WRITE_BLOCK;
					}
				}
				break;
			case message::T_WRITE_UNBLOCK:
				{
					if (pctx->type == T_HTTP) {
						stream_http_conn_map::iterator it_http_conn = std::find_if(pctx->conn_map.begin(), pctx->conn_map.end(), [&s](stream_http_conn_pair const& pair_) {
							return pair_.second->s->id == s->id;
						});

						if (it_http_conn == pctx->conn_map.end()) {
							//only client closed should be ok. 
							//cuz, resp with connection: close should be last one
							WAWO_ASSERT(pctx->state == CLIENT_CLOSED);
							s->close();

							WAWO_WARN("[roger][http][s%u]stream unblock, but no ctx found", s->id);
							return;
						}

						WWRP<http_conn_ctx> http_ctx = it_http_conn->second;
						WAWO_ASSERT(http_ctx->req_up_packets.size() > 0);

						while ( http_ctx->req_up_packets.size() ) {
							WWSP<packet>& outp = http_ctx->req_up_packets.front();
							int sndrt = http_ctx->s->write(outp);
							if (sndrt != wawo::OK ) {
								break;
							}
							http_ctx->req_up_packets.pop();
						}

						if (http_ctx->req_up_packets.size() == 0) {
							pctx->client_peer->get_socket()->begin_async_read();
						}
					}
					else {

						if (pctx->state == CLIENT_CLOSED) {
							return;
						}

						WAWO_ASSERT(pctx->state == PIPE_MAKING || pctx->state == PIPE_CONNECTED);
						WAWO_ASSERT(pctx->protocol_packet->len() == 0);
						WAWO_ASSERT(pctx->s != NULL);

						while (pctx->client_up_packets.size()) {
							WWSP<packet>& outp = pctx->client_up_packets.front();

							int sndrt = pctx->s->write(outp);
							if (sndrt != wawo::OK) {
								break;
							}
							pctx->client_up_packets.pop();
						}

						if (pctx->client_up_packets.size() == 0) {
							WAWO_WARN("[roger][#%u:%s][s%u]stream write unblock,begin async read", pctx->client_peer->get_socket()->get_fd(), pctx->client_peer->get_socket()->get_addr_info().cstr, pctx->s->id);

							pctx->stream_write_flag &= ~STREAM_WRITE_BLOCK;
							pctx->client_peer->get_socket()->begin_async_read();
						}
					}
				}
				break;
			case message::T_DATA:
			{
				WWSP<packet> inpack;
				u32_t rcount = s->read(inpack);

				if (rcount == 0) return;

				bool close_client_after_flush = false;

				proxy_state state = pctx->state;
				WWRP<http_conn_ctx> http_ctx;

				if (pctx->type == T_HTTP) {
					stream_http_conn_map::iterator it_http_conn = std::find_if(pctx->conn_map.begin(), pctx->conn_map.end(), [&s]( stream_http_conn_pair const& pair_) {
						return pair_.second->s->id == s->id;
					});

					if (it_http_conn == pctx->conn_map.end()) {
						//only client closed should be ok. 
						//cuz, resp with connection: close should be last one
						WAWO_ASSERT(pctx->state == CLIENT_CLOSED );
						s->close();

						WAWO_WARN("[roger][http][s%u]new packet arrive, but no ctx found, len: %u", s->id, inpack->len());
						return;
					}

					http_ctx = it_http_conn->second;
					state = it_http_conn->second->state;
				}

				switch (state) {
				case _RESP_BLIND_FORWARD:
				{
					
				__RESP_BLIND_FORWARD:
					{
						//WAWO_ASSERT(ctx->type != T_HTTP);
						WAWO_ASSERT(inpack->len());
						WAWO_ASSERT(pctx->client_peer != NULL);
						WWSP<message::cargo> bp_packet = wawo::make_shared<message::cargo>(inpack);
						int rt = pctx->client_peer->do_send_message(bp_packet);

						//if (rt == wawo::E_CHANNEL_WRITE_BLOCK) {
						//	WAWO_ASSERT(pctx->client_down_packet->len() == 0);
						//	pctx->client_down_packet = inpack;
						//}

						if (rt != wawo::OK) {
							WAWO_WARN("[roger][s%u]receive C_CONTENT, but forward to cp failed, close CP, failed code: %d", evt->message->s->id, rt);
							pctx->client_peer->close(rt);
						}

						if (close_client_after_flush) {
							WAWO_WARN("[roger][s%u]connect to target host failed: close cp", evt->message->s->id);
							pctx->client_peer->close();
						}
					}
				}
				break;
				case PIPE_MAKING:
				{
					WAWO_ASSERT(inpack != NULL);
					WAWO_ASSERT(inpack->len() >= 1);

					u8_t connect_ok_or_not = inpack->read<u8_t>();

					switch (pctx->type) {
					case T_SOCKS5:
					{
						pctx->state = connect_ok_or_not == 0 ? PIPE_CONNECTED : PIPE_CONNECT_HOST_FAILED;
						socks5_response_code code = connect_ok_or_not == 0 ? S5_SUCCEEDED : S5_GENERAL_SOCKS_SERVER_FAILURE;

						inpack->write_left<u16_t>(0);
						inpack->write_left<u32_t>(0);
						inpack->write_left<u8_t>(ADDR_IPV4);
						inpack->write_left<u8_t>(0);
						inpack->write_left<u8_t>(code & 0xFF);
						inpack->write_left<u8_t>(5);
					}
					break;
					case T_SOCKS4:
					{
						pctx->state = connect_ok_or_not == 0 ? PIPE_CONNECTED : PIPE_CONNECT_HOST_FAILED;
						socks4_response_code code = connect_ok_or_not == 0 ? S4_REQUEST_GRANTED : S4_REQUEST_REJECTED_FOR_FAILED;
						inpack->write_left<u32_t>(0);
						inpack->write_left<u16_t>(0);
						inpack->write_left<u8_t>(code & 0xFF);
						inpack->write_left<u8_t>(0);
					}
					break;
					case T_HTTP:
					{
						WAWO_ASSERT(http_ctx != NULL);
						http_ctx->state = connect_ok_or_not == 0 ? HTTP_PARSE : PIPE_CONNECT_HOST_FAILED;

						if (connect_ok_or_not != wawo::OK) {
							WAWO_ASSERT(inpack->len() == 0);
							//inpack->write_left((byte_t*)HTTP_RESP_RELAY_FAILED, wawo::strlen(HTTP_RESP_RELAY_FAILED));
							//close_client_after_flush = true;
							WAWO_ASSERT(http_ctx->reqs.size() != 0);

							WWSP<wawo::net::protocol::http::message>& m = http_ctx->reqs.front();
							WAWO_WARN("[roger][https]connect to url: %s failed for: %d, cancel reqs: %u", m->url.cstr, connect_ok_or_not, http_ctx->reqs.size() );

							cancel_all_ctx_reqs(http_ctx, CANCEL_CODE_CONNECT_HOST_FAILED );
						} else {
							if (inpack->len()) {
								goto _HTTP_RESP_PARSE;
							}
						}
					}
					break;
					case T_HTTPS:
					{
						pctx->state = connect_ok_or_not == 0 ? PIPE_CONNECTED : PIPE_CONNECT_HOST_FAILED;

						//WAWO_ASSERT(ctx->http_req_message->opt == wawo::net::protocol::http::O_CONNECT);
						if (connect_ok_or_not == wawo::OK) {
							inpack->write_left((byte_t*)HTTP_RESP_RELAY_SUCCEED, wawo::strlen(HTTP_RESP_RELAY_SUCCEED));
						}
						else {
 							WAWO_WARN("[roger][https]connect to url: %s failed for: %d", pctx->cur_req->url.cstr, connect_ok_or_not);
							inpack->write_left((byte_t*)HTTP_RESP_CONNECT_HOST_FAILED, wawo::strlen(HTTP_RESP_CONNECT_HOST_FAILED));
							close_client_after_flush = true;
						}
					}
					break;
					}

					if (inpack->len()) {
						goto __RESP_BLIND_FORWARD;
					}
				}
				break;
				case PIPE_CONNECTED:
				{
					goto __RESP_BLIND_FORWARD;
				}
				break;
				case HTTP_PARSE:
				{

_HTTP_RESP_PARSE:
					WAWO_ASSERT(inpack->len());

					WAWO_ASSERT(http_ctx->http_resp_parser != NULL);
					WAWO_ASSERT(inpack->len() <= http_ctx->resp_rb->left_capacity());

					http_ctx->resp_rb->write(inpack->begin(), inpack->len());
					//WAWO_INFO("[roger][s%u]write bytes: %u", s->id, inpack->len() );

					int ec = 0;
					while (http_ctx->resp_rb->count()) {
						//memset(_tmp, 'd', 20480);

//#define DEBUG_302
#ifdef DEBUG_302

						byte_t _tmp[20480] = { 0 };

						const char* str_302 = "\
HTTP/1.1 302 Found\r\n\
Date: Mon, 30 Oct 2017 05:31:09 GMT\r\n\
Pragma: no-cache\r\n\
Expires: Fri, 01 Jan 1990 00:00:00 GMT\r\n\
Cache-Control: no-cache, must-revalidate\r\n\
Location: http://r3---sn-2x3eln7z.gvt1.com/edgedl/release2/chrome_component/AOE-CSwmdX-z_4/4_all_sslErrorAssistant.crx3?cms_redirect=yes&expire=1509355869&ip=119.4.142.27&ipbits=0&mm=28&mn=sn-2x3eln7z&ms=nvh&mt=1509341361&mv=m&pl=14&shardbypass=yes&sparams=expire,ip,ipbits,mm,mn,ms,mv,pl,shardbypass&signature=0395EAFBBC84C705617D676F94B2C564629CADD4.83B92F33D10E78A5757D42C20A896223D87FCE30&key=cms1\r\n\
Content-Type: text/html; charset=UTF-8\r\n\
Server: ClientMapServer\r\n\
Content-Length: 640\r\n\
X-XSS-Protection: 1; mode=block\r\n\
X-Frame-Options: SAMEORIGIN\r\n\
\r\n\
<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\
<TITLE>302 Moved</TITLE></HEAD><BODY>\
<H1>302 Moved</H1>\
The document has moved\
<A HREF=\"http://r3---sn-2x3eln7z.gvt1.com/edgedl/release2/chrome_component/AOE-CSwmdX-z_4/4_all_sslErrorAssistant.crx3?cms_redirect=yes&amp;expire=1509355869&amp;ip=119.4.142.27&amp;ipbits=0&amp;mm=28&amp;mn=sn-2x3eln7z&amp;ms=nvh&amp;mt=1509341361&amp;mv=m&amp;pl=14&amp;shardbypass=yes&amp;sparams=expire,ip,ipbits,mm,mn,ms,mv,pl,shardbypass&amp;signature=0395EAFBBC84C705617D676F94B2C564629CADD4.83B92F33D10E78A5757D42C20A896223D87FCE30&amp;key=cms1\">here</A>.\
</BODY></HTML>\
";
						u32_t npeek = wawo::strlen(str_302);
						memcpy(_tmp, str_302, npeek);
#else

						//if (http_ctx->resp_count >= 1) {
						//	WAWO_INFO("HIT respcount>= 1");
						//}
						byte_t _tmp[20480] = { 0 };
						u32_t npeek = http_ctx->resp_rb->peek(_tmp, 20480);
#endif




						u32_t nparsed = http_ctx->http_resp_parser->parse((char*)_tmp, npeek, ec);
						WAWO_ASSERT(nparsed >= 0);
						http_ctx->resp_rb->skip(nparsed);

						if ( ec != wawo::OK ) {

							http_ctx->state = HTTP_PARSE_ERROR;
							http_ctx->resp_rb->reset();
							//message_queue().swap(http_ctx->reqs);

							message_queue empty_q;
							std::swap( empty_q, http_ctx->reqs ) ;


							//WAWO_ASSERT(http_ctx->state != HTTP_PARSE);
							/*
							 * @TODO, for HEP_INVALID_CONSTANT ISSUE, need investigate
							 *
							 */
							s->close();
							WAWO_WARN("[roger][s%u]mux resp, parse failed: %u, close stream", s->id, ec);
							break;
						}

						TRACE_HTTP_PROXY("[roger][s%u]parsed bytes: %u", s->id, nparsed);
					}
				}
				break;
				case CLIENT_CLOSED:
				{
					s->close();
					WAWO_WARN("[roger][s%u]client closed, new packet arrive, len: %u", s->id, inpack->len());
				}
				break;
				case HTTP_PARSE_ERROR:
				{
					s->close();
				}
				break;
				default:
				{
					WAWO_ASSERT(!"WHAT");
				}
				break;
				}
			}
			break;
			case message::T_FIN:
			{
				WAWO_ASSERT(pctx->client_peer != NULL);
				WAWO_DEBUG("[roger][http][s%u][#%d:%s]stream T_FIN arrive", s->id, evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr);

				if (pctx->type == T_HTTP) {
					WAWO_ASSERT(s != NULL);
					s->close();

					stream_http_conn_map::iterator it_http_ctx = std::find_if(pctx->conn_map.begin(), pctx->conn_map.end(), [&s](stream_http_conn_pair const& pair_) {
						return pair_.second->s->id == s->id;
					});

					if (it_http_ctx == pctx->conn_map.end()) {

						/**
						 *
						 * stream switch
						 * or
						 * client close
						*/

						//WAWO_ASSERT(ctx->state == CLIENT_CLOSED);
						s->close();

						WAWO_DEBUG("[roger][http][s%u][#%d:%s]stream T_FIN arrive, but no ctx found", s->id, evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr);
						return;
					}

					WAWO_ASSERT(it_http_ctx != pctx->conn_map.end());
					WAWO_ASSERT(it_http_ctx->second->s != NULL);
					//WAWO_ASSERT(it_http_conn->second->reqs.size() == 0);

					if (it_http_ctx->second->reqs.size()) {
						//@todo, resp connection failed to browser
						WAWO_DEBUG("[roger][http][s%u][#%d:%s]stream T_FIN arrive, cancel reqs: %u", s->id, evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr, it_http_ctx->second->reqs.size());
						roger::cancel_all_ctx_reqs(it_http_ctx->second, CANCEL_CODE_SERVER_NO_RESPONSE);
						it_http_ctx->second->s->close();
						it_http_ctx->second->cp = NULL;
						it_http_ctx->second->http_resp_parser->ctx = NULL;
						it_http_ctx->second->http_resp_parser->deinit();
					}

					//check ctx.conn_map
					bool is_there_req_wait_resp = false;
					stream_http_conn_map::iterator _it = pctx->conn_map.begin();
					WAWO_ASSERT(_it != pctx->conn_map.end());
					while (_it != pctx->conn_map.end()) {
						if (_it->second->reqs.size()) {
							is_there_req_wait_resp = true;
							break;
						}

						++_it;
					}

					if ((!is_there_req_wait_resp) && pctx->client_peer->get_socket()->is_read_shutdowned()) {
						pctx->client_peer->shutdown(wawo::net::SHUTDOWN_WR);
						WAWO_DEBUG("[roger][http][#%u:%s][s%u]stream T_FIN arrive and no stream connected,cp shutdown wr", pctx->client_peer->get_socket()->get_fd(), pctx->client_peer->get_socket()->get_remote_addr().address_info().cstr, s->id);
					} else {
						WAWO_DEBUG("[roger][http][s%u][#%d:%s]stream T_FIN arrive, has http reqs in queue or cp !read_shutdowned(), no shutdown_wr", s->id, evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr);
					}
				}
				else {
					pctx->client_peer->shutdown(SHUTDOWN_WR);
				}
			}
			break;
			case message::T_ACCEPTED:
			{
				WAWO_ASSERT(!"what");
			}
			break;
			case message::T_CLOSED:
			{
				WAWO_ASSERT(pctx->client_peer != NULL);

				if (pctx->type == T_HTTP) {
				
					WAWO_ASSERT(s != NULL);

					stream_http_conn_map::iterator it_http_ctx = std::find_if(pctx->conn_map.begin(), pctx->conn_map.end(), [&s](stream_http_conn_pair const& pair_) {
						return pair_.second->s->id == s->id;
					});

					if (it_http_ctx == pctx->conn_map.end()) {
						return;
					}

					WAWO_ASSERT(it_http_ctx->second->s != NULL);
					WAWO_ASSERT(it_http_ctx->second->s == s);

					it_http_ctx->second->s = NULL;
					it_http_ctx->second->cp = NULL;
					it_http_ctx->second->http_resp_parser->ctx = NULL;
					it_http_ctx->second->http_resp_parser->deinit();
					it_http_ctx->second->http_resp_parser = NULL;

					pctx->conn_map.erase(it_http_ctx);

					if (pctx->conn_map.size() == 0) {
						pctx->client_peer->close();
					}
				}
				else {
					pctx->client_peer->close();
				}
			}
			break;
			}
		}

		void on_close(WWRP<mux_evt_t> const& evt) {
			shared_lock_guard<shared_mutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				WAWO_ERR("[roger]service exit already ");
				return;
			}

			{
				WAWO_WARN("[roger]rp closed: %d", evt->info.int32_v);
				lock_guard<shared_mutex> lg_eps(m_mux_peers_mutex);
				std::vector< WWRP<mux_peer_t> >::iterator it = std::find(m_mux_peers.begin(), m_mux_peers.end(), evt->peer);
				WAWO_ASSERT(it != m_mux_peers.end());
				m_mux_peers.erase(it);
			}

			int connrt = async_connect_roger_server();
			WAWO_ASSERT(connrt == wawo::OK);
		}

		void on_mux_connect_success(WWRP<mux_peer_t> const& peer, WWRP<wawo::net::socket> const& so, WWRP<ref_base> const& cookie) {
			shared_lock_guard<shared_mutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				so->close(wawo::E_SOCKET_FORCE_CLOSE);
				return;
			}

			wawo::u8_t tos = IPTOS_LOWDELAY | IPTOS_THROUGHPUT;
			int settosrt = so->set_tos(tos);
			if (settosrt != wawo::OK)
			{
				so->close();
				int connrt = async_connect_roger_server();;
				WAWO_ASSERT(connrt == wawo::OK);
				return;
			}

			lock_guard<shared_mutex> lg_eps(m_mux_peers_mutex);
			m_mux_peers.push_back(peer);
			WAWO_INFO("[roger][#%u:%s] local info: %s, service ready !!!", so->get_fd(), so->get_addr_info().cstr, so->get_local_addr().address_info().cstr);

			(void)cookie;
		}

		void on_mux_connect_error(int const& code, WWRP<ref_base> const& cookie) {
			shared_lock_guard<shared_mutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				return;
			}

			wawo::this_thread::sleep(100);
			int connrt = async_connect_roger_server();
			WAWO_ASSERT(connrt == wawo::OK);
			WAWO_INFO("[roger]connect server failed: %d, reconnect !!!", code);

			(void)cookie;
		}

		void on_accepted(WWRP<client_peer_t> const& peer, WWRP<wawo::net::socket> const& so ) {

			WAWO_ASSERT(peer != NULL);

			shared_lock_guard<shared_mutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				client_node_t::unwatch_peer_all_event(peer);
				peer->close(-1111);
				WAWO_ERR("[roger]service exit already ");
				return;
			}
			so->turnon_nodelay();

			WAWO_ASSERT(peer != NULL);
			WWRP<proxy_ctx> ctx = wawo::make_ref<proxy_ctx>();
			
			ctx->state = WAIT_FIRST_PACK;
			ctx->sub_state = http_req_sub_state::S_IDLE;
			ctx->client_peer = peer;
			ctx->protocol_packet = wawo::make_shared<wawo::packet>(10240);
			ctx->type = T_NONE;
			ctx->rclient = WWRP<roger_client>(this);
			ctx->memory_tag = wawo::make_ref<wawo::bytes_ringbuffer>(3888);

			peer->set_ctx(ctx);

			WAWO_INFO("[roger][#%u:%s]client accepted, local addr: %s", so->get_fd(), so->get_remote_addr().address_info().cstr, so->get_local_addr().address_info().cstr );
		}

		enum protocol_parse_error {
			E_WAIT_BYTES_ARRIVE			= 1,
			E_OK						= 0,
			E_NOT_SOCKS4_PROTOCOL		= -1,
			E_UNSUPPORTED_SOCKS4_CMD	= -2,
			E_INVALID_DST_IP			= -3,
			E_CLIENT_SOCKET_ERROR		= -4,
			E_SOCKS5_UNKNOWN_ATYPE		= -5,
			E_SOCKS5_MISSING_IP_OR_PORT = -6,
			E_SOCKS5_INVALID_DOMAIN		= -7,
			E_UNKNOWN_HTTP_METHOD		= -8
		};

		void on_message(WWRP<cp_evt_t> const& evt) {
			shared_lock_guard<shared_mutex> lg_state(m_mutex);
			if (m_state != S_RUN) {
				evt->peer->close(-1112);
				WAWO_ERR("[roger]service exit already ");
				return;
			}

			//WAWO_INFO("[roger][http][#%d:%s]cp bytes", evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr );

			const char* tmp = "CONNECT youtubei.googleapis.com:443 HTTP/1.1\r\n\
				Host: settings.crashlytics.com\r\n\
				Proxy-Connection : Keep-Alive\r\n\
				User-Agent : Crashlytics Android SDK/1.3.17.dev\r\n\
				\r\n\
				zie_uds, hardware = qcom, product = kinzie_retla_ds, platformVersionRelease = 7.0, model = XT1580, buildId = NPK25.200 - 12, isWideScreen = 0, supportedAbis = arm64 - v8a; armeabi - v7a; armeabi) (kinzie_uds NPK25.200 - 12); gzip\r\n\
				Host : www.googleapis.com\r\n\
				\r\n\
				-8831771699398612&output=html&h=250&slotname=1113910027&adk=2435220640&adf=1480696129&w=300&lmt=1512823094&url=http%3A%2F%2Ftech.sina.com.cn%2Fd%2F2017-11-21%2Fdoc-ifynwnty5994892.shtml&ea=0&flash=0&wgl=1&dt=1512823093868&bpp=22&bdt=438&fdt=26&idt=344&shv=r20171129&cbv=r20170110&saldr=sa&correlator=189302667698&frm=23&ga_vid=328561932.1509257218&ga_sid=1512823094&ga_hid=1180444312&ga_fc=1&pv=2&iag=15&icsg=2&nhd=2&dssz=2&mdo=0&mso=0&u_tz=480&u_his=1&u_java=0&u_h=1080&u_w=1920&u_ah=1040&u_aw=1920&u_cd=24&u_nplug=4&u_nmime=5&adx=1262&ady=6646&biw=1903&bih=949&isw=300&ish=250&ifk=2040432178&eid=21061122%2C191880502&oid=3&nmo=1&ref=https%3A%2F%2Fcn.bing.com%2F&rx=0&eae=2&fc=528&brdim=0%2C0%2C0%2C0%2C1920%2C0%2C1920%2C1040%2C300%2C250&vis=1&rsz=do%7Cd%7CoeEbr%7Cn&abl=XS&ppjl=u&pfx=0&fu=12&bc=1&ifi=1&dtd=391\r\n\
				Accept-Encoding : gzip, deflate\r\n\
				Accept-Language : en - US, en; q = 0.9\r\n";


			

			WAWO_ASSERT(evt->message != NULL);
			WWSP<packet> inpack = evt->message->data;
			//WWSP<packet> inpack = wawo::make_shared<packet>();
			//inpack->write((byte_t*)tmp, wawo::strlen(tmp));

			WWRP<proxy_ctx> ctx = evt->peer->get_ctx<proxy_ctx>();
			WAWO_ASSERT(ctx != NULL);
			WAWO_ASSERT(ctx->client_peer == evt->peer);
			lock_guard<spin_mutex> lg_ctx(ctx->mutex);

			bool has_write_to_protocol_packet_already = false;
			bool should_setup_read = true;
	_check_again:
			switch (ctx->state) {
				case _REQ_BLIND_FORWARD:
					{
				__REQ_BLIND_FORWARD:
						WAWO_ASSERT(ctx->protocol_packet->len() == 0);

						if (ctx->stream_write_flag&STREAM_WRITE_BLOCK) {
							WAWO_WARN("[roger][#%u:%s][s%u]stream state write block, stop async read", evt->so->get_fd(), evt->so->get_addr_info().cstr, ctx->s->id);
							ctx->client_up_packets.push(inpack);
							should_setup_read = false;
							goto __end_check;
						}

						WAWO_ASSERT( ctx->client_up_packets.size() == 0 );
						WAWO_ASSERT(ctx->s != NULL);
						int sndrt = ctx->s->write(inpack);

						if (sndrt == wawo::OK) {
							goto __end_check;
						}

						WAWO_RETURN_IF_MATCH(sndrt == wawo::OK);

						if (sndrt == wawo::E_MUX_STREAM_WRITE_BLOCK) {
							WAWO_WARN("[roger][#%u:%s][s%u]stream write block, stop async read", evt->so->get_fd(), evt->so->get_addr_info().cstr, ctx->s->id);
							should_setup_read = false;
							ctx->stream_write_flag |= STREAM_WRITE_BLOCK;
							ctx->client_up_packets.push(inpack);
							goto __end_check;
						}

						WAWO_WARN("[roger][#%u:%s][s%u]stream send failed: %d, shutdown cp rd", evt->so->get_fd(), evt->so->get_addr_info().cstr, ctx->s->id, sndrt);
						evt->so->shutdown(SHUTDOWN_RD, sndrt);
						goto __end_check;
				}
				break;
				case WAIT_FIRST_PACK:
					{
						//refer to https://www.ietf.org/rfc/rfc1928.txt
						ctx->protocol_packet->write(inpack->begin(), inpack->len());
						has_write_to_protocol_packet_already = true;

						if (ctx->protocol_packet->len() < 3) {
							goto __end_check;
						}

						wawo::byte_t v_and_nmethods[2];
						ctx->protocol_packet->peek(v_and_nmethods,2);

						if (v_and_nmethods[0] == 0x05) {
							//socks5
							ctx->type = T_SOCKS5;
							ctx->state = SOCKS5_CHECK_AUTH;
						} else if (v_and_nmethods[0] == 0x04) {
							ctx->type = T_SOCKS4;
							ctx->state = SOCKS4_PARSE;
						} else {
							//try http
							//ctx->type = T_HTTP;

							int detect_rt = _detect_http_proxy(ctx);
							if (detect_rt > 0) {
								goto __end_check;
							}
							else if( detect_rt < 0) {
								WAWO_ERR("[client][#%u:%s]unknown proxy type", evt->so->get_fd(), evt->so->get_addr_info().cstr);
								evt->peer->close();
								goto __end_check;
							}
							else {
								//WAWO_INFO("[roger][http][#%d:%s]detected http type: %u", evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr, ctx->type );

								ctx->state = HTTP_PARSE;
								ctx->req_parser = wawo::make_ref<wawo::net::protocol::http::parser>();

								ctx->req_parser->init(wawo::net::protocol::http::PARSER_REQ);
								ctx->req_parser->ctx = ctx;

								ctx->req_parser->on_message_begin = http::req::on_message_begin;
								ctx->req_parser->on_url = http::req::on_url;

								ctx->req_parser->on_status = http::req::on_status;
								ctx->req_parser->on_header_field = http::req::on_header_field;
								ctx->req_parser->on_header_value = http::req::on_header_value;
								ctx->req_parser->on_headers_complete = http::req::on_headers_complete;

								ctx->req_parser->on_body = http::req::on_body;
								ctx->req_parser->on_message_complete = http::req::on_message_complete;

								ctx->req_parser->on_chunk_header = http::req::on_chunk_header;
								ctx->req_parser->on_chunk_complete = http::req::on_chunk_complete;
							}
						}

						if (ctx->protocol_packet->len()) {
							goto _check_again;
						}
					}
					break;
				case SOCKS5_CHECK_AUTH:
					{
						if (has_write_to_protocol_packet_already == false) {
							ctx->protocol_packet->write(inpack->begin(), inpack->len());
							has_write_to_protocol_packet_already = true;
						}

						int check_rt = _socks5_check_auth(ctx, evt);
						if ( check_rt == E_OK && ctx->protocol_packet->len()) {
							goto _check_again;
						}
					}
					break;
				case SOCKS5_CHECK_CMD:
					{
						if (has_write_to_protocol_packet_already == false) {
							ctx->protocol_packet->write(inpack->begin(), inpack->len());
							has_write_to_protocol_packet_already = true;
						}

						int check_rt = _socks5_check_cmd(ctx, evt);
						if (check_rt == E_OK ) {
							goto _check_again;
						}
					}
					break;//end for SOCKS5_AUTH_DONE
				case SOCKS4_PARSE:
					{
						if (has_write_to_protocol_packet_already == false) {
							ctx->protocol_packet->write(inpack->begin(), inpack->len());
							has_write_to_protocol_packet_already = true;
						}

						//socks4
						int parse_rt = _socks4_parse(ctx, evt);

						if (parse_rt > E_OK) {
							goto __end_check;
						}

						else if (parse_rt == E_OK) {
							ctx->state = PIPE_PREPARE;
							goto _check_again;
						}
						else {
							WAWO_ASSERT(parse_rt == E_WAIT_BYTES_ARRIVE);
							//continue

							evt->so->close(parse_rt);
							WAWO_WARN("[roger]parse socks4 protocol failed: %d, close client", parse_rt);
						}
					}
					break;
				case PIPE_PREPARE:
					{

						if (ctx->address_type == HOST && is_ipv4_in_dotted_decimal_notation(ctx->dst_domain.cstr)) {
							wawo::net::ipv4::Ip _ip;
							int crt = wawo::net::convert_to_netsequence_ulongip_fromip(ctx->dst_domain.cstr, _ip);

							if (crt != wawo::OK) {
								WAWO_WARN("[client][http_proxy][#%u:%s]invalid ipaddr, close cp", evt->so->get_fd(), evt->so->get_addr_info().cstr);

								ctx->state = PIPE_MAKING_FAILED;
								goto __end_check;
							}

							ctx->address_type = IPV4;
							ctx->dst_ipv4 = ::ntohl(_ip);
							ctx->dst_domain = "";
						}

						int ec = wawo::OK;
						WWRP<stream> ss = _make_stream(ctx, ec);

						if (ec != wawo::OK) {
							evt->so->close(ec);
							WAWO_WARN("[client][#%u:%s]make stream failed:%d", evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr, ctx->dst_port);

							if (ss != NULL) {
								ss->close();
							}

							ctx->state = PIPE_MAKING_FAILED;
							goto __end_check;
						}

						WAWO_ASSERT(ss != NULL);
						ctx->s = ss;
						int connrt;
						if ( ctx->address_type == IPV4 ) {

							WAWO_ASSERT(ctx->dst_ipv4 != 0);
							WAWO_ASSERT(ctx->dst_domain.len == 0);
							connrt = _CMD_connect_server(ss, ctx->dst_ipv4, ctx->dst_port);

							if (connrt != wawo::OK) {
								evt->so->close(connrt);
								WAWO_WARN("[client][#%u:%s]send connect server failed:%d, target addr: %s:%u"
									,evt->so->get_fd(), evt->so->get_addr_info().cstr, ctx->dst_port, ::ntohl(ctx->dst_ipv4), ctx->dst_port );

								ctx->state = PIPE_CONNECT_HOST_FAILED;
								ss->close();
								goto __end_check;
							}

							ctx->state = PIPE_MAKING;
						} else {
							WAWO_ASSERT(ctx->address_type == HOST);
							WAWO_ASSERT(ctx->dst_ipv4 == 0);
							WAWO_ASSERT(ctx->dst_domain.len != 0);
							connrt = _CMD_connect_server(ss, ctx->dst_domain, ctx->dst_port);

							if (connrt != wawo::OK) {
								evt->so->close(connrt);
								WAWO_WARN("[client][#%u:%s]send connect server failed:%d, target addr: %s:%u"
									, evt->so->get_fd(), evt->so->get_addr_info().cstr, ctx->dst_port, ctx->dst_domain.cstr, ctx->dst_port);

								ctx->state = PIPE_BROKEN;
								ss->close();
								goto __end_check;
							}

							ctx->state = PIPE_MAKING;
							WAWO_ASSERT(ctx->protocol_packet->len() == 0);
						}
					}
					break;
				case PIPE_MAKING:
				case PIPE_CONNECTED:
					{
						goto __REQ_BLIND_FORWARD;
					}
					break;
				case HTTP_PARSE:
					{
					
						if (has_write_to_protocol_packet_already == false) {
							ctx->protocol_packet->write(inpack->begin(), inpack->len());
							has_write_to_protocol_packet_already = true;
						}

						WAWO_ASSERT(ctx->req_parser != NULL);
						int ec = wawo::OK;
						while (ctx->protocol_packet->len() && ctx->state == HTTP_PARSE) {
							byte_t _tmp[20480] = { 0 };

							u32_t npeek = ctx->protocol_packet->peek(_tmp, 20480);
							u32_t nparsed = ctx->req_parser->parse((char*)_tmp, npeek, ec);
							ctx->protocol_packet->skip(nparsed);

							bool is_parse_error = (ctx->type == T_HTTPS && ctx->state == PIPE_PREPARE) ? ec != 7 : ec != wawo::OK;
							if (is_parse_error) {

								//WAWO_ASSERT(ctx->state != HTTP_PARSE);
								ctx->client_peer->close(ec);
								ctx->state = HTTP_PARSE_ERROR;

								ctx->req_parser->ctx = NULL;
								ctx->req_parser->deinit();
								ctx->req_parser = NULL;

								ctx->cur_http_ctx = NULL;

								WAWO_WARN("[roger][#%u:%s][%u]http request parsed failed: %d, shutdown cp rd", evt->so->get_fd(), evt->so->get_addr_info().cstr, ec);
								goto __end_check;
							}
						}//end for __HTTP_PARSE tag

						 //flush all left to remote server
						if ( ctx->type == T_HTTPS && ctx->sub_state == S_ON_MESSAGE_COMPLETE ) {

							WAWO_ASSERT(ctx->state == PIPE_PREPARE);

							WAWO_ASSERT(ctx->cur_req->opt == wawo::net::protocol::http::O_CONNECT);
							WWSP<packet> opack = wawo::make_shared<packet>( *(ctx->protocol_packet) );
							ctx->protocol_packet->reset();

							inpack = opack;
							goto _check_again;
						}

					}//end for HTTP_PARSER state
					break;
				case PIPE_MAKING_FAILED:
				case PIPE_BROKEN:
				case HTTP_PARSE_ERROR:
				case PIPE_CONNECT_HOST_FAILED:
					{
					}
					break;
				default:
					{
						WAWO_THROW("WHAT")
					}
					break;
			}

		__end_check:
			if (should_setup_read) {
				evt->so->begin_async_read();
			}
		}

		void on_close(WWRP<cp_evt_t> const& evt) {

			WWRP<proxy_ctx> pctx = evt->peer->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			lock_guard<spin_mutex> lg_ctx(pctx->mutex);
			evt->peer->set_ctx(NULL);
			
			pctx->state = CLIENT_CLOSED;
			pctx->rclient = NULL;

			if (pctx->s != NULL ) {
				pctx->s->close();
				TRACE_CLIENT_SOCKET("[roger][#%u:%s][s%u]cp close, close stream: %d", evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr, pctx->s->id, evt->info.int32_v);
				pctx->s = NULL;
			}

			if (pctx->req_parser != NULL) {
				pctx->req_parser->ctx = NULL;
				pctx->req_parser->deinit();
				pctx->req_parser = NULL;
			}

			if (pctx->conn_map.size()) {
				WAWO_ASSERT(pctx->type == T_HTTP);
				WAWO_ASSERT(pctx->cur_http_ctx == NULL);
				WAWO_ASSERT(pctx->s == NULL);

				stream_http_conn_map::iterator it = pctx->conn_map.begin();
				while (it != pctx->conn_map.end()) {

					roger::cancel_all_ctx_reqs(it->second, -1 );

					it->second->s->close();
					it->second->http_resp_parser->ctx = NULL;
					it->second->http_resp_parser->deinit();
					it->second->s = NULL;
					it->second->cp = NULL;

					++it;
				}

				pctx->conn_map.clear();
			}

			WAWO_INFO("[roger][#%u:%s]client close", evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr );
		}

		void on_socket_read_shutdown(WWRP<cp_evt_t> const& evt) {
			WWRP<proxy_ctx> pctx = evt->peer->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			lock_guard<spin_mutex> lg_ctx(pctx->mutex);

			TRACE_CLIENT_SOCKET("[roger][#%u:%s]cp read shutdown, type: %u", evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr, pctx->type );

			if (pctx->s != NULL) {
				int closert = pctx->s->close_write();
				TRACE_CLIENT_SOCKET("[roger][#%u:%s]cp read shutdown, close stream write, closert: %d", evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr, closert);
			}

			if (pctx->type == T_NONE) {
				evt->so->close(wawo::E_SOCKET_FORCE_CLOSE);
			}

			if (pctx->type != T_HTTP) {
				return;
			}

			bool cp_so_should_send_shutdown_wr = true;
			if (pctx->conn_map.size()) {
				WAWO_ASSERT(pctx->type == T_HTTP);
				WAWO_ASSERT(pctx->cur_http_ctx == NULL);
				WAWO_ASSERT(pctx->s == NULL);

				stream_http_conn_map::iterator it = pctx->conn_map.begin();
				while (it != pctx->conn_map.end()) {
					
					if (it->second->reqs.size() > 0) {
						cp_so_should_send_shutdown_wr = false;
					}

					it->second->s->close_write();
					++it;
				}
			}

			if(cp_so_should_send_shutdown_wr) {
				evt->so->shutdown(wawo::net::SHUTDOWN_WR);
				TRACE_CLIENT_SOCKET("[roger][#%u:%s]cp read shutdown, conn_map.size()== 0, shutdown_wr", evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr );
			}
		}

		void on_socket_write_shutdown(WWRP<cp_evt_t> const& evt) {

			WWRP<proxy_ctx> pctx = evt->peer->get_ctx<proxy_ctx>();
			WAWO_ASSERT(pctx != NULL);
			lock_guard<spin_mutex> lg_ctx(pctx->mutex);
			TRACE_CLIENT_SOCKET("[roger][#%u:%s]cp write shutdown", evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr);

			if (pctx->s != NULL) {
				int closert = pctx->s->close_read();
				TRACE_CLIENT_SOCKET("[roger]stream_close_read s%u <---> #%d:%s, closert: %d", pctx->s->id, evt->so->get_fd(), evt->so->get_remote_addr().address_info().cstr, closert);
			}

			if (pctx->conn_map.size()) {
				WAWO_ASSERT(pctx->type == T_HTTP);
				WAWO_ASSERT(pctx->cur_http_ctx == NULL);
				WAWO_ASSERT(pctx->s == NULL);

				stream_http_conn_map::iterator it = pctx->conn_map.begin();
				while (it != pctx->conn_map.end()) {
					it->second->s->close_read();
					++it;
				}
			}
		}
	};
}

#endif