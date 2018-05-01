#include <wawo.h>
#include "../shared/shared.hpp"

namespace roger {
	struct proxy_ctx :
		public wawo::ref_base
	{
		wawo::thread::spin_mutex mutex;
		WWRP<wawo::net::channel_handler_context> rclient;

		proxy_state state;
		http_req_sub_state sub_state;

		proxy_forward_type type;

		WWRP<client_peer_t> client_peer;

		WWRP<wawo::packet> protocol_packet; //client up ringbuffer --> stream
		packet_queue client_up_packets;

		WWRP<stream> s;
		u8_t stream_write_flag;

		roger_connect_address_type address_type;

		ipv4::Ip	dst_ipv4;
		ipv4::Port	dst_port;

		len_cstr	dst_domain;
		address		dst_addrv4;

		stream_http_conn_map	conn_map;

		WWRP<wawo::net::protocol::http::parser> req_parser;
		WWSP<wawo::net::protocol::http::message> cur_req;
		WWRP<http_conn_ctx> cur_http_ctx;

		wawo::len_cstr http_field_tmp;

		//for resp
		WWRP<http_conn_ctx> cur_resp_http_conn_ctx;

		WWRP<wawo::bytes_ringbuffer> memory_tag;
	};

	class local_proxy_handler :
		public wawo::net::channel_inbound_handler_abstract,
		public wawo::net::channel_activity_handler_abstract
	{
	public:
		virtual void connected(WWRP<wawo::net::channel_handler_context> const& ctx) {
			ctx->ch->turnon_nodelay();

			WWRP<proxy_ctx>

		}

		virtual void closed(WWRP<wawo::net::channel_handler_context > const& ctx) {

		}

		virtual void read_shutdowned(WWRP<wawo::net::channel_handler_context> const& ctx) {

		}

		virtual void write_shutdowned(WWRP<wawo::net::channel_handler_context> const& ctx) {

		}

		void read(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::net::channel> const& ch) {

		}
	};

	class local_proxy_listener_handler :
		public wawo::net::channel_acceptor_handler_abstract
	{
	public:
		void accepted(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::net::channel> const& ch) {
			ch->pipeline()->add_last(wawo::make_ref<local_proxy_handler>());
		}
	};

	inline int load_file_into_len_cstr(wawo::len_cstr& file, wawo::len_cstr const& file_path_name) {
		FILE* fp = fopen(file_path_name.cstr, "rb");
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

		wawo::len_cstr _file((char*)file_bytes->begin(), file_bytes->len());
		file = _file;
		WAWO_ASSERT((long)file.len == end);
		return file.len;
	}

	class http_server_handler :
		public wawo::ref_base
	{

	public:
		void on_request(WWRP<wawo::net::channel_handler_context> const& ctx, WWSP<wawo::net::protocol::http::message> const& m) {
			WAWO_ASSERT(m->type == wawo::net::protocol::http::T_REQ);
			WAWO_INFO("[http_server]request url: %s", m->url.cstr);

			wawo::len_cstr proxy_type = wawo::len_cstr("PROXY");
			int is_socks5_url = wawo::strpos(m->url.cstr, "socks5.pac");
			if (is_socks5_url != -1) {
				proxy_type = wawo::len_cstr("SOCKS5");
			}

			WWSP<wawo::net::protocol::http::message> resp = wawo::make_shared<wawo::net::protocol::http::message>();

			resp->ver = { 1,1 };;
			resp->h.set("Content-Type", "application/x-ns-proxy-autoconfig");
			resp->h.set("Connection", "close");

			wawo::len_cstr pac_file_content;
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

			if (load_rt < 0 || pac_file_content.len == 0) {
				resp->status_code = 404;
				resp->status = "File not found";
				resp->body = "file not found";
			}
			else {

				wawo::len_cstr host = m->h.get("Host");

				if (host.len == 0) {
					resp->status_code = 403;
					resp->status = "access forbidden";
					resp->body = "access forbidden";
				}
				else {

					resp->status_code = 200;
					resp->status = "OK";

					std::vector<wawo::len_cstr> host_and_port;
					wawo::split(host, ":", host_and_port);

					if (host_and_port.size() != 2) {
						WAWO_ERR("[http_server]invalid http request");
						ctx->close();
						return;
					}

					WAWO_ASSERT(host_and_port.size() == 2);

					wawo::len_cstr REPLACE_IP = "ROGER_HTTP_SERVER_ADDR";
					wawo::len_cstr REPLACE_TYPE = "PROXY_TYPE";

					wawo::len_cstr new_content_phase_1;
					wawo::len_cstr new_content_phase_2;

					int rep_rt1 = wawo::replace(pac_file_content, REPLACE_IP, host_and_port[0], new_content_phase_1);
					WAWO_ASSERT(rep_rt1 >= 1);
					int rep_rt2 = wawo::replace(new_content_phase_1, REPLACE_TYPE, proxy_type, new_content_phase_2);
					WAWO_ASSERT(rep_rt2 == 1);

					resp->body = new_content_phase_2;
				}
			}

			WWRP<wawo::packet> outp;
			resp->encode(outp);

			int resprt = ctx->write(outp);
			WAWO_ASSERT(resprt == wawo::OK);
			ctx->close();
		}
	};

	class pac_http_listener_handler :
		public wawo::net::channel_acceptor_handler_abstract
	{
	public:
		void accepted(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::net::channel> const& ch) {

			WWRP<http_server_handler> https = wawo::make_ref<http_server_handler>();

			WWRP<wawo::net::handler::http> h = wawo::make_ref<wawo::net::handler::http>();
			h->bind<wawo::net::handler::fn_http_message_header_end_t>(wawo::net::handler::http_event::E_HEADER_COMPLETE, &http_server_handler::on_request, https, std::placeholders::_1, std::placeholders::_2);

			ch->pipeline()->add_last(h);
		}
	};

}