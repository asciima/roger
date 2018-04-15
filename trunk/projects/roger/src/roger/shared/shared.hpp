#ifndef _ROGER_SHARED_HPP
#define _ROGER_SHARED_HPP


#ifdef ROGER_SERVER
	#define ROGER_USE_LIBUDNS
#endif

#ifdef ROGER_USE_LIBUDNS
	#include <udns.h>
#endif

#include <wawo.h>

#define FORCE_WCP 1

#ifdef _DEBUG
	#define DEBUG_HTTP_PROXY
	#define DEBUG_CLIENT_SOCKET
#endif

#ifdef DEBUG_HTTP_PROXY
	#define TRACE_HTTP_PROXY WAWO_INFO
#else
	#define TRACE_HTTP_PROXY(...)
#endif

#ifdef DEBUG_CLIENT_SOCKET
	#define TRACE_CLIENT_SOCKET WAWO_INFO
#else
	#define TRACE_CLIENT_SOCKET(...)
#endif

#ifdef DEBUG
	#define ENABLE_TRACE_CTX
	#define ENABLE_TRACE_SERVER_STREAM
	#define ENABLE_TRACE_DNS_RESOLVE
#endif

#ifdef ENABLE_TRACE_CTX
	#define TRACE_CTX WAWO_INFO
#else
	#define TRACE_CTX(...)
#endif

#ifdef ENABLE_TRACE_SERVER_STREAM
	#define TRACE_SERVER_STREAM WAWO_INFO
#else
	#define TRACE_SERVER_STREAM(...)
#endif

#ifdef ENABLE_TRACE_DNS_RESOLVE
	#define TRACE_DNS WAWO_INFO
#else
	#define TRACE_DNS(...)
#endif


namespace roger {

	using namespace wawo::net;
	using namespace wawo;

	enum roger_cmd {
		C_LOGIN,
		C_LOGOUT,

		//[slen:u16+cstr]
		C_LOOKUP_DNS,
		//[type:u8,[ip:port|domain]]
		C_CONNECT
	};

	enum roger_server_code {
		OK = 0,
		CONNECT_SERVER_FAILED
	};

	enum roger_connect_address_type {
		HOST, //domain or ip in Dotted Decimal Notation
		IPV4,
		IPV6
	};

	enum socks4_response_code {
		S4_REQUEST_GRANTED = 90,
		S4_REQUEST_REJECTED_FOR_FAILED = 91,
		S4_REQUEST_REJECTED_FOR_CONNECT_IDENTD_FAILED = 92,
		S4_REQUEST_REJECTED_FOR_DIFFERENT_USER_IDS = 93
	};

	enum socks4_cmd {
		S4C_CONNECT = 1,
		S4C_BIND = 2
	};

	enum socks5_address_type {
		ADDR_IPV4	= 0x01,
		ADDR_DOMAIN = 0x03,
		ADDR_IPV6	= 0x04
	};

	enum socks5_cmd {
		S5C_CONNECT			= 0x01,
		S5C_BIND			= 0x02,
		S5C_UDP_ASSOCIATE	= 0x03
	};

	enum socks5_response_code {
		S5_SUCCEEDED = 0,
		S5_GENERAL_SOCKS_SERVER_FAILURE,
		S5_CONNECTION_NOT_ALLOWED_BY_RULESET,
		S5_NETWORK_UNREACHABLE,
		S5_HOST_UNREACHABLE,
		S5_CONNECTION_REFUSED,
		S5_TTL_EXPIRE,
		S5_COMMAND_NOT_SUPPORTED,
		S5_ADDRESS_TYPE_NOT_SUPPORTED,
		S5_TO_XFF_UNASSIGNED
	};

	enum proxy_forward_type {
		T_NONE,
		T_DIRECT,
		T_HTTP,
		T_HTTPS,
		T_SOCKS4,
		T_SOCKS4A, // dns lookup on server side , TO BE IMPL
		T_SOCKS5
	};

	enum proxy_state {

		_REQ_BLIND_FORWARD,
		_RESP_BLIND_FORWARD,

		_HTTP_PARSE,

		WAIT_FIRST_PACK,

		SOCKS5_CHECK_AUTH,
		SOCKS5_CHECK_CMD,

		SOCKS4_PARSE,

		HTTP_PARSE,

		PIPE_PREPARE,
		PIPE_MAKING,
		PIPE_CONNECTED,
		PIPE_CONNECT_HOST_FAILED,
		PIPE_MAKING_FAILED,
		PIPE_BROKEN,

		CLIENT_CLOSED,
		PROXY_ERROR,
		HTTP_PARSE_ERROR,

		PS_MAX
	};

	enum http_req_sub_state {
		S_IDLE,
		S_ON_MESSAGE_BEGIN,
		S_ON_HEADERS_COMPLETE,
		S_ON_MESSAGE_COMPLETE
	};

	static const char* proxy_state_str[PS_MAX] = {
		"_req_blind_forward",
		"_resp_blind_forward",
		"_http_parse",

		"wait_first_pack",

		"socks5_check_auth",
		"socks5_check_cmd",

		"socks4_parse",

		"http_parse",

		"pipe_prepare",
		"pipe_making",
		"pipe_connected",
		"pipe_connect_host_failed",
		"pipe_making_failed",
		"pipe_broken",

		"client_closed",
		"proxy_error",
		"http_parse_error"
	};


	enum server_state {
		CONNECT,
		READ_DST_ADDR,
		LOOKUP_SERVER_NAME,
		CONNECTING_SERVER,
		SERVER_CONNECTED,
		SERVER_CLOSED,
		STREAM_CLOSED,
		ERR,
		SS_MAX
	};

	static const char* server_state_str[SS_MAX] = {
		"wait_connect",
		"read_dst_addr",
		"lookup_server_name",
		"connecting_server",
		"server_connected",
		"server_closed",
		"err"
	};

	static const char HTTP_RESP_RELAY_SUCCEED[] =
		"HTTP/1.1 200 Connection established\r\n\r\n";

	static const char HTTP_RESP_CONNECT_HOST_FAILED[] =
		"HTTP/1.1 504 Connection timeout\r\n"
		"Content-Type: text/plain\r\n"
		"Connection: close\r\n\r\n"
		"ROGER: connect to host failed\r\n";

	//refer to https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#4xx_Client_errors
	static const char HTTP_RESP_SERVER_NO_RESPONSE[] =
		"HTTP/1.1 444 No response\r\n"
		"Content-Type: text/plain\r\n"
		"Connection: keep-alive\r\n\r\n"
		"ROGER: server closed with no response, please retry (F5)";

	static const char HTTP_RESP_PROXY_PIPE_ERROR[] =
		"HTTP/1.1 541 Proxy pipe error\r\n"
		"Content-Type: text/plain\r\n"
		"Connection: close\r\n\r\n"
		"ROGER: proxy pipe issue";


	/*
	static const char HTTP_RESP_CLIENT_CLOSE[]=
		"HTTP/1.1 499 Client closed\r\n"
		"Connection: close\r\n\r\n"
		"ROGER: client closed the connection before server respond";
	*/

	typedef std::queue< WWSP<wawo::net::protocol::http::message> > message_queue;
	typedef std::queue< WWRP<wawo::packet> > packet_queue;

	struct async_dns_query;

	class roger_client;

	struct forward_ctx :
		public wawo::ref_base
	{
		enum session_flag {
			F_NONE = 0,
			F_CLIENT_FIN = 1,
			F_SERVER_FIN = 1 << 1,
			F_BOTH_FIN = (F_CLIENT_FIN | F_SERVER_FIN),
		};

		wawo::thread::spin_mutex mutex;
		wawo::net::peer::stream_id_t stream_id;
		WWRP<stream> s;
		WWRP<server_peer_t> server_peer;

		WWRP<wawo::packet> client_up_first_packet; //first req packet

		packet_queue client_outps;

		packet_queue sp_to_stream_packets;
		server_state state;

		roger_connect_address_type address_type;

		ipv4::Ip dst_ipv4;
		ipv4::Port dst_port;

		len_cstr	dst_domain;
		address		dst_addrv4;

		int sflag;

#ifdef ROGER_USE_LIBUDNS
		WWRP<async_dns_query> query;
#endif

		WWRP<wawo::bytes_ringbuffer> memory_tag;
		forward_ctx() {}
		~forward_ctx() {}

		int flush_packet_to_server( WWSP<packet> const& outp ) {

			WAWO_ASSERT( server_peer != NULL);

			WWSP<message::cargo> omessage = wawo::make_shared<message::cargo>(outp);
			int flushrt = server_peer->do_send_message(omessage);

			if (flushrt == wawo::E_CHANNEL_WRITE_BLOCK) {
			} else if (flushrt == wawo::OK) {
				TRACE_SERVER_STREAM("[forward_ctx][s%u][%d:%s]forward buffer to server success: %u", s->id, server_peer->get_socket()->get_fd(), server_peer->get_socket()->get_addr_info().cstr, outp->len() );
			} else {
				TRACE_SERVER_STREAM("[forward_ctx][s%u][%d:%s]forward buffer to server failed: %d, close sp", s->id, server_peer->get_socket()->get_fd(), server_peer->get_socket()->get_addr_info().cstr, flushrt );
				server_peer->close(flushrt);
			}

			return flushrt;
		}
	};

	enum http_conn_state {};

	struct http_conn_ctx:
		public wawo::ref_base
	{
		spin_mutex mutex;

		roger_connect_address_type address_type;
		wawo::len_cstr host_with_port;

		wawo::len_cstr domain;
		ipv4::Ip ip;

		ipv4::Port port;
		proxy_state state;

		bool in_chunk_body;
		bool resp_header_connection_close;

		u32_t resp_count;

		WWRP<wawo::net::protocol::http::parser> http_resp_parser;
		WWSP<wawo::net::protocol::http::message> cur_req;

		packet_queue req_up_packets;
		
		message_queue reqs;

		WWRP<wawo::bytes_ringbuffer> resp_rb;
		WWSP<wawo::net::protocol::http::message> cur_resp;

		wawo::len_cstr resp_http_field_tmp;

		WWRP<client_peer_t> cp;
		WWRP<stream> s;
	};

	enum http_request_cancel_code {
		CANCEL_CODE_SERVER_NO_RESPONSE = 0,
		CANCEL_CODE_PROXY_PIPE_ERROR,
		CANCEL_CODE_CONNECT_HOST_FAILED,
		HTTP_REQUEST_CANCEL_CODE_MAX
	};

	static const char* HTTP_RESP_ERROR[HTTP_REQUEST_CANCEL_CODE_MAX] =
	{
		HTTP_RESP_SERVER_NO_RESPONSE,
		HTTP_RESP_PROXY_PIPE_ERROR,
		HTTP_RESP_CONNECT_HOST_FAILED
	};

	inline void cancel_all_ctx_reqs(WWRP<http_conn_ctx> const& ctx, int const& cancel_code ) {
		while (ctx->reqs.size()) {

			if (cancel_code >= 0) {
				WAWO_ASSERT(cancel_code < http_request_cancel_code::HTTP_REQUEST_CANCEL_CODE_MAX);
				WWRP<wawo::packet> resp_pack = wawo::make_shared<wawo::packet>(1024);

				resp_pack->write((wawo::byte_t*) HTTP_RESP_ERROR[cancel_code], wawo::strlen(HTTP_RESP_ERROR[cancel_code]));
				WWSP<wawo::net::peer::message::cargo> mresp = wawo::make_shared<wawo::net::peer::message::cargo>(resp_pack);

				WAWO_ASSERT(ctx->cp != NULL);
				ctx->cp->do_send_message(mresp);
			}

			WWSP<wawo::net::protocol::http::message>& req = ctx->reqs.front();
			WAWO_INFO("[roger][http][s%u]cancel req: %s, cancel code: %u", ctx->s->id, req->url.cstr, cancel_code );
			ctx->reqs.pop();
		}
	}

	typedef std::unordered_map < wawo::len_cstr, WWRP<http_conn_ctx> > stream_http_conn_map;
	typedef std::pair < wawo::len_cstr, WWRP<http_conn_ctx>> stream_http_conn_pair;


	enum e_stream_write_flag {
		STREAM_WRITE_BLOCK = 0x01
	};

	struct proxy_ctx :
		public wawo::ref_base
	{
		wawo::thread::spin_mutex mutex;
		WWRP<roger_client> rclient;

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

	//const int ENCRYPT_BUFFER_CFG = wawo::net::BT_MEDIUM_UPPER;
	const static wawo::net::socket_buffer_cfg mux_sbc = { 256*1024,256*1024 };
	const static wawo::net::socket_buffer_cfg http_proxy_sbc = { 256*1024,256*1024 };
	const static wawo::net::socket_buffer_cfg client_sbc = { 256*1024,256*1024 };
	const static wawo::net::socket_buffer_cfg server_sbc = { 256*1024,256*1024 };


	const static wawo::u32_t http_resp_rb_size = (256*1024);
	const static wawo::u32_t client_req_buffer_size = (256*1024+5);
}



#endif