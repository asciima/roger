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
	//#define DEBUG_HTTP_PROXY
	//#define ENABLE_TRACE_SERVER_SIDE_CTX
	//#define ENABLE_TRACE_CLIENT_SIDE_CTX
#endif

//#define ENABLE_TRACE_SERVER_SIDE_CTX
//#define ENABLE_TRACE_CLIENT_SIDE_CTX
//#define DEBUG_HTTP_PROXY
//#define ENABLE_TRACE_DNS_RESOLVE

#ifdef DEBUG_HTTP_PROXY
	#define TRACE_HTTP_PROXY WAWO_INFO
#else
	#define TRACE_HTTP_PROXY(...)
#endif

#ifdef ENABLE_TRACE_CLIENT_SIDE_CTX
	#define TRACE_CLIENT_SIDE_CTX WAWO_INFO
#else
	#define TRACE_CLIENT_SIDE_CTX(...)
#endif

#ifdef ENABLE_TRACE_SERVER_SIDE_CTX
	#define TRACE_SERVER_SIDE_CTX WAWO_INFO
#else
	#define TRACE_SERVER_SIDE_CTX(...)
#endif

#ifdef ENABLE_TRACE_DNS_RESOLVE
	#define TRACE_DNS WAWO_INFO
#else
	#define TRACE_DNS(...)
#endif


namespace roger {

	using namespace wawo::net;
	using namespace wawo;

	enum protocol_parse_error {
		E_WAIT_BYTES_ARRIVE = 1,
		E_OK = 0,
		E_NOT_SOCKS4_PROTOCOL = -1,
		E_UNSUPPORTED_SOCKS4_CMD = -2,
		E_INVALID_DST_IP = -3,
		E_CLIENT_SOCKET_ERROR = -4,
		E_SOCKS5_UNKNOWN_ATYPE = -5,
		E_SOCKS5_UNSUPPORTED_ADDR_TYPE = -6,
		E_SOCKS5_MISSING_IP_OR_PORT = -7,
		E_SOCKS5_INVALID_DOMAIN = -8,
		E_UNKNOWN_HTTP_METHOD = -9,
		E_SOCKS5_UNSUPPORTED_CMD = -10
	};



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
		ADDR_IPV4 = 0x01,
		ADDR_DOMAIN = 0x03,
		ADDR_IPV6 = 0x04
	};

	enum socks5_cmd {
		S5C_CONNECT = 0x01,
		S5C_BIND = 0x02,
		S5C_UDP_ASSOCIATE = 0x03
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
		SOCKS5_RESP_HANDSHAKE,
		SOCKS5_CHECK_CMD,

		SOCKS4_PARSE,
		HTTP_REQ_PARSE,

		PIPE_PREPARE,
		
		PIPE_DIALING_STREAM,
		PIPE_DIAL_STREAM_OK,
		PIPE_DIAL_STREAM_FAILED,

		PIPE_DIALING_SERVER,
		PIPE_DIAL_SERVER_OK,
		PIPE_DIAL_SERVER_FAILED,

		HTTP_PARSE_ERROR,

		PS_MAX
	};

	static const char* proxy_state_str[PS_MAX] = {
		"_req_blind_forward",
		"_resp_blind_forward",
		"_http_parse",

		"wait_first_pack",

		"socks5_check_auth",
		"socks5_check_cmd",

		"socks4_parse",

		"http_req_parse",

		"pipe_prepare",
		"pipe_dialing_stream",
		"pipe_dial_stream_ok",
		"pipe_dial_stream_failed",

		"pipe_dialing_server",
		"pipe_dial_server_ok"
		"pipe_dial_server_failed",

		"http_parse_error"
	};

	enum http_req_sub_state {
		S_IDLE,
		S_ON_MESSAGE_BEGIN,
		S_ON_HEADERS_COMPLETE,
		S_ON_MESSAGE_COMPLETE
	};
	enum server_state {
		CONNECT,
		READ_DST_ADDR,
		LOOKUP_SERVER_NAME,
		LOOKUP_SERVER_NAEM_FAILED,
		DIAL_SERVER,
		DIAL_SERVER_FAILED,
		DIAL_SERVER_OK,
		SERVER_CONNECTED,
		SS_MAX
	};

	static const char* server_state_str[SS_MAX] = {
		"wait_connect",
		"read_dst_addr",
		"lookup_server_name",
		"lookup_server_name_failed",
		"dial_server",
		"dial_server_failed",
		"dial_server_ok",
		"server_connected"
	};

	enum server_error_code {
		E_UNKNOWN_CMD = -40001,
		E_INVALID_DOMAIN = -40002,
		E_INVALID_IPV4 = -40003,
		E_DNSLOOKUP_RETURN_NO_IP = -40004,
		E_DNS_TEMPORARY_ERROR = -40005,
		E_DNS_PROTOCOL_ERROR = -40006,
		E_DNS_DOMAIN_NAME_NOT_EXISTS = -40007,
		E_DNS_DOMAIN_NO_DATA = -40008,
		E_DNS_NOMEM = -40009,
		E_DNS_BADQUERY = -40010,
	};

	const static int dns_error_map[] = {
		0,
		E_DNS_TEMPORARY_ERROR,
		E_DNS_PROTOCOL_ERROR,
		E_DNS_DOMAIN_NAME_NOT_EXISTS,
		E_DNS_DOMAIN_NO_DATA,
		E_DNS_NOMEM,
		E_DNS_BADQUERY
	};

	static const char HTTP_RESP_RELAY_SUCCEED[] =
		"HTTP/1.1 200 Connection established\r\n\r\n";

	static const char HTTP_RESP_BAD_REQUEST[] =
		"HTTP/1.1 400 Bad request\r\n"
		"Content-Type: text/plain\r\n"
		"Connection: close\r\n\r\n"
		"ROGER: Bad request\r\n";

	static const char HTTP_RESP_CONNECT_HOST_FAILED[] =
		"HTTP/1.1 504 Connection timeout\r\n"
		"Content-Type: text/plain\r\n"
		"Connection: close\r\n\r\n"
		"ROGER: connect to host timeout\r\n";

	//refer to https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#4xx_Client_errors
	static const char HTTP_RESP_SERVER_NO_RESPONSE[] =
		"HTTP/1.1 444 No response\r\n"
		"Content-Type: text/plain\r\n"
		"Connection: close\r\n\r\n"
		"ROGER: server closed with no response, please retry (F5)";

	static const char HTTP_RESP_SERVER_RESPONSE_PARSED_FAILED[] =
		"HTTP/1.1 541 Server response error\r\n"
		"Content-Type: text/plain\r\n"
		"Connection: close\r\n\r\n"
		"ROGER: server response parse failed";

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

	enum ctx_write_state {
		WS_IDLE,
		WS_WRITING,
	};

	struct forward_ctx :
		public wawo::ref_base
	{
		forward_ctx() {
			TRACE_SERVER_SIDE_CTX("forward_ctx::forward_ctx()");
		}
		~forward_ctx() {
			TRACE_SERVER_SIDE_CTX("forward_ctx::~forward_ctx()");
		}

		WWRP<wawo::net::channel_handler_context> ch_stream_ctx;
		WWRP<wawo::net::channel_handler_context> ch_server_ctx;

		WWRP<wawo::packet> client_up_first_packet; //first req packet
		packet_queue up_to_server_packets;
		packet_queue down_to_stream_packets;

		server_state state;
		ctx_write_state up_state;
		ctx_write_state down_state;
		bool stream_read_closed;
		bool server_read_closed;
		roger_connect_address_type address_type;

		ipv4_t dst_ipv4;
		port_t dst_port;

		std::string dst_domain;
		address		dst_addrv4;
		int dns_try_time;

#ifdef ROGER_USE_LIBUDNS
		WWRP<async_dns_query> query;
#endif

		u64_t ts_dns_lookup_start;
		u64_t ts_dns_lookup_done;
		u64_t ts_server_connect_start;
		u64_t ts_server_connect_done;
	};

	enum http_conn_state {};

	enum http_request_cancel_code {
		CANCEL_CODE_CONNECT_HOST_FAILED=-0,
		CANCEL_CODE_CLIENT_BAD_REQUEST,
		CANCEL_CODE_SERVER_NO_RESPONSE,
		CANCEL_CODE_SERVER_RESPONSE_PARSE_ERROR,
		CANCEL_CODE_PROXY_PIPE_ERROR,
		HTTP_REQUEST_CANCEL_CODE_MAX
	};

	static const char* HTTP_RESP_ERROR[HTTP_REQUEST_CANCEL_CODE_MAX] =
	{
		HTTP_RESP_BAD_REQUEST,
		HTTP_RESP_CONNECT_HOST_FAILED,
		HTTP_RESP_SERVER_NO_RESPONSE,
		HTTP_RESP_SERVER_RESPONSE_PARSED_FAILED,
		HTTP_RESP_PROXY_PIPE_ERROR
	};

	const static wawo::net::socket_cfg mux_cfg = wawo::net::socket_cfg(wawo::net::OPTION_NON_BLOCKING, { 1024*1024,1024*1024 }, default_keep_alive_vals);
	const static wawo::net::socket_buffer_cfg mux_stream_sbc = { 1024*1024,1024*1024 };

//	const static wawo::u32_t client_req_buffer_size = (256 * 1024 + 5);
	const static wawo::net::socket_cfg client_cfg = wawo::net::socket_cfg(wawo::net::OPTION_NON_BLOCKING, { 256 * 1024,256 * 1024 }, default_keep_alive_vals);
	const static wawo::net::socket_cfg server_cfg = wawo::net::socket_cfg(wawo::net::OPTION_NON_BLOCKING, { 256 * 1024,256 * 1024 }, default_keep_alive_vals);

	const static wawo::net::socket_cfg http_server_cfg = wawo::net::socket_cfg(wawo::net::OPTION_NON_BLOCKING, { 256 * 1024,256 * 1024 }, default_keep_alive_vals);
	const static wawo::u32_t http_resp_rb_size = (256*1024);
}
#endif