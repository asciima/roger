#ifndef _ROGER_PROTOCOL_HPP
#define _ROGER_PROTOCOL_HPP

#include <wawo.h>

namespace roger {

	static const char* option_name_str[wawo::net::protocol::http::O_MAX] = {
		"GET",
		"HEAD",
		"POST",
		"PUT",
		"DELETE",
		"CONNECT",
		"OPTIONS",
		"TRACE"
	};


	enum protocol_parse_error {
		E_WAIT_BYTES_ARRIVE = 1,
		E_OK = 0,
		E_NOT_SOCKS4_PROTOCOL = -1,
		E_UNSUPPORTED_SOCKS4_CMD = -2,
		E_INVALID_DST_IP = -3,
		E_CLIENT_SOCKET_ERROR = -4,
		E_SOCKS5_UNKNOWN_ATYPE = -5,
		E_SOCKS5_UNSUPPORTED_ADDR_TYPE=-6,
		E_SOCKS5_MISSING_IP_OR_PORT = -7,
		E_SOCKS5_INVALID_DOMAIN = -8,
		E_UNKNOWN_HTTP_METHOD = -9,
		E_SOCKS5_UNSUPPORTED_CMD= -10
	};

	struct proxy_ctx;
	void _socks5_check_auth(WWRP<proxy_ctx> const& ctx);
	int _socks5_check_cmd(WWRP<proxy_ctx> const& ctx);

	/*
	1,	continue
	0,	ok
	<0,	error
	*/
	int _socks4_parse(WWRP<proxy_ctx> const& ctx);
	int _detect_http_proxy(WWRP<proxy_ctx> const& pctx);
}

#endif