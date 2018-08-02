#ifndef _ROGER_PROTOCOL_HPP
#define _ROGER_PROTOCOL_HPP

#include <wawo.h>

namespace roger {
	struct proxy_ctx;

	enum protocol_parse_error {
		E_WAIT_BYTES_ARRIVE = 1,
		E_OK = 0,
		E_NOT_SOCKS4_PROTOCOL = -1,
		E_UNSUPPORTED_SOCKS4_CMD = -2,
		E_INVALID_DST_IP = -3,
		E_CLIENT_SOCKET_ERROR = -4,
		E_SOCKS5_UNKNOWN_ATYPE = -5,
		E_SOCKS5_MISSING_IP_OR_PORT = -6,
		E_SOCKS5_INVALID_DOMAIN = -7,
		E_UNKNOWN_HTTP_METHOD = -8
	};

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