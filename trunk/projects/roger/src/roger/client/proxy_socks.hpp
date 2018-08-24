#ifndef _ROGER_PROTOCOL_HPP
#define _ROGER_PROTOCOL_HPP

#include <wawo.h>

namespace roger {

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