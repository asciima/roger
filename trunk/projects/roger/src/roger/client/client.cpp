#ifdef _DEBUG
	#define VLD_DEBUG_ON 0
#endif

#if defined(WIN32) && defined(VLD_DEBUG_ON) && VLD_DEBUG_ON
	#include <vld.h>
	#include <stdio.h>
	#include <stdlib.h>

	void _Test_VLD() {
		int* p = new int();
		*p = 12345678;
		*p ++;
	}
#endif

#include "../shared/shared.hpp"
#include "client_node.hpp"

#include "client_handlers.hpp"


int main(int argc, char** argv) {

#if defined(WIN32) && defined(VLD_DEBUG_ON) && VLD_DEBUG_ON
	_Test_VLD();
#endif

	WAWO_WARN("[roger]client start...");
	if (argc != 4) {
		WAWO_ERR("[roger]invalid parameter, usage: roger server_ip port");
		return -1;
	}

	wawo::app _app;

	wawo::net::socketaddr raddr;
	raddr.so_family = wawo::net::F_AF_INET;
	raddr.so_address = wawo::net::address(wawo::len_cstr(argv[1]).cstr, wawo::to_u32(argv[2]) & 0xFFFF);

	wawo::len_cstr proto = wawo::len_cstr(argv[3]);

	if (proto == wawo::len_cstr("wcp")) {
		raddr.so_type = wawo::net::T_DGRAM;
		raddr.so_protocol = wawo::net::P_WCP;
	}
	else {
		raddr.so_type = wawo::net::T_STREAM;
		raddr.so_protocol = wawo::net::P_TCP;
	}

	WWRP<wawo::net::socket> muxso = wawo::make_ref<wawo::net::socket>( raddr.so_family, raddr.so_type, raddr.so_protocol );
	int rt = muxso->open();
	WAWO_RETURN_V_IF_NOT_MATCH( rt, rt==wawo::OK );

	WWRP<wawo::net::channel_handler_abstract> h_dh_symmetric = wawo::make_ref<wawo::net::handler::dh_symmetric_encrypt>();
	muxso->pipeline()->add_last(h_dh_symmetric);

	WWRP<wawo::net::channel_handler_abstract> h_muxstream = wawo::make_ref<wawo::net::handler::mux>();
	muxso->pipeline()->add_last(h_muxstream);

	rt = muxso->async_connect(raddr.so_address);
	WAWO_ASSERT(rt == wawo::OK);

	wawo::net::socketaddr laddr;
	laddr.so_family = wawo::net::F_AF_INET;
	laddr.so_type = wawo::net::T_STREAM;
	laddr.so_protocol = wawo::net::P_TCP;
	laddr.so_address = wawo::net::address("0.0.0.0", 12122);

	WWRP<wawo::net::socket> proxyso = wawo::make_ref < wawo::net::socket >(laddr.so_family, laddr.so_type, laddr.so_address);
	rt = proxyso->open();
	WAWO_ASSERT(rt == wawo::OK);
	if (rt != wawo::OK) {
		WAWO_ERR("[roger]local proxy so open failed, exiting, ec: %d", rt);
		muxso->close();
		proxyso->close();
		return -1;
	}

	rt = proxyso->bind( laddr.so_address );
	if (rt != wawo::OK) {
		WAWO_ERR("[roger]local proxy so bind failed, exiting, ec: %d", rt);
		muxso->close();
		proxyso->close();
		return -1;
	}

	WWRP<wawo::net::channel_handler_abstract> h_proxylistener = wawo::make_ref<roger::local_proxy_listener_handler>();
	proxyso->pipeline()->add_last(h_proxylistener);

	rt = proxyso->listen();
	WAWO_ASSERT(rt == wawo::OK);

	wawo::net::socketaddr laddr_8088;
	laddr_8088.so_family = wawo::net::F_AF_INET;
	laddr_8088.so_type = wawo::net::T_STREAM;
	laddr_8088.so_protocol = wawo::net::P_TCP;
	laddr_8088.so_address = wawo::net::address("0.0.0.0", 8088);

	WWRP<wawo::net::socket> pachttpso = wawo::make_ref<wawo::net::socket>(laddr_8088.so_family, laddr.so_type, laddr.so_protocol);
	rt = pachttpso->open();
	WAWO_ASSERT(rt == wawo::OK);

	rt = pachttpso->bind(laddr_8088.so_address);
	WAWO_ASSERT(rt == wawo::OK);

	WWRP<wawo::net::channel_handler_abstract> h_http = wawo::make_ref<roger::pac_http_listener_handler> ();
	pachttpso->pipeline()->add_last(h_http);

	rt = pachttpso->listen();
	WAWO_ASSERT(rt == wawo::OK);

	_app.run_for();
	WAWO_INFO("exit main ...");
	return 0;
}