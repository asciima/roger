#ifdef _DEBUG
	#define VLD_DEBUG_ON 0
#endif

#if defined(WIN32) && defined(VLD_DEBUG_ON) && VLD_DEBUG_ON
#include <vld.h>
void _Test_VLD() {
	int* p = new int(12345678);
	*p++;
}
#endif

int __main(int argc, char** argv) {

#if defined(WIN32) && defined(VLD_DEBUG_ON) && VLD_DEBUG_ON
	_Test_VLD();
#endif


	/*
	wawo::app App;

	WAWO_INFO("[roger]server start...");
	wawo::net::address address;
	wawo::len_cstr proto = wawo::len_cstr("tcp");

	if (argc != 4) {
		WAWO_WARN("[roger] listen address not specified, we'll use 0.0.0.0:12120 tcp");
		address = wawo::net::address("0.0.0.0", 12120);
	}
	else {
		wawo::len_cstr ip(argv[1]);
		wawo::u16_t port = wawo::to_u32(argv[2]) & 0xFFFF;
		address = wawo::net::address(ip.cstr, port);
		proto = wawo::len_cstr(argv[3]);
	}

	wawo::net::socketaddr laddr;
	laddr.so_address = address;
	laddr.so_family = wawo::net::F_AF_INET;

	if (proto == "wcp") {
		laddr.so_type = wawo::net::T_DGRAM;
		laddr.so_protocol = wawo::net::P_WCP;
	}
	else {
		laddr.so_type = wawo::net::T_STREAM;
		laddr.so_protocol = wawo::net::P_TCP;
	}

	WWRP<wawo::net::socket> so = wawo::make_ref<wawo::net::socket>(laddr.so_family, laddr.so_type, laddr.so_protocol);
	int rt = so->open();
	WAWO_RETURN_V_IF_NOT_MATCH(rt, rt == wawo::OK);

	rt = so->bind(laddr.so_address);
	WAWO_RETURN_V_IF_NOT_MATCH(rt, rt == wawo::OK);


	App.run_for();

	WAWO_INFO("[roger]server exiting...");

	*/
	return 0;
}
