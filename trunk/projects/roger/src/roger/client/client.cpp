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

int main(int argc, char** argv) {

	//test for coredump
	//WAWO_ASSERT(false);

#if defined(WIN32) && defined(VLD_DEBUG_ON) && VLD_DEBUG_ON
	_Test_VLD();
#endif

	WAWO_WARN("[roger]client start...");
	if (argc != 4) {
		WAWO_ERR("[roger]invalid parameter, usage: roger server_ip port");
		return -1;
	}

	{
		wawo::app _app;
		try {
			//WAWO_ASSERT(false, "failed");

			wawo::net::socket_addr remote_socketaddr;
			remote_socketaddr.so_family = wawo::net::F_AF_INET;
			remote_socketaddr.so_address = wawo::net::address(wawo::len_cstr(argv[1]).cstr, wawo::to_u32(argv[2]) & 0xFFFF);

			wawo::len_cstr proto = wawo::len_cstr(argv[3]);

			if (proto == wawo::len_cstr("wcp")) {
				remote_socketaddr.so_type = wawo::net::ST_DGRAM;
				remote_socketaddr.so_protocol = wawo::net::P_WCP;
			}
			else {
				remote_socketaddr.so_type = wawo::net::ST_STREAM;
				remote_socketaddr.so_protocol = wawo::net::P_TCP;
			}

			WWRP<roger::roger_client> node = wawo::make_ref<roger::roger_client>();
			node->init_socket_addr(remote_socketaddr);

			int start_rt = node->start();
			if (start_rt != wawo::OK) {
				WAWO_ERR("[roger]start failed, exiting, ec: %d", start_rt);
				node->stop();
				system("pause");
				return start_rt;
			}

			int sp_rt = node->StartProxy();
			if (sp_rt != wawo::OK) {
				WAWO_ERR("[roger]start local proxy failed, exiting, ec: %d", sp_rt);
				node->stop();
				system("pause");
				return sp_rt;
			}

			WWRP<roger::http_server> httpServer = wawo::make_ref<roger::http_server>();
			int httpstartrt = httpServer->start();
			if (httpstartrt != wawo::OK) {
				WAWO_ERR("[roger]start httpserver failed: %d, exiting", httpstartrt);
				node->stop();
				httpServer->stop();
				system("pause");
				return httpstartrt;
			}

			wawo::net::socket_addr laddr;
			laddr.so_family = wawo::net::F_AF_INET;
			laddr.so_type = wawo::net::ST_STREAM;
			laddr.so_protocol = wawo::net::P_TCP;
			laddr.so_address = wawo::net::address("0.0.0.0", 8088);

			int listenrt = httpServer->start_listen(laddr, roger::http_proxy_sbc);
			if (listenrt != wawo::OK) {
				WAWO_ERR("[roger]listen http server on addr: %s failed: %d, exiting", laddr.so_address.address_info().cstr, listenrt);
				node->stop();
				httpServer->stop();
				system("pause");
				return listenrt;
			}

			_app.run_for();

			httpServer->stop();
			node->stop();

			WAWO_WARN("[roger]server exiting...");
		}
		catch (wawo::exception& e) {
			WAWO_ERR("[main]wawo::exception: [%d]%s\n%s(%d) %s\n%s",
				e.code, e.message, e.file, e.line, e.func, e.callstack);
			throw;
		}
		catch (std::exception& e) {
			WAWO_ERR("[main]std::exception: %s", e.what() );
			throw;
		}
		catch (...) {
			WAWO_ERR("[main]unknown err");
			throw;
		}
	}

	return 0;
}