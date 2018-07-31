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

//	int a = 3;
//	WAWO_ASSERT(a < 1);

	wawo::app _app;

	std::string ip(argv[1]);
	wawo::u16_t port = wawo::to_u32(argv[2]) & 0xFFFF;
	std::string proto = std::string(argv[3]);
	std::string dialurl = proto + "://" + ip + ":" + std::to_string(port);
//	std::string dialurl = "tcp://127.0.0.1:8082";
	roger::mux_pool::instance()->init(dialurl);
	
	
connect_mux:
	WWRP < wawo::net::channel_future> dial_f = wawo::net::socket::dial(dialurl, [](WWRP<wawo::net::channel> const& ch) {

		WWRP<wawo::net::channel_handler_abstract> h_outlen = wawo::make_ref<wawo::net::handler::dump_out_len>();
		ch->pipeline()->add_last(h_outlen);

		WWRP<wawo::net::channel_handler_abstract> h_inlen = wawo::make_ref<wawo::net::handler::dump_in_len>();
		ch->pipeline()->add_last(h_inlen);

		WWRP<wawo::net::channel_handler_abstract> h_hlen = wawo::make_ref<wawo::net::handler::hlen>();
		ch->pipeline()->add_last(h_hlen);

		WWRP<wawo::net::channel_handler_abstract> h_dh_symmetric = wawo::make_ref<wawo::net::handler::dh_symmetric_encrypt>();
		ch->pipeline()->add_last(h_dh_symmetric);

		WWRP<wawo::net::handler::mux> h_mux = wawo::make_ref<wawo::net::handler::mux>();
		h_mux->bind<wawo::net::handler::fn_mux_evt_t>(wawo::net::handler::E_MUX_CH_CONNECTED, &roger::mux_pool::connected, roger::mux_pool::instance(), std::placeholders::_1);
		
		ch->pipeline()->add_last(h_mux);
	}, roger::mux_cfg );

	if (dial_f->get() != wawo::OK) {
		wawo::this_thread::sleep(1000);
		goto connect_mux;
	}
	

	std::string listenurl = "tcp://0.0.0.0:12122";
	WWRP<wawo::net::channel_future> listen_f = wawo::net::socket::listen_on(listenurl, [](WWRP<wawo::net::channel> const& ch) {
		ch->pipeline()->add_last(wawo::make_ref<roger::local_proxy_handler>());
	}, roger::client_cfg );
	WAWO_ASSERT(listen_f->get() == wawo::OK);

	std::string http_listenurl = "tcp://0.0.0.0:8088";
	WWRP<wawo::net::channel_future> http_listen_f = wawo::net::socket::listen_on(http_listenurl, [](WWRP<wawo::net::channel> const& ch) {
		WWRP<roger::http_server_handler> https = wawo::make_ref<roger::http_server_handler>();
		WWRP<wawo::net::handler::http> h = wawo::make_ref<wawo::net::handler::http>();
		h->bind<wawo::net::handler::fn_http_message_header_end_t>(wawo::net::handler::http_event::E_HEADER_COMPLETE, &roger::http_server_handler::on_request, https, std::placeholders::_1, std::placeholders::_2);
		ch->pipeline()->add_last(h);
	}, roger::http_server_cfg);

	WAWO_INFO("service ready");
	_app.run();
	roger::mux_pool::instance()->deinit();

	WAWO_INFO("exit main ...");
	return 0;
}