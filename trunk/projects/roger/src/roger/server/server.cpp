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

#include <wawo.h>
#include "server_handlers.hpp"
#include "dns_resolver.hpp"

int main(int argc, char** argv) {

#if defined(WIN32) && defined(VLD_DEBUG_ON) && VLD_DEBUG_ON
	_Test_VLD();
#endif

	wawo::app App;

	std::vector<std::string> ns;
#if WAWO_ISWIN

	std::vector<wawo::net::address> addrs_dns;
	wawo::env::instance()->get_local_dns_server_list(addrs_dns);

	std::for_each(addrs_dns.begin(), addrs_dns.end(), [&ns](wawo::net::address const& addr) {
		ns.push_back(addr.dotip());
	});
#endif

	int resolver_init = roger::dns_resolver::instance()->init(ns);
	WAWO_RETURN_V_IF_NOT_MATCH(resolver_init, resolver_init == wawo::OK);

	WAWO_INFO("[roger]server start...");
	wawo::net::address address;
	std::string proto = std::string("wcp");
	std::string listenurl = "wcp://0.0.0.0:13726";

	if (argc == 4) {
		std::string ip(argv[1]);
		wawo::u16_t port = wawo::to_u32(argv[2]) & 0xFFFF;
		proto = std::string(argv[3]);
		listenurl = proto + "://" + ip + ":" +std::to_string(port);
	}

	WWRP<wawo::net::channel_future> lch = wawo::net::socket::listen_on(listenurl, [](WWRP<wawo::net::channel> const& ch ) {

		WWRP<wawo::net::channel_handler_abstract> h_hlen = wawo::make_ref<wawo::net::handler::hlen>();
		ch->pipeline()->add_last(h_hlen);

		WWRP<wawo::net::channel_handler_abstract> h_dh_symmetric = wawo::make_ref<wawo::net::handler::dh_symmetric_encrypt>();
		ch->pipeline()->add_last(h_dh_symmetric);

		WWRP<wawo::net::handler::mux> h_mux = wawo::make_ref<wawo::net::handler::mux>();
		h_mux->bind<wawo::net::handler::fn_mux_stream_accepted_t>(wawo::net::handler::E_MUX_CH_STREAM_ACCEPTED, &roger::stream_accepted, std::placeholders::_1);

		ch->pipeline()->add_last(h_mux);

		WAWO_INFO("[roger]new mux connected: %u", ch->ch_id() );
	}, roger::mux_cfg );

	if (lch->get() != wawo::OK) {
		WAWO_INFO("[roger]server listen failed: %d", lch->get() );
		return lch->get();
	}

	WAWO_INFO("[roger]listen on %s", listenurl.c_str() );

	App.run();
	lch->channel()->ch_close();
	roger::dns_resolver::instance()->deinit();
	WAWO_INFO("[roger]server exiting...");
	return 0;
}
