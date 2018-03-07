#ifdef _DEBUG
	#define VLD_DEBUG_ON 1
#endif

#if defined(WIN32) && defined(VLD_DEBUG_ON) && VLD_DEBUG_ON
#include <vld.h>
void _Test_VLD() {
	int* p = new int(12345678);
	*p++;
}
#endif

#include "server_node.hpp"


//int main(int argc, char** argv) {
	//test ntop,pton

//	const char* ip = "192.168.2.1";
//	sockaddr_in saddr;
//	int rt = inet_pton(AF_INET, ip, &saddr.sin_addr);

//	char ip2[64];
//	inet_ntop(AF_INET, &saddr.sin_addr, ip2, 64 );
//}

//#define TEST_RESOLVER

#ifdef TEST_RESOLVER
wawo::thread::spin_mutex querys_mutex;
std::vector< WWRP<roger::async_dns_query>> querys;

struct resolve_cookie:
	public wawo::ref_base
{
	wawo::thread::spin_mutex mutex;
	wawo::len_cstr domain;
	WWRP<roger::async_dns_query> query;
};

void dns_resolve_success(std::vector<in_addr> const& in_addrs, WWRP<wawo::ref_base> const& cookie_) {

	WWRP<resolve_cookie> cookie = wawo::static_pointer_cast<resolve_cookie>(cookie_);
	wawo::thread::lock_guard<wawo::thread::spin_mutex> lg(cookie->mutex);

	std::for_each(in_addrs.begin(), in_addrs.end(), [&](in_addr const& inaddr) {
		char addr[16] = { 0 };
		const char* addr_cstr = inet_ntop(AF_INET, &inaddr, addr, 16);
		WAWO_ERR("dns_resolve_success, %s:%s", cookie->domain.cstr, addr_cstr);
	});

	wawo::thread::lock_guard<wawo::thread::spin_mutex> lg_querys(querys_mutex);
	std::vector< WWRP<roger::async_dns_query>>::iterator it = std::find(querys.begin(), querys.end(), cookie->query);
	WAWO_ASSERT(it != querys.end());
	querys.erase(it);

}

void dns_resolve_error(int const& code, WWRP < wawo::ref_base > const& cookie) {

	WAWO_ERR("dns_resolve_error: %d", code);
}
#endif

#include <unordered_map>

int main(int argc, char** argv) {

	/*
	std::hash<std::string> string_hash;
	std::size_t xxx = string_hash(std::string("aaaa"));
	std::unordered_map<wawo::len_cstr, wawo::len_cstr> unordered_map_var;
	*/

#if defined(WIN32) && defined(VLD_DEBUG_ON) && VLD_DEBUG_ON
	_Test_VLD();
#endif
#ifdef DEBUG_THREAD_POLL_COUNT
	wawo::app App(1);
#else
	wawo::app App;
#endif

#ifdef TEST_RESOLVER
	{
		std::vector<wawo::len_cstr> ns;
		ns.push_back(wawo::len_cstr("192.168.2.1"));
		ns.push_back(wawo::len_cstr("100.64.10.2"));
		ns.push_back(wawo::len_cstr("100.64.10.3"));

		WWRP<roger::dns_resolver> _resolver = wawo::make_ref<roger::dns_resolver>(ns);
	
		int rt = _resolver->init();

		std::vector<wawo::len_cstr> domains;
		domains.push_back("www.baidu.com");
		domains.push_back("www.163.com");
		domains.push_back("www.sina.com.cn");
		domains.push_back("54.65.109.6");

		std::for_each(domains.begin(), domains.end(), [&_resolver](wawo::len_cstr const& domain) {
			WWRP<resolve_cookie> cookie = wawo::make_ref<resolve_cookie>();

			wawo::thread::lock_guard<wawo::thread::spin_mutex> lg(cookie->mutex);
			cookie->domain = domain;
			cookie->query = _resolver->async_resolve(domain.cstr, cookie, dns_resolve_success, dns_resolve_error);

			wawo::thread::lock_guard<wawo::thread::spin_mutex> lg_querys(querys_mutex);
			querys.push_back(cookie->query);
		});

		while( querys.size())
		{	
			wawo::this_thread::yield();
		}

		_resolver->deinit();
		return 0;
	}
#endif


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

	wawo::net::socket_addr listen_addr;
	listen_addr.so_address = address;
	listen_addr.so_family = wawo::net::F_AF_INET;

	if (proto == "wcp") {
		listen_addr.so_type = wawo::net::ST_DGRAM;
		listen_addr.so_protocol = wawo::net::P_WCP;
	}
	else {
		listen_addr.so_type = wawo::net::ST_STREAM;
		listen_addr.so_protocol = wawo::net::P_TCP;
	}

	WWRP<roger::roger_server> node = wawo::make_ref<roger::roger_server>();
	int rt = node->Start(listen_addr);
	(void)&rt;

	WAWO_INFO("start rt: %d", rt );
	WAWO_RETURN_V_IF_NOT_MATCH(rt, rt == wawo::OK);
	while ( !App.should_exit()) {
		wawo::this_thread::sleep(5);
	}

	node->Stop();

	WAWO_INFO("[roger]server exiting...");
	return 0;
}
