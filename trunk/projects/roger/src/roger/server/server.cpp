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
//#include "server_node.hpp"

#include <iostream>

//typedef int(*foo_t)(int);
//typedef std::function<int(int)> foo_tt;

int fooo(int arg) {
	WAWO_INFO("arg: %d", arg);
	return arg;
}

typedef decltype(fooo) _fooo_t;
typedef decltype( std::bind(&fooo, std::placeholders::_1) ) fooo_t;

template <class _Callable>
struct event_handler: public wawo::ref_base
{
	_Callable func_;

	event_handler(_Callable&& _func) : func_( std::forward<_Callable>(_func) )
	{
		typedef typename std::decay<_Callable>::type __tt;
		__tt* aaa = 0;
	}

	template<class... Args>
	void call(Args&&... args) {
		func_(std::forward<Args>(args)...);
	}
};


typedef event_handler<fooo_t> real_type_2;

template <class _Callable>
inline wawo::ref_ptr<event_handler<_Callable>> make_event_handler( _Callable _func)
{
	//typedef typename std::decay<fooo_t>::type ___tt;
	//typedef typename std::decay<_Callable>::type __tt;
	//static_assert(std::is_same<fooo_t, __tt >::value, "");

	int iu;

	//__tt* aaa= 0;
	//___tt* aaaa = 0;

	return wawo::make_ref<event_handler<_Callable>>(std::forward<_Callable>(_func));
}

struct event_trigger :
	public wawo::ref_base
{
	typedef std::map<int, WWRP<wawo::ref_base> > event_map_t;
	event_map_t m_evt_map;

public:
	event_trigger():m_evt_map()
	{}
	virtual ~event_trigger()
	{}

	template<class _Fx, class... _Args>
	void bind(int const& id, _Fx&& _func, _Args&&... _args)
	{
		WWRP<wawo::ref_base> handler = make_event_handler(std::bind(std::forward<_Fx>(_func), std::forward<_Args>(_args)...));
		m_evt_map.insert({id, handler});
	}

	template<class _Lambda>
	void bind(int const& id, _Lambda&& lambda) {

	}

	template<class _Callable, class... _Args>
	void invoke(int id, _Args&&... _args) {
		typename event_map_t::iterator it = m_evt_map.find(id);
		if (it != m_evt_map.end()) {
			WWRP<event_handler<_Callable>> callee = wawo::dynamic_pointer_cast<event_handler<_Callable>>(it->second);
			WAWO_ASSERT(callee != NULL);
			callee->call(std::forward<_Args>(_args)...);
		}
	}
};

class user_event_trigger :
	public event_trigger
{
	typedef std::function<int(int)> foo;
	foo _foo_var;

	typedef decltype(std::bind(_foo_var, std::placeholders::_1)) foo_bind_t;

public:
	void invoke_foo(int i) {
		event_trigger::invoke<foo_bind_t>(1,i);
	}
};


class user_event_handler:
	public wawo::ref_base
{
	int i;
public:

	user_event_handler(int i_) :i(i_) {}

	void foo(int j) {
		WAWO_INFO("this.i: %d, j: %d", i, j);
	}
};


int main() {

	WWRP<user_event_trigger> user_et = wawo::make_ref<user_event_trigger>();
	WWRP<user_event_handler> user_eh = wawo::make_ref<user_event_handler>(1);

	user_et->bind(1, &user_event_handler::foo, user_eh, std::placeholders::_1);
	user_et->invoke_foo(10);

	typedef std::function<int(int)> int_int_func_t;
	int_int_func_t lambda = [](int a) -> int {
		return a;
	};

	//typedef decltype(lambda) lambda_t;
	//lambda_t* lambdat;

	//typedef decltype(std::bind(&fooo, std::placeholders::_1)) ttt;
	//ttt* _ttt =0;

	//typedef decltype(std::bind(&lambda, std::placeholders::_1)) ttt_;
	//ttt_* _ttt_ = 0;

	//WWRP<wawo::ref_base> ib = make_event_handler(std::bind( &fooo, std::placeholders::_1));

	//decltype(std::bind(std::declval<foo&>())) t;
	//WWSP<real_type> _bb = wawo::static_pointer_cast<real_type>(_b);
	//int i = _bb->call<int>(9);

	//WWRP<real_type_2> _bb2 = wawo::dynamic_pointer_cast<real_type_2>(ib);
	//WAWO_ASSERT( _bb2 != NULL );

	//int i2 = _bb2->call<int>(10);

	//auto x = cmd<int>(&foo, std::placeholders::_1);
	//x->exec<int>(12);

	//std::cout << x->getResult() << std::endl;
	return 0;
}




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
