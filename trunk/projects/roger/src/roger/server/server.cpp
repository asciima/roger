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

<<<<<<< HEAD
=======
#include <wawo.h>
#include <iostream>

template <class _Callable>
struct event_handler: public wawo::ref_base
{
	_Callable _callee;
	event_handler(_Callable&& callee) : _callee( std::forward<_Callable>(callee) )
	{
		typedef typename std::decay<_Callable>::type __Callable_t;
		__Callable_t* _t_hint_for_debug = 0;
	}

	template<class... Args>
	void call(Args&&... args) {
		_callee(std::forward<Args>(args)...);
	}
};


//typedef event_handler<fn_foo_t> event_handler_fn_foo_t;
//typedef event_handler<bind_foo_t> event_handler_bind_foot_t;


template <class _Callable>
inline wawo::ref_ptr<event_handler<_Callable>> make_event_handler( _Callable _func)
{
	typedef typename std::decay<_Callable>::type decay_Callable_t;
	decay_Callable_t* decay_Callable_v_for_debug = 0;

	//static_assert(std::is_same<fn_foo_t, decay_fn_foo_t >::value, "fn_foo_t == decay_fn_foo_t assert failed");

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
		WWRP<wawo::ref_base> handler = make_event_handler(std::forward<_Lambda>(lambda));
		m_evt_map.insert({ id, handler });
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

typedef std::function<void(int)> event_handler_t;
class user_event_trigger :
	public event_trigger
{
	event_handler_t _eht_v;

	//typedef decltype(_eht_v) event_handler_t
public:
	void invoke_foo(int i) {
		event_trigger::invoke<event_handler_t>(1,i);
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

void foo(int arg) {
	WAWO_INFO("arg: %d", arg);
}

class cfoo_handler {
public:
	void foo(int arg) {
		WAWO_INFO("cfoo::foo(), arg: %d", arg);
	}
};

int main() {

	typedef void(*fn_foo_t) (int);
	typedef typename std::decay<fn_foo_t>::type decay_fn_foo_t;

	fn_foo_t fn_foo_v = 0;
	decay_fn_foo_t decay_foo_v_for_debug = 0;
	static_assert(std::is_same<fn_foo_t, decay_fn_foo_t>::value, "!std::is_same<fn_foo_t, decay_fn_foo_t>");
	typedef decltype(fn_foo_v) decltype_fn_foo_t;

	decltype_fn_foo_t decltype_fn_foo_v = 0;
	static_assert(std::is_same<decltype_fn_foo_t, fn_foo_t>::value, "");

	typedef decltype(&foo) decltype_foo_t;
	decltype_foo_t ptr_foo_t = fn_foo_v;
	static_assert(std::is_same<decltype_foo_t, fn_foo_t>::value, "");

	//result of std::bind  can not be dynamic_cast to func ptr
	typedef decltype(std::bind(&foo, std::placeholders::_1)) decltype_bind_foo_t;
	decltype_bind_foo_t* bind_foo_v = 0;
	static_assert( !std::is_same<decltype_bind_foo_t, fn_foo_t>::value, "");

	//class member function can not be dynamic_cast to func ptr
	cfoo_handler* _cfoo = new cfoo_handler();
	typedef decltype(std::bind( &cfoo_handler::foo, _cfoo , std::placeholders::_1)) decltype_bind_cfoo_foo_t;
	decltype_bind_cfoo_foo_t* cfoo_bind_foo_v = 0;

	//lambda test

	typedef std::function<void(int)> std_func_void_int_t;
	static_assert( std::is_same<std_func_void_int_t, event_handler_t>::value, "" );

	std_func_void_int_t lambda = [](int arg) -> void {
		WAWO_INFO("arg: %d", arg );
	};

	std_func_void_int_t lambda_from_cfoo;
	lambda_from_cfoo = [&_cfoo](int arg) -> void {
		_cfoo->foo(arg);
	};

	WWRP<user_event_trigger> user_et = wawo::make_ref<user_event_trigger>();
	WWRP<user_event_handler> user_eh = wawo::make_ref<user_event_handler>(1);

	//user_et->bind(1, lambda_from_cfoo);
	
	user_et->bind(1, [&_cfoo](int a) {
		_cfoo->foo(a);
	});
	
	user_et->invoke_foo(10);

	//typedef std::function<int(int)> int_int_func_t;
	//int_int_func_t lambda = [](int a) -> int {
	//	return a;
	//};

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




>>>>>>> 62aadb89ae17c61b8d47017af102fee1d8ee9ce9
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
