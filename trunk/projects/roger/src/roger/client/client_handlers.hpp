#include <wawo.h>


class local_proxy_handler :
	public wawo::net::channel_inbound_handler_abstract
{
public:
	void read(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::net::channel> const& ch) {

	}
};

class local_proxy_listener_handler :
	public wawo::net::channel_acceptor_handler_abstract
{
public:
	void accepted(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::net::channel> const& ch) {
		ch->pipeline()->add_last( wawo::make_ref<local_proxy_handler>() );
	}
};
