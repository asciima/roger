#ifndef _SERVER_HANDLERS_HPP
#define _SERVER_HANDLERS_HPP

#include <wawo.h>

namespace roger {


	class stream_handler :
		public wawo::net::channel_activity_handler_abstract,
		public wawo::net::channel_inbound_handler_abstract,
		public wawo::net::channel_outbound_handler_abstract
	{
	public:
		void connected(WWRP<wawo::net::channel_handler_context> const& ctx) {

			WAWO_ASSERT(!"todo");
		}

		void read(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::packet> const& income) {
			WAWO_ASSERT(!"todo");
		}

		int write(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::packet> const& outlet) {
			WAWO_ASSERT(!"todo");

			return 0;
		}

	};

	class mux_stream_acceptor :
		public wawo::net::channel_acceptor_handler_abstract
	{
	public:
		void accepted(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::net::channel> const& newch) {

			WWRP<stream_handler> h = wawo::make_ref<stream_handler>();
			newch->pipeline()->add_last(h);
		}
	};

	class mux_acceptor :
		public wawo::net::channel_acceptor_handler_abstract
	{

	public:
		void accepted(WWRP<wawo::net::channel_handler_context> const& ctx, WWRP<wawo::net::channel> const& newch) {
			WWRP<wawo::net::channel_acceptor_handler_abstract> h_mux_s_acceptor = wawo::make_ref<mux_stream_acceptor>();

			WWRP<wawo::net::channel_handler_abstract> h_mux = wawo::make_ref<wawo::net::handler::mux>(h_mux_s_acceptor);
			newch->pipeline()->add_last(h_mux);

			(void)ctx;
		}
	};
}
#endif