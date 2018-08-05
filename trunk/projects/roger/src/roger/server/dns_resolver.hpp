#ifndef ROGER_DNS_RESOLVER_HPP
#define ROGER_DNS_RESOLVER_HPP

#include <udns.h>
#include <wawo.h>

#include "../shared/shared.hpp"

namespace roger {

	using namespace wawo::net;
	using namespace wawo;

	typedef void(*fn_resolve_succes)(std::vector<in_addr> const& in_addrs, WWRP<ref_base> const& cookie);
	typedef void(*fn_resolve_error)(int const& code, WWRP<ref_base> const& cookie);

	struct async_resolve_cookie {
		WWRP<ref_base> user_cookie;
		fn_resolve_succes success;
		fn_resolve_error error;
	};

	struct async_dns_query :
		public ref_base
	{
		struct dns_query* dnsquery;
	};

	class dns_resolver;
	/*
	struct dns_async_cookie:
		public wawo::ref_base
	{
		dns_resolver* dnsr;
	};
	*/

	class dns_resolver:
		public singleton<dns_resolver>
	{
		WWRP<wawo::net::socket> m_so;
		WWSP<fn_ticker> m_dns_ticker;

		spin_mutex m_dns_ctx_mutex;
		struct dns_ctx* m_dns_ctx;

		std::vector<std::string> m_ns;

	public:
		dns_resolver():
			m_so(NULL),
			m_dns_ctx(NULL)
		{
		}

		~dns_resolver() {}

		int init(std::vector<std::string> const& name_servers) {
			m_ns = std::vector<std::string>(name_servers.begin(), name_servers.end());

			lock_guard<spin_mutex> lg_ctx(m_dns_ctx_mutex);
			m_dns_ctx = &dns_defctx;

			if (m_ns.size() == 0) {
#if WAWO_ISGNU
				dns_init(m_dns_ctx, 0);
#else
				WAWO_THROW("missing name server");
#endif
			}
			else {
				dns_reset(m_dns_ctx);
				std::for_each(m_ns.begin(), m_ns.end(), [&](std::string const& serv ) {
					dns_add_serv(m_dns_ctx, serv.c_str());
				});
			}

			int fd = dns_open(m_dns_ctx);
			if (fd < 0) {
				WAWO_ERR("[dns_resolver]dns open failed: %d", fd);
				return fd;
			}

			wawo::net::address laddr;
			wawo::net::address raddr;
			WWRP<wawo::net::socket> so = wawo::make_ref<wawo::net::socket>(fd, SM_ACTIVE, laddr,raddr, F_AF_INET, T_DGRAM, P_UDP );
			int nonblocking = so->turnon_nonblocking();

			if (nonblocking != wawo::OK) {
				WAWO_ERR("[dns_resolver]turnon nonblocking failed: %d", nonblocking);
				return nonblocking;
			}

			m_dns_ticker = wawo::make_shared<fn_ticker>(std::bind(&dns_resolver::dns_timeout_ticker, this));
			milli_ticker::instance()->schedule(m_dns_ticker);

			//so->event_poller()->start_timer();

			so->begin_read(F_WATCH_READ_INFINITE, std::bind(&dns_resolver::async_read_dns_reply, this, std::placeholders::_1));
			m_so = so;
			return wawo::OK;
		}

		void deinit() {
			m_so->ch_close();

			milli_ticker::instance()->deschedule(m_dns_ticker);
			m_dns_ticker = NULL;

			dns_close(m_dns_ctx);
			m_dns_ctx = NULL;
		}

		void dns_timeout_ticker() {
			//time_t now = ::time(NULL);
			lock_guard<spin_mutex> lg_ctx(m_dns_ctx_mutex);
			dns_timeouts(m_dns_ctx, -1, 0);
		}

		void dns_event_loop() {
			lock_guard<spin_mutex> lg_ctx(m_dns_ctx_mutex);
			time_t now = ::time(NULL);
			dns_ioevent(m_dns_ctx, now);
		}

		void async_read_dns_reply(async_io_result const& r) {
			if (r.v.code == wawo::OK) {
				dns_event_loop();
			} else {
				WAWO_ERR("[dns_resolver]dns read error: %d", r.v.code );
				m_so->ch_close();
			}
		}

		/*
		static void async_read_dns_error(int const& code, WWRP<ref_base> const& cookie_) {
			WAWO_ERR("[dns_resolver]async_read_dns_error: %d", code);
			WAWO_ASSERT(!"WHAT");

			(void)cookie_;
		}*/

		static void dns_query_v4_cb(struct dns_ctx* ctx, struct dns_rr_a4* result, void* data) {
			WAWO_ASSERT(ctx != NULL);
			WAWO_ASSERT(data != NULL);
			async_resolve_cookie* cookie = (async_resolve_cookie*)data;

			if (result == NULL) {
				int code = dns_status(ctx);
				WAWO_ASSERT(code != wawo::OK);
				WAWO_ERR("[dns_resolver]dns resolve failed: %d:%s", code, dns_strerror(code));
				cookie->error(WAWO_NEGATIVE(code), cookie->user_cookie);
				WAWO_DELETE(cookie);
				return;
			}

			std::vector<in_addr> in_addr_vec;
			if (result->dnsa4_nrr > 0) {
				for (int i = 0; i < result->dnsa4_nrr; ++i) {
					in_addr_vec.push_back( result->dnsa4_addr[i] );
				}
			}

			WAWO_ASSERT(in_addr_vec.size());
			if (in_addr_vec.size()) {
				cookie->success(in_addr_vec, cookie->user_cookie);
			} else {
				cookie->error(roger::E_DNSLOOKUP_RETURN_NO_IP, cookie->user_cookie);
			}

			dns_free_ptr(result);
			WAWO_DELETE(cookie);
		}

		WWRP<async_dns_query> async_resolve( std::string const& domain, WWRP<ref_base> const& cookie, fn_resolve_succes const& success, fn_resolve_error const& error) {
			async_resolve_cookie* _cookie = new async_resolve_cookie();
			WAWO_ALLOC_CHECK(_cookie, sizeof(async_resolve_cookie) );
			_cookie->user_cookie = cookie;
			_cookie->success = success;
			_cookie->error = error;

			WWRP<async_dns_query> query = wawo::make_ref<async_dns_query>();
			lock_guard<spin_mutex> lg_ctx(m_dns_ctx_mutex);
			query->dnsquery = dns_submit_a4(m_dns_ctx, domain.c_str(), 0, dns_resolver::dns_query_v4_cb, (void*)_cookie);

			return query;
		}

		void resolve_cancel(WWRP<async_dns_query> const& q) {
			lock_guard<spin_mutex> lg_ctx(m_dns_ctx_mutex);
			if (q->dnsquery != NULL) {
				dns_cancel(m_dns_ctx, q->dnsquery);
				dns_free_ptr(q->dnsquery);
			}
		}
	};

}

#endif
