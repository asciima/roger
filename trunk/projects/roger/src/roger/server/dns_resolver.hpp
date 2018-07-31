#ifndef ROGER_DNS_RESOLVER_HPP
#define ROGER_DNS_RESOLVER_HPP

#include <udns.h>
#include <wawo.h>

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

	class dns_resolver:
		public ref_base
	{
		WWRP<wawo::net::socket> m_so;
		WWSP<fn_ticker> m_dns_ticker;

		spin_mutex m_dns_ctx_mutex;
		struct dns_ctx* m_dns_ctx;

		std::vector<wawo::len_cstr> m_ns;

	public:
		dns_resolver(std::vector<wawo::len_cstr> const& name_servers):
			m_so(NULL),
			m_dns_ctx(NULL)
		{
			m_ns = std::vector<wawo::len_cstr>(name_servers.begin(), name_servers.end());
		}

		~dns_resolver() {}

		int init() {

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
				std::for_each(m_ns.begin(), m_ns.end(), [&](wawo::len_cstr const& serv ) {
					dns_add_serv(m_dns_ctx, serv.cstr);
				});
			}

			int fd = dns_open(m_dns_ctx);
			if (fd < 0) {
				WAWO_ERR("[dns_resolver]dns open failed: %d", fd);
				return fd;
			}

			wawo::net::address _address;
			WWRP<wawo::net::socket> so = wawo::make_ref<wawo::net::socket>(fd, _address, SM_ACTIVE, socket_buffer_cfgs[BT_DEFAULT], F_AF_INET, ST_DGRAM, P_UDP);
			int nonblocking = so->turnon_nonblocking();

			if (nonblocking != wawo::OK) {
				WAWO_ERR("[dns_resolver]turnon nonblocking failed: %d", nonblocking);
				return nonblocking;
			}

			m_dns_ticker = wawo::make_shared<fn_ticker>(std::bind(&dns_resolver::dns_timeout_ticker, WWRP<dns_resolver>(this)));
			milli_ticker::instance()->schedule(m_dns_ticker);

			so->begin_async_read(WATCH_OPTION_INFINITE, WWRP<dns_resolver>(this), dns_resolver::async_read_dns_reply, dns_resolver::async_read_dns_error);
			
			m_so = so;
			return wawo::OK;
		}

		void deinit() {
			m_so->close(wawo::E_SOCKET_FORCE_CLOSE);

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

		static void async_read_dns_reply(WWRP<ref_base> const& cookie_) {
			WAWO_ASSERT(cookie_ != NULL);
			WWRP<async_cookie> cookie = wawo::static_pointer_cast<async_cookie>(cookie_);
			WWRP<dns_resolver> resolver = wawo::static_pointer_cast<dns_resolver>(cookie->user_cookie);
			resolver->dns_event_loop();
		}

		static void async_read_dns_error(int const& code, WWRP<ref_base> const& cookie_) {
			WAWO_ERR("[dns_resolver]async_read_dns_error: %d", code);
		}

		static void dns_query_v4_cb(struct dns_ctx* ctx, struct dns_rr_a4* result, void* data) {
			WAWO_ASSERT(ctx != NULL);
			WAWO_ASSERT(data != NULL);
			async_resolve_cookie* cookie = (async_resolve_cookie*)data;

			if (result == NULL) {
				WAWO_ERR("[dns_resolver]IPV4 resolve: %s", dns_strerror(dns_status(ctx)));
				cookie->error(dns_status(ctx), cookie->user_cookie);
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
			}
			else {
				cookie->error(-1, cookie->user_cookie);
			}

			dns_free_ptr(result);
			WAWO_DELETE(cookie);
		}

		WWRP<async_dns_query> async_resolve( wawo::len_cstr const& domain, WWRP<ref_base> const& cookie, fn_resolve_succes const& success, fn_resolve_error const& error) {
			async_resolve_cookie* _cookie = new async_resolve_cookie();
			_cookie->user_cookie = cookie;
			_cookie->success = success;
			_cookie->error = error;

			WWRP<async_dns_query> query = wawo::make_ref<async_dns_query>();
			lock_guard<spin_mutex> lg_ctx(m_dns_ctx_mutex);
			query->dnsquery = dns_submit_a4(m_dns_ctx, domain.cstr, 0, dns_resolver::dns_query_v4_cb, (void*)_cookie);

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
