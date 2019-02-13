
#include "proxy_socks.hpp"
#include "client_handlers.hpp"

namespace roger {

	void _socks5_check_auth(WWRP<proxy_ctx> const& ctx) {

		//we always response with 0x05 0x00
		WWRP<packet> s5_handshake_reply = wawo::make_ref<packet>(64);
		s5_handshake_reply->write<u8_t>(5);
		s5_handshake_reply->write<u8_t>(0);

		WWRP<wawo::net::channel_future> write_f = ctx->ch_client_ctx->write(s5_handshake_reply);
		write_f->add_listener([ctx](WWRP<wawo::net::channel_future> const& f) {
			int rt = f->get();
			if (rt != wawo::OK) {
				WAWO_ERR("[client][#%u]resp socks5 handshake failed, %d", ctx->ch_client_ctx->ch->ch_id(), rt);
				ctx->ch_client_ctx->close();
			} else {
				ctx->state = SOCKS5_CHECK_CMD;
				if (ctx->protocol_packet->len()) {
					WWRP<wawo::packet> income = wawo::make_ref<wawo::packet>();
					//income->write( ctx->protocol_packet->begin(), ctx->protocol_packet->len() );
					//ctx->protocol_packet->reset();
					//fake a new arrive to get a check chance
					ctx->ch_client_ctx->invoke_read(income);
				}
			}
		});
	}

	int _socks5_check_cmd(WWRP<proxy_ctx> const& pctx) {
		// check vcra	[ver,cmd,rsv,atype]
		if (pctx->protocol_packet->len() < 5) {
			return E_WAIT_BYTES_ARRIVE;
		}

		wawo::byte_t vcra[5];
		pctx->protocol_packet->peek(vcra, 5);

		u32_t addr_len = 0;
		u32_t rlen = 0;
		if (((vcra[3])&(0xff)) == ADDR_IPV4) {
			//tcp v4
			addr_len = 4;
			rlen = 4 + addr_len + 2;
		} else if (((vcra[3])&(0xff)) == ADDR_IPV6) {
			//tcp v6
			addr_len = 16;
			rlen = 4 + addr_len + 2;
		} else if (((vcra[3])&(0xff)) == ADDR_DOMAIN) {
			u8_t dlen = vcra[4] & 0xFF;
			//vcra + len + domain
			rlen = 4 + 1 + dlen;
			WAWO_DEBUG("[client][#%u]atype(domain): %d", pctx->ch_client_ctx->ch->ch_id() , vcra[3]);
		}
		else {
			WAWO_ERR("[client][#%u:%s]unknown atype: %d", pctx->ch_client_ctx->ch->ch_id(), vcra[3]);
			return E_SOCKS5_UNKNOWN_ATYPE;
		}

		if (pctx->protocol_packet->len() < rlen) {
			return E_WAIT_BYTES_ARRIVE;
		}

		u8_t ver = pctx->protocol_packet->read<u8_t>();
		u8_t cmd = pctx->protocol_packet->read<u8_t>();
		u8_t rsv = pctx->protocol_packet->read<u8_t>();
		u8_t at = pctx->protocol_packet->read<u8_t>();

		(void)&ver;
		(void)&cmd;
		(void)&rsv;
		(void)&at;

		if (at == ADDR_IPV4) {
			pctx->dst_ipv4 = pctx->protocol_packet->read<u32_t>();
			pctx->dst_port = pctx->protocol_packet->read<u16_t>();

			if (pctx->dst_ipv4 == 0 || pctx->dst_port == 0)
			{
				WAWO_ERR("[client][#%u]invalid addr or port", pctx->ch_client_ctx->ch->ch_id() );
				return E_SOCKS5_MISSING_IP_OR_PORT;
			}
			pctx->address_type = IPV4;
		}
		else if (at == ADDR_IPV6) {
			return E_SOCKS5_UNSUPPORTED_ADDR_TYPE;
		}
		else if (at == ADDR_DOMAIN) {
			u8_t dlen = pctx->protocol_packet->read<u8_t>();
			if (dlen >= HOST_MAX_LENGTH) {
				WAWO_ERR("[client][#%u]invalid domain", pctx->ch_client_ctx->ch->ch_id());
				return E_SOCKS5_INVALID_DOMAIN;
			}

			char domain[HOST_MAX_LENGTH] = { 0 };
			u32_t drlen = pctx->protocol_packet->read((wawo::byte_t*)domain, dlen);
			WAWO_ASSERT(dlen == drlen);
			pctx->address_type = HOST;

			pctx->dst_domain = std::string(domain, wawo::strlen(domain));
			pctx->dst_port = pctx->protocol_packet->read<u16_t>();

			WAWO_DEBUG("[client][#%u]CMD: %d, dst addr: %s:%d", pctx->ch_client_ctx->ch->ch_id() , cmd, domain, pctx->dst_port);
			pctx->dst_ipv4 = 0;
		}
		else {
			return E_SOCKS5_UNSUPPORTED_ADDR_TYPE;
		}

		switch (cmd) {
		case S5C_CONNECT:
		{
		}
		break;
		case S5C_BIND:
		case S5C_UDP_ASSOCIATE:
		default:
		{
			return E_SOCKS5_UNSUPPORTED_CMD;
		}
		break;
		}

		WAWO_ASSERT(pctx->protocol_packet->len() == 0);
		return E_OK;
	}

	/*
	1,	continue
	0,	ok
	<0,	error
	*/
	int _socks4_parse(WWRP<proxy_ctx> const& pctx) {
		WAWO_ASSERT(pctx->type == T_SOCKS4);

		byte_t _tmp[HOST_MAX_LENGTH] = { 0 };
		u32_t count = pctx->protocol_packet->peek(_tmp, HOST_MAX_LENGTH);

		enum parse_socks4_connect_state {
			S4_CHECK_VN,
			S4_READ_CMD,
			S4_READ_PORT,
			S4_READ_DST_IP,
			S4_READ_DOMAIN,
			S4_DONE
		};

		parse_socks4_connect_state s4_state = S4_CHECK_VN;

		u32_t idx = 0;

		u16_t dst_port = 0;
		std::string dst_ip;
		std::string dst_domain;

		while (idx < count) {
			switch (s4_state) {
			case S4_CHECK_VN:
			{
				u8_t vn = _tmp[idx];
				if (vn != 4) {
					WAWO_WARN("[client][#%u]broken socks4 protocol, close cp", pctx->ch_client_ctx->ch->ch_id() );
					return E_NOT_SOCKS4_PROTOCOL;
				}

				s4_state = S4_READ_CMD;
				++idx;
			}
			break;
			case S4_READ_CMD:
			{
				u8_t cmd = _tmp[idx];
				if (cmd != S4C_CONNECT) {
					WAWO_WARN("[client][#%u]unsupported socks4 protocol cmd, close cp", pctx->ch_client_ctx->ch->ch_id() );
					return E_UNSUPPORTED_SOCKS4_CMD;
				}
				s4_state = S4_READ_PORT;
				++idx;
			}
			break;
			case S4_READ_PORT:
			{
				if ((idx + 2) >= count) {
					return E_WAIT_BYTES_ARRIVE;
				}

				dst_port = wawo::bytes_helper::read_u16(_tmp + idx);
				idx += 2;
				if (idx + 4 <= count) {
					char tmp[16] = { 0 };
					int rt = snprintf(tmp, 16, "%u.%u.%u.%u", _tmp[idx], _tmp[idx + 1], _tmp[idx + 2], _tmp[idx + 3]);
					WAWO_ASSERT((rt > 0) && (rt < 16));
					idx += 4;
					dst_ip = std::string(tmp);
				}

				//skip after '0'
				while ((idx < count) && _tmp[idx++] != 0);

				if (dst_ip == std::string("0.0.0.1")) {
					s4_state = S4_READ_DOMAIN;
				}
				else {
					s4_state = S4_DONE;
				}
			}
			break;
			case S4_READ_DOMAIN:
			{
				char _domain[256];
				u32_t didx = 0;
				while ((idx < count) && _tmp[idx] != 0) {
					_domain[didx++] = _tmp[idx++];

					if (_tmp[idx] == 0) {
						_domain[didx] = 0;

						if (!wawo::net::is_dotipv4_decimal_notation(_domain)) {
							dst_domain = std::string(_domain);
						}
						else {
							dst_ip = _domain;
						}
						s4_state = S4_DONE;
						idx++; //last '0'
					}
				}
			}
			break;
			}
		}

		if (s4_state != S4_DONE) {
			return E_WAIT_BYTES_ARRIVE;
		}
		pctx->protocol_packet->skip(idx);

		WAWO_ASSERT(dst_port > 0);
		WAWO_ASSERT(dst_domain.length() > 0 || dst_ip.length() > 0);

		pctx->dst_port = dst_port;
		if (dst_domain.length() > 0) {
			pctx->dst_domain = dst_domain;
			pctx->address_type = HOST;
		}
		else {
			WAWO_ASSERT(dst_ip.length() > 0);

			wawo::net::ipv4_t _ip;
			int crt = wawo::net::hosttoip(dst_ip.c_str(), _ip);

			if (crt != wawo::OK) {
				WAWO_WARN("[client][#%u]invalid ipaddr in socks4 protocol cmd, close cp", pctx->ch_client_ctx->ch->ch_id() );
				return E_INVALID_DST_IP;
			}

			pctx->dst_ipv4 = ::ntohl(_ip);
			pctx->address_type = IPV4;
		}

		return E_OK;
	}
}