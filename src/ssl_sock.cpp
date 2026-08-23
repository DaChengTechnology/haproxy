/*
 * SSL/TLS transport layer over SOCK_STREAM sockets -- JPSSL backend
 *
 * Copyright (C) 2026 DaChengTechnology
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * ---------------------------------------------------------------------
 * WHAT THIS FILE IS
 *
 * This is a first, self-contained implementation of HAProxy's SSL xprt
 * layer on top of the JPSSL C++20 library (https://github.com/DaChengTechnology/JPSSL).
 * It is meant to be built INSTEAD of src/ssl_sock.c when USE_JPSSL=1, and
 * directly drives JPSSL's message-level API (jpssl::tls::tls_session +
 * tls13_make_server_flight()/tls12_make_server_hello_flight()/tls_encrypt()/
 * tls_decrypt()) from HAProxy's own event loop.
 *
 * It deliberately does NOT use jpssl::tls::tls_connection / tls_listener:
 * those socket wrappers poll internally with a bounded timeout (default
 * 30 s), which would stall HAProxy's single-threaded event loop and turn a
 * slow client into a DoS vector.  Instead all handshake I/O is driven by
 * the lower xprt (raw socket) through the usual SUB_RETRY_RECV /
 * SUB_RETRY_SEND subscription mechanism.
 *
 * IMPLEMENTED
 *   - xprt registration (XPRT_SSL, "SSL")
 *   - listener (frontend) mode, TLS 1.2 and TLS 1.3 server handshakes,
 *     ALPN negotiation, SNI-based certificate selection (exact match with
 *     default-certificate fallback), application-data record encryption
 *     and decryption, close_notify on shutdown.
 *   - minimal bind_conf glue: jpssl_sock_set_certfile() registers a
 *     certificate, prepare_bind_conf() validates and decodes ALPN.
 *
 * NOT IMPLEMENTED YET (tracked with TODO in the code)
 *   - outbound (server/connect) mode, client-certificate verification,
 *     OCSP stapling, TLS 1.3 session tickets / 0-RTT, post-handshake
 *     KeyUpdate, kTLS, ECH, JWT/ACME sample fetches, CLI "show ssl" etc.
 *     Those pieces belong to other files (cfgparse-ssl.c, ssl_ckch.c,
 *     ssl_sample.c, ...) which still need JPSSL counterparts before a full
 *     USE_JPSSL build can link.
 *
 * BUILD NOTES
 *   - compile this file with the C++ compiler:
 *       $(CXX) -std=c++20 $(COPTS) -I$(SSL_INC) -c src/ssl_sock.cpp
 *     where SSL_INC points at JPSSL's include/ directory.
 *   - HAProxy's C headers are included inside an extern "C" block so that
 *     calls into the C core get C linkage.
 * ---------------------------------------------------------------------
 */

#ifdef USE_JPSSL

/* HAProxy C headers -- must be seen with C linkage from C++. */
extern "C" {
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/tcp.h>

#include <haproxy/api.h>
#include <haproxy/buf.h>
#include <haproxy/chunk.h>
#include <haproxy/connection.h>
#include <haproxy/errors.h>
#include <haproxy/global.h>
#include <haproxy/listener.h>
#include <haproxy/log.h>
#include <haproxy/proxy.h>
#include <haproxy/task.h>
#include <haproxy/ticks.h>
#include <haproxy/time.h>
#include <haproxy/tools.h>
}

#include <algorithm>
#include <map>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <utility>
#include <vector>

/* JPSSL headers.  SSL_INC must point at JPSSL's include/ directory. */
#include "tls.hpp"

using jpssl::tls::AlertDescription;
using jpssl::tls::AlertLevel;
using jpssl::tls::CipherSuite;
using jpssl::tls::ContentType;
using jpssl::tls::HandshakeType;
using jpssl::tls::TLSVersion;
using jpssl::tls::tls_certificate_manager;

/* forward declaration of the exported xprt ops (defined at the bottom) */
extern "C" struct xprt_ops ssl_sock;

/* Handshake machine states */
enum jpssl_hs_state {
	JPSSL_HS_NONE,
	JPSSL_HS_READ_CH,       /* waiting for the full ClientHello        */
	JPSSL_HS_READ_CKE,      /* TLS1.2: waiting for ClientKeyExchange   */
	JPSSL_HS_READ_CCS,      /* TLS1.2: waiting for ChangeCipherSpec    */
	JPSSL_HS_READ_FIN,      /* waiting for the encrypted Finished      */
	JPSSL_HS_DONE,          /* handshake completed                     */
	JPSSL_HS_ERROR,         /* handshake failed                        */
};

/* Per-connection transport context (opaque to the rest of HAProxy). */
struct jpssl_sock_ctx {
	struct connection *conn;
	const struct xprt_ops *xprt;   /* lower transport (raw socket)  */
	void *xprt_ctx;

	struct wait_event wait_event;  /* subscription on the lower xprt */
	struct wait_event *subs;       /* upper-layer subscription       */

	jpssl::tls::tls_session session;
	const tls_certificate_manager *cert_mgr; /* borrowed from bind_conf */

	/* raw bytes received from the lower xprt, not yet consumed */
	std::vector<uint8_t> rxbuf;
	size_t rx_off = 0;

	/* encrypted bytes waiting to be flushed to the lower xprt */
	std::vector<uint8_t> txbuf;
	size_t tx_off = 0;
	size_t pending_consumed = 0; /* plaintext accepted but not yet flushed */

	/* decrypted application data not yet copied to the caller */
	std::vector<uint8_t> appbuf;
	size_t app_off = 0;

	/* handshake state */
	enum jpssl_hs_state state = JPSSL_HS_NONE;
	std::vector<uint8_t> hs_msg;   /* current handshake message (incl. header) */
	unsigned int hs_flags = 0;
};

/* ------------------------------------------------------------------ */
/* Per-bind_conf JPSSL data (cert manager + ALPN), kept in a registry */
/* ------------------------------------------------------------------ */
struct jpssl_bind_ctx {
	tls_certificate_manager cert_mgr;
	std::vector<std::string> alpn;
};

static std::mutex jpssl_bind_lock;
static std::map<struct bind_conf *, std::unique_ptr<jpssl_bind_ctx>> jpssl_bind_ctxs;

static jpssl_bind_ctx *jpssl_bind_ctx_lookup(struct bind_conf *bc)
{
	std::lock_guard<std::mutex> lock(jpssl_bind_lock);
	auto it = jpssl_bind_ctxs.find(bc);
	return it != jpssl_bind_ctxs.end() ? it->second.get() : nullptr;
}

/* Retrieve our ctx from a connection, or NULL if SSL is not the active
 * transport layer on this connection. */
static struct jpssl_sock_ctx *jpssl_conn_ctx(struct connection *conn)
{
	if (!conn || conn->xprt != &ssl_sock)
		return nullptr;
	return static_cast<jpssl_sock_ctx *>(conn->xprt_ctx);
}

/* ------------------------------------------------------------------ */
/* Record-layer helpers                                               */
/* ------------------------------------------------------------------ */

/* Wrap <data> into a single TLS record of type <rtype> (legacy version
 * 0x0303, as used by both TLS 1.2 and TLS 1.3). */
static void jpssl_make_record(std::vector<uint8_t>& out, uint8_t rtype,
                              const uint8_t *data, size_t len)
{
	out.push_back(rtype);
	out.push_back(0x03);
	out.push_back(0x03);
	out.push_back((uint8_t)(len >> 8));
	out.push_back((uint8_t)len);
	out.insert(out.end(), data, data + len);
}

static size_t jpssl_msg_len24(const uint8_t *p)
{
	return ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
}

/* Parse the ClientHello supported_versions extension (0x002b) and report
 * whether the client advertised TLS 1.3 (0x0304). */
static bool jpssl_client_supports_tls13(const uint8_t *ch, size_t ch_len)
{
	if (!ch || ch_len < 4 + 2 + 32)
		return false;
	size_t o = 4 + 2 + 32;
	if (o + 1 > ch_len)
		return false;
	uint8_t sid_len = ch[o];
	o += 1 + sid_len;
	if (o + 2 > ch_len)
		return false;
	uint16_t cs_len = (ch[o] << 8) | ch[o + 1];
	o += 2 + cs_len;
	if (o + 1 > ch_len)
		return false;
	uint8_t comp_len = ch[o];
	o += 1 + comp_len;
	if (o + 2 > ch_len)
		return false;
	uint16_t ext_total = (ch[o] << 8) | ch[o + 1];
	o += 2;
	if (o + ext_total > ch_len)
		return false;
	size_t end = o + ext_total;
	while (o + 4 <= end) {
		uint16_t etype = (ch[o] << 8) | ch[o + 1];
		uint16_t elen  = (ch[o + 2] << 8) | ch[o + 3];
		if (etype == 0x002b && elen >= 2 && o + 4 + elen <= end) {
			uint8_t vlen = ch[o + 4];
			for (uint8_t i = 0; i + 2 <= vlen && i + 3 <= elen; i += 2) {
				uint16_t v = (ch[o + 5 + i] << 8) | ch[o + 5 + i + 1];
				if (v == 0x0304)
					return true;
			}
		}
		o += 4 + elen;
	}
	return false;
}

/* Extract one complete record of type <allow_type> from rxbuf.  Other
 * record types (e.g. CCS in TLS 1.3 compatibility mode) are skipped.
 * Returns:
 *   1  a complete record was consumed (payload in *payload, type in *rtype)
 *   0  more data needed
 *  -1  error (malformed record or alert)
 */
static int jpssl_rx_record(struct jpssl_sock_ctx *ctx, uint8_t allow_type,
                           uint8_t *rtype, std::vector<uint8_t>& payload)
{
	for (;;) {
		size_t avail = ctx->rxbuf.size() - ctx->rx_off;
		if (avail < 5)
			return 0;

		const uint8_t *p = ctx->rxbuf.data() + ctx->rx_off;
		size_t rlen = (p[3] << 8) | p[4];
		if (rlen > jpssl::tls::TLS_MAX_RECORD_PLAINTEXT + 256)
			return -1;
		if (5 + rlen > avail)
			return 0;              /* partial record */

		uint8_t type = p[0];
		if (type == 21)            /* alert during handshake */
			return -1;

		payload.assign(p + 5, p + 5 + rlen);
		ctx->rx_off += 5 + rlen;

		if (type == allow_type) {
			*rtype = type;
			return 1;
		}
		/* otherwise skip (CCS, plaintext handshake leftovers, ...) */
	}
}

/* Accumulate one full handshake message of type <want> from rxbuf into
 * ctx->hs_msg.  Returns 1 when complete, 0 when more data is needed,
 * -1 on error. */
static int jpssl_hs_recv_msg(struct jpssl_sock_ctx *ctx, uint8_t want)
{
	uint8_t rtype;
	std::vector<uint8_t> payload;

	for (;;) {
		/* do we already hold a complete message? */
		if (ctx->hs_msg.size() >= 4) {
			size_t mlen = jpssl_msg_len24(ctx->hs_msg.data());
			if (ctx->hs_msg.size() >= 4 + mlen) {
				if (ctx->hs_msg[0] == want)
					return 1;
				/* unrelated handshake message (e.g. a client cert we did
				 * not request): skip it and keep looking */
				ctx->hs_msg.clear();
				continue;
			}
		}

		int r = jpssl_rx_record(ctx, 22, &rtype, payload);
		if (r <= 0)
			return r;
		ctx->hs_msg.insert(ctx->hs_msg.end(), payload.begin(), payload.end());
	}
}

/* ------------------------------------------------------------------ */
/* Raw I/O plumbing through the lower xprt                            */
/* ------------------------------------------------------------------ */

/* Read more raw bytes from the lower xprt into rxbuf.  Returns >0 on
 * progress, 0 when the read would block, -1 on error/read0. */
static int jpssl_sock_refill_rx(struct jpssl_sock_ctx *ctx)
{
	struct connection *conn = ctx->conn;
	uint8_t buf[16384];
	struct buffer tmpbuf;
	size_t ret;

	tmpbuf.size = sizeof(buf);
	tmpbuf.area = (char *)buf;
	tmpbuf.head = 0;
	tmpbuf.data = 0;

	ret = ctx->xprt->rcv_buf(conn, ctx->xprt_ctx, &tmpbuf, sizeof(buf),
	                         NULL, NULL, 0);
	if (ret > 0) {
		ctx->rxbuf.insert(ctx->rxbuf.end(), buf, buf + ret);
		return (int)ret;
	}
	if (ret == 0) {
		if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH))
			return -1;
		return 0;                /* EAGAIN */
	}
	return -1;
}

/* Flush txbuf to the lower xprt.  Returns 0 when fully flushed, 1 when
 * the write would block (subscribed for SUB_RETRY_SEND), -1 on error. */
static int jpssl_sock_flush_tx(struct jpssl_sock_ctx *ctx)
{
	struct connection *conn = ctx->conn;

	while (ctx->tx_off < ctx->txbuf.size()) {
		struct buffer tmpbuf;
		size_t n = ctx->txbuf.size() - ctx->tx_off;
		size_t ret;

		tmpbuf.size = n;
		tmpbuf.area = (char *)(ctx->txbuf.data() + ctx->tx_off);
		tmpbuf.data = n;
		tmpbuf.head = 0;

		ret = ctx->xprt->snd_buf(conn, ctx->xprt_ctx, &tmpbuf, n,
		                         NULL, 0, 0);
		if (ret > 0) {
			ctx->tx_off += ret;
			continue;
		}
		if (ret == 0 && !(conn->flags & (CO_FL_ERROR | CO_FL_SOCK_WR_SH))) {
			if (!(ctx->wait_event.events & SUB_RETRY_SEND))
				ctx->xprt->subscribe(conn, ctx->xprt_ctx,
				                     SUB_RETRY_SEND,
				                     &ctx->wait_event);
			return 1;
		}
		return -1;
	}
	ctx->txbuf.clear();
	ctx->tx_off = 0;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Handshake                                                          */
/* ------------------------------------------------------------------ */

/* Advance the handshake state machine as far as possible without
 * blocking.  Returns 1 on progress, 0 when more input is needed,
 * -1 on fatal error. */
static int jpssl_hs_step(struct jpssl_sock_ctx *ctx)
{
	switch (ctx->state) {
	case JPSSL_HS_READ_CH: {
		int r = jpssl_hs_recv_msg(ctx, (uint8_t)HandshakeType::CLIENT_HELLO);
		if (r <= 0)
			return r;

		size_t ch_len = 4 + jpssl_msg_len24(ctx->hs_msg.data());
		const uint8_t *ch = ctx->hs_msg.data();
		bool tls13 = jpssl_client_supports_tls13(ch, ch_len);

		if (tls13) {
			std::vector<uint8_t> flight;
			ctx->session.ver = TLSVersion::V13;
			if (!jpssl::tls::tls13_make_server_flight(ctx->session, ch, ch_len,
			                                          flight, *ctx->cert_mgr))
				return -1;
			/* flight = raw ServerHello + encrypted handshake records */
			if (flight.size() < 4 ||
			    flight[0] != (uint8_t)HandshakeType::SERVER_HELLO)
				return -1;
			size_t sh_len = jpssl_msg_len24(flight.data());
			if (flight.size() < 4 + sh_len + 5)
				return -1;

			ctx->txbuf.clear();
			jpssl_make_record(ctx->txbuf, 22, flight.data(), 4 + sh_len);
			ctx->txbuf.insert(ctx->txbuf.end(),
			                  flight.begin() + 4 + sh_len, flight.end());
			ctx->state = JPSSL_HS_READ_FIN;
		} else {
			std::vector<uint8_t> flight;
			ctx->session.ver = TLSVersion::V12;
			if (!jpssl::tls::tls12_make_server_hello_flight(ctx->session, ch,
			                                                ch_len, flight,
			                                                *ctx->cert_mgr,
			                                                nullptr))
				return -1;
			ctx->txbuf.clear();
			jpssl_make_record(ctx->txbuf, 22, flight.data(), flight.size());
			ctx->state = JPSSL_HS_READ_CKE;
		}
		ctx->hs_msg.clear();
		ctx->tx_off = 0;
		return 1;
	}

	case JPSSL_HS_READ_CKE: {
		int r = jpssl_hs_recv_msg(ctx,
		                          (uint8_t)HandshakeType::CLIENT_KEY_EXCHANGE);
		if (r <= 0)
			return r;
		size_t body_len = jpssl_msg_len24(ctx->hs_msg.data());
		const uint8_t *msg = ctx->hs_msg.data();
		/* transcript uses the full handshake message, incl. header */
		jpssl::tls::tls_transcript_update(ctx->session, msg, 4 + body_len);
		std::vector<uint8_t> dummy;
		if (!jpssl::tls::tls12_process_client_key_exchange(ctx->session,
		                                                   msg + 4, body_len,
		                                                   dummy, nullptr))
			return -1;
		ctx->hs_msg.clear();
		ctx->state = JPSSL_HS_READ_CCS;
		return 1;
	}

	case JPSSL_HS_READ_CCS: {
		uint8_t rtype;
		std::vector<uint8_t> payload;
		int r = jpssl_rx_record(ctx, 20, &rtype, payload); /* CCS */
		if (r <= 0)
			return r;
		ctx->state = JPSSL_HS_READ_FIN;
		return 1;
	}

	case JPSSL_HS_READ_FIN: {
		uint8_t rtype;
		std::vector<uint8_t> payload;
		/* TLS 1.3: encrypted Finished travels in an app-data record.
		 * TLS 1.2: encrypted Finished travels in a handshake record. */
		uint8_t allow = (ctx->session.ver == TLSVersion::V13) ? 23 : 22;
		int r = jpssl_rx_record(ctx, allow, &rtype, payload);
		if (r <= 0)
			return r;

		std::vector<uint8_t> rec;
		jpssl_make_record(rec, rtype, payload.data(), payload.size());

		if (ctx->session.ver == TLSVersion::V13) {
			if (!jpssl::tls::tls13_process_client_finished(ctx->session,
			                                               rec.data(),
			                                               rec.size()))
				return -1;
		} else {
			ContentType ct;
			std::vector<uint8_t> plain;
			if (!jpssl::tls::tls_decrypt(ctx->session, rec.data(), rec.size(),
			                             ct, plain))
				return -1;
			if (plain.size() < 4 ||
			    plain[0] != (uint8_t)HandshakeType::FINISHED)
				return -1;
			if (!jpssl::tls::tls12_verify_finished(ctx->session,
			                                       plain.data(), plain.size(),
			                                       false))
				return -1;
			/* server Finished hash must include client Finished */
			jpssl::tls::tls_transcript_update(ctx->session,
			                                  plain.data(), plain.size());

			/* send CCS + encrypted Server Finished */
			ctx->txbuf.clear();
			auto ccs = jpssl::tls::tls_make_change_cipher_spec();
			ctx->txbuf.insert(ctx->txbuf.end(), ccs.begin(), ccs.end());
			auto sf = jpssl::tls::tls12_make_finished(ctx->session, true);
			auto enc = jpssl::tls::tls_encrypt(ctx->session,
			                                  ContentType::HANDSHAKE,
			                                  sf.data(), sf.size());
			if (enc.empty())
				return -1;
			ctx->txbuf.insert(ctx->txbuf.end(), enc.begin(), enc.end());
			ctx->tx_off = 0;
		}
		ctx->state = JPSSL_HS_DONE;
		return 1;
	}

	default:
		return -1;
	}
}

/* Handshake driver.  Returns 1 when the handshake completed, 0 when it is
 * still in progress (or failed).  Mirrors ssl_sock_handshake(). */
static int jpssl_sock_handshake(struct connection *conn, unsigned int flag)
{
	struct jpssl_sock_ctx *ctx = jpssl_conn_ctx(conn);
	int ret;

	if (!conn_ctrl_ready(conn))
		return 0;
	if (!ctx)
		goto out_error;
	if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH | CO_FL_SOCK_WR_SH))
		goto out_error;

	for (;;) {
		if (ctx->state == JPSSL_HS_ERROR)
			goto out_error;

		/* 1) flush pending output first */
		if (ctx->tx_off < ctx->txbuf.size()) {
			ret = jpssl_sock_flush_tx(ctx);
			if (ret == 1)
				return 0;              /* need write */
			if (ret < 0)
				goto out_error;
			continue;
		}

		if (ctx->state == JPSSL_HS_DONE)
			break;

		/* 2) make progress on the current handshake step */
		ret = jpssl_hs_step(ctx);
		if (ret == 1)
			continue;
		if (ret < 0)
			goto out_error;

		/* 3) need more input: refill from the lower layer */
		ret = jpssl_sock_refill_rx(ctx);
		if (ret > 0)
			continue;
		if (ret < 0)
			goto out_error;
		if (conn->flags & (CO_FL_ERROR | CO_FL_SOCK_RD_SH))
			goto out_error;
		if (!(ctx->wait_event.events & SUB_RETRY_RECV))
			ctx->xprt->subscribe(conn, ctx->xprt_ctx, SUB_RETRY_RECV,
			                     &ctx->wait_event);
		return 0;
	}

	/* handshake succeeded */
	conn->flags &= ~(flag | CO_FL_WAIT_L4_CONN | CO_FL_WAIT_L6_CONN);
	return 1;

out_error:
	conn->flags |= CO_FL_ERROR;
	if (!conn->err_code)
		conn->err_code = CO_ER_SSL_HANDSHAKE;
	return 0;
}

/* Tasklet invoked when the lower xprt reports readability/writability or
 * when we want to make the handshake progress. */
extern "C" struct task *ssl_sock_io_cb(struct task *t, void *context,
                                       unsigned int state)
{
	struct tasklet *tl = (struct tasklet *)t;
	struct jpssl_sock_ctx *ctx = static_cast<jpssl_sock_ctx *>(context);
	struct connection *conn = ctx->conn;

	if (conn->flags & CO_FL_SSL_WAIT_HS) {
		jpssl_sock_handshake(conn, CO_FL_SSL_WAIT_HS);
		if (!(conn->flags & CO_FL_SSL_WAIT_HS))
			_HA_ATOMIC_AND(&tl->state, ~TASK_HEAVY);
	} else if (ctx->tx_off < ctx->txbuf.size()) {
		jpssl_sock_flush_tx(ctx);
	}

	if ((conn->flags & CO_FL_ERROR) || !(conn->flags & CO_FL_SSL_WAIT_HS)) {
		if (ctx->subs) {
			tasklet_wakeup(ctx->subs->tasklet);
			ctx->subs->events = 0;
			ctx->subs = NULL;
		}
		if (conn->mux)
			conn->mux->wake(conn);
	}
	return NULL;
}

/* ------------------------------------------------------------------ */
/* xprt_ops callbacks                                                 */
/* ------------------------------------------------------------------ */

static int jpssl_subscribe(struct connection *conn, void *xprt_ctx,
                           int event_type, struct wait_event *es)
{
	struct jpssl_sock_ctx *ctx = static_cast<jpssl_sock_ctx *>(xprt_ctx);

	if (!ctx)
		return -1;
	BUG_ON(event_type & ~(SUB_RETRY_SEND | SUB_RETRY_RECV));
	BUG_ON(ctx->subs && ctx->subs != es);

	ctx->subs = es;
	es->events |= event_type;

	/* forward the subscription to the lower layer unless a handshake is
	 * in progress (the handshake driver subscribes on its own) */
	event_type &= ~ctx->wait_event.events;
	if (event_type && !(conn->flags & CO_FL_SSL_WAIT_HS))
		ctx->xprt->subscribe(conn, ctx->xprt_ctx, event_type,
		                     &ctx->wait_event);
	return 0;
}

static int jpssl_unsubscribe(struct connection *conn, void *xprt_ctx,
                             int event_type, struct wait_event *es)
{
	struct jpssl_sock_ctx *ctx = static_cast<jpssl_sock_ctx *>(xprt_ctx);

	BUG_ON(event_type & ~(SUB_RETRY_SEND | SUB_RETRY_RECV));
	BUG_ON(ctx->subs && ctx->subs != es);

	es->events &= ~event_type;
	if (!es->events)
		ctx->subs = NULL;

	event_type &= ctx->wait_event.events;
	if (event_type && !(conn->flags & CO_FL_SSL_WAIT_HS))
		conn_unsubscribe(conn, ctx->xprt_ctx, event_type, &ctx->wait_event);
	return 0;
}

static int jpssl_takeover(struct connection *conn, void *xprt_ctx,
                          int orig_tid, int release)
{
	struct jpssl_sock_ctx *ctx = static_cast<jpssl_sock_ctx *>(xprt_ctx);
	struct tasklet *tl = NULL;

	if (!release) {
		tl = tasklet_new();
		if (!tl)
			return -1;
	}
	ctx->wait_event.tasklet->context = NULL;
	tasklet_wakeup_on(ctx->wait_event.tasklet, orig_tid);
	if (!release) {
		tl->process = ssl_sock_io_cb;
		tl->context = ctx;
		tl->state |= TASK_HEAVY;
		ctx->wait_event.tasklet = tl;
	} else {
		tasklet_free(ctx->wait_event.tasklet);
		ctx->wait_event.tasklet = NULL;
	}
	return 0;
}

static int jpssl_sock_get_alpn(const struct connection *conn, void *xprt_ctx,
                               const char **str, int *len)
{
	struct jpssl_sock_ctx *ctx = static_cast<jpssl_sock_ctx *>(xprt_ctx);

	if (!ctx || ctx->session.alpn_selected.empty())
		return 0;
	*str = ctx->session.alpn_selected.data();
	*len = (int)ctx->session.alpn_selected.size();
	return 1;
}

/* Copy up to <count> bytes from <data> into HAProxy's <buf> (which may be
 * wrapping).  Returns the number of bytes actually copied. */
static size_t jpssl_buf_put(struct buffer *buf, const uint8_t *data,
                            size_t len, size_t count)
{
	size_t try = b_contig_space(buf);
	if (try > len)
		try = len;
	if (try > count)
		try = count;
	if (!try)
		return 0;
	memcpy(b_tail(buf), data, try);
	b_add(buf, try);
	return try;
}

/* Decrypt incoming records into <buf>.  Handles partial records by keeping
 * the raw bytes in rxbuf and partial plaintext in appbuf. */
static size_t jpssl_sock_to_buf(struct connection *conn, void *xprt_ctx,
                                struct buffer *buf, size_t count,
                                void *msg_control, size_t *msg_controllen,
                                int flags)
{
	struct jpssl_sock_ctx *ctx = static_cast<jpssl_sock_ctx *>(xprt_ctx);
	size_t done = 0;

	if (!ctx)
		goto out_error;
	BUG_ON_HOT(msg_control != NULL);

	if (conn->flags & (CO_FL_WAIT_XPRT | CO_FL_SSL_WAIT_HS))
		return 0;

	/* drain leftover decrypted application data first */
	while (count && ctx->app_off < ctx->appbuf.size()) {
		size_t n = ctx->appbuf.size() - ctx->app_off;
		if (n > count)
			n = count;
		size_t put = jpssl_buf_put(buf, ctx->appbuf.data() + ctx->app_off,
		                           n, count);
		ctx->app_off += put;
		done += put;
		count -= put;
		if (put < n)
			break;
	}
	if (ctx->app_off == ctx->appbuf.size()) {
		ctx->appbuf.clear();
		ctx->app_off = 0;
	}

	while (count) {
		size_t avail = ctx->rxbuf.size() - ctx->rx_off;

		if (avail < 5) {
			/* compact and refill */
			if (ctx->rx_off) {
				ctx->rxbuf.erase(ctx->rxbuf.begin(),
				                 ctx->rxbuf.begin() + ctx->rx_off);
				ctx->rx_off = 0;
			}
			int rd = jpssl_sock_refill_rx(ctx);
			if (rd < 0)
				goto out_error;
			if (rd == 0) {
				if (conn->flags & CO_FL_SOCK_RD_SH)
					goto read0;
				break;               /* EAGAIN */
			}
			avail = ctx->rxbuf.size() - ctx->rx_off;
		}

		const uint8_t *p = ctx->rxbuf.data() + ctx->rx_off;
		size_t rlen = (p[3] << 8) | p[4];
		if (rlen > jpssl::tls::TLS_MAX_RECORD_PLAINTEXT + 256)
			goto out_error;
		if (5 + rlen > avail)
			break;                   /* partial record, wait for more */

		uint8_t type = p[0];
		if (type == 23) {
			std::vector<uint8_t> rec(p, p + 5 + rlen);
			ctx->rx_off += 5 + rlen;

			ContentType ct;
			std::vector<uint8_t> plain;
			if (!jpssl::tls::tls_decrypt(ctx->session, rec.data(), rec.size(),
			                             ct, plain))
				goto out_error;
			if (ct == ContentType::ALERT) {
				if (plain.size() == 2 && plain[1] == 0) /* close_notify */
					goto read0;
				goto out_error;
			}
			if (ct == ContentType::HANDSHAKE) {
				/* post-handshake message (NewSessionTicket, KeyUpdate):
				 * not handled yet, ignore */
				continue;
			}
			if (ct != ContentType::APPLICATION_DATA)
				continue;

			size_t off = 0;
			while (off < plain.size() && count) {
				size_t n = plain.size() - off;
				if (n > count)
					n = count;
				size_t put = jpssl_buf_put(buf, plain.data() + off, n, count);
				off += put;
				done += put;
				count -= put;
				if (put < n)
					break;
			}
			if (off < plain.size()) {
				ctx->appbuf.assign(plain.begin() + off, plain.end());
				ctx->app_off = 0;
			}
		} else if (type == 21) {
			/* plaintext alert (pre-handshake or TLS 1.2) */
			const uint8_t *alert = p + 5;
			ctx->rx_off += 5 + rlen;
			if (rlen == 2 && alert[0] == 1 && alert[1] == 0)
				goto read0;
			goto out_error;
		} else {
			ctx->rx_off += 5 + rlen; /* CCS / unexpected: skip */
		}
	}
	return done;

read0:
	conn_report_term_evt(conn, tevt_loc_xprt, xprt_tevt_type_shutr);
	conn_sock_read0(conn);
	return done;

out_error:
	conn_report_term_evt(conn, tevt_loc_xprt, xprt_tevt_type_rcv_err);
	conn->flags |= CO_FL_ERROR;
	if (!conn->err_code)
		conn->err_code = CO_ER_SSL_FATAL;
	return done;
}

/* Encrypt and send up to <count> bytes from <buf>.  Only plaintext whose
 * encrypted output was fully flushed to the lower layer is reported as
 * consumed; otherwise the amount is remembered in pending_consumed and
 * reported on a later call once the flush completes. */
static size_t jpssl_sock_from_buf(struct connection *conn, void *xprt_ctx,
                                  const struct buffer *buf, size_t count,
                                  void *msg_control, size_t msg_controllen,
                                  int flags)
{
	struct jpssl_sock_ctx *ctx = static_cast<jpssl_sock_ctx *>(xprt_ctx);
	size_t try, done = 0;
	int ret;

	if (!ctx)
		goto out_error;
	BUG_ON_HOT(msg_control != NULL);

	if (conn->flags & (CO_FL_WAIT_XPRT | CO_FL_SSL_WAIT_HS))
		return 0;

	/* previous encrypted chunk still being flushed */
	if (ctx->tx_off < ctx->txbuf.size()) {
		ret = jpssl_sock_flush_tx(ctx);
		if (ret < 0)
			goto out_error;
		if (ret == 1)
			return 0;                /* blocked */
		if (ctx->pending_consumed) {
			done = ctx->pending_consumed;
			ctx->pending_consumed = 0;
		}
		return done;
	}

	/* the previous chunk was fully flushed from the tasklet; report its
	 * consumption now so the caller can advance past it */
	if (ctx->pending_consumed) {
		done = ctx->pending_consumed;
		ctx->pending_consumed = 0;
		return done;
	}

	/* one record-sized chunk at a time */
	try = b_contig_data(buf, 0);
	if (try > count)
		try = count;
	if (try > jpssl::tls::TLS_MAX_RECORD_PLAINTEXT)
		try = jpssl::tls::TLS_MAX_RECORD_PLAINTEXT;
	if (!try)
		return 0;

	auto rec = jpssl::tls::tls_encrypt(ctx->session,
	                                  ContentType::APPLICATION_DATA,
	                                  (const uint8_t *)b_peek(buf, 0), try);
	if (rec.empty())
		goto out_error;

	ctx->txbuf = std::move(rec);
	ctx->tx_off = 0;
	ctx->pending_consumed = try;

	ret = jpssl_sock_flush_tx(ctx);
	if (ret < 0)
		goto out_error;
	if (ret == 1)
		return 0;                    /* blocked; consumed reported later */
	done = ctx->pending_consumed;
	ctx->pending_consumed = 0;
	return done;

out_error:
	conn_report_term_evt(conn, tevt_loc_xprt, xprt_tevt_type_snd_err);
	conn->flags |= CO_FL_ERROR;
	if (!conn->err_code)
		conn->err_code = CO_ER_SSL_FATAL;
	return done;
}

static void jpssl_sock_shutw(struct connection *conn, void *xprt_ctx, int clean)
{
	struct jpssl_sock_ctx *ctx = static_cast<jpssl_sock_ctx *>(xprt_ctx);
	uint8_t alert[2] = { 1 /* warning */, 0 /* close_notify */ };
	std::vector<uint8_t> rec;

	if (!ctx)
		return;
	if (conn->flags & (CO_FL_WAIT_XPRT | CO_FL_SSL_WAIT_HS))
		return;

	conn_report_term_evt(conn, tevt_loc_xprt, xprt_tevt_type_shutw);

	/* best-effort close_notify; TLS 1.2+ sends it encrypted */
	if (ctx->session.ver == TLSVersion::V12 || ctx->session.ver == TLSVersion::V13)
		rec = jpssl::tls::tls_encrypt(ctx->session, ContentType::ALERT,
		                              alert, sizeof(alert));
	if (rec.empty())
		rec = jpssl::tls::tls_make_alert(AlertLevel::WARNING,
		                                 AlertDescription::CLOSE_NOTIFY);
	if (!rec.empty()) {
		struct buffer tmpbuf;
		tmpbuf.size = rec.size();
		tmpbuf.area = (char *)rec.data();
		tmpbuf.data = rec.size();
		tmpbuf.head = 0;
		ctx->xprt->snd_buf(conn, ctx->xprt_ctx, &tmpbuf, rec.size(),
		                   NULL, 0, 0);
	}
}

static void jpssl_sock_close(struct connection *conn, void *xprt_ctx)
{
	struct jpssl_sock_ctx *ctx = static_cast<jpssl_sock_ctx *>(xprt_ctx);

	if (!ctx)
		return;
	if (ctx->wait_event.events != 0)
		ctx->xprt->unsubscribe(ctx->conn, ctx->xprt_ctx,
		                       ctx->wait_event.events, &ctx->wait_event);
	if (ctx->subs) {
		ctx->subs->events = 0;
		tasklet_wakeup(ctx->subs->tasklet);
	}
	if (ctx->xprt->close)
		ctx->xprt->close(conn, ctx->xprt_ctx);
	if (ctx->wait_event.tasklet)
		tasklet_free(ctx->wait_event.tasklet);
	delete ctx;
	_HA_ATOMIC_DEC(&global.sslconns);
}

/* xprt init: allocate the context and start the handshake.  Only the
 * listener (frontend) path is implemented for now. */
static int jpssl_sock_init(struct connection *conn, void **xprt_ctx)
{
	struct jpssl_sock_ctx *ctx;
	struct bind_conf *bc;
	jpssl_bind_ctx *bctx;

	if (*xprt_ctx)
		return 0;

	if (!objt_listener(conn->target)) {
		/* TODO: outbound (connect) mode with jpssl::tls::tls13_make_client_hello()
		 * and tls13_process_server_flight() */
		conn->err_code = CO_ER_SSL_NO_TARGET;
		return -1;
	}
	bc = __objt_listener(conn->target)->bind_conf;
	bctx = jpssl_bind_ctx_lookup(bc);
	if (!bctx || !bctx->cert_mgr.count()) {
		conn->err_code = CO_ER_SSL_HANDSHAKE;
		return -1;
	}

	ctx = new (std::nothrow) jpssl_sock_ctx();
	if (!ctx) {
		conn->err_code = CO_ER_SSL_NO_MEM;
		return -1;
	}
	ctx->wait_event.tasklet = tasklet_new();
	if (!ctx->wait_event.tasklet) {
		conn->err_code = CO_ER_SSL_NO_MEM;
		delete ctx;
		return -1;
	}
	ctx->wait_event.tasklet->process = ssl_sock_io_cb;
	ctx->wait_event.tasklet->context = ctx;
	ctx->wait_event.tasklet->state |= TASK_HEAVY;
	ctx->wait_event.events = 0;
	ctx->conn = conn;
	ctx->subs = NULL;
	ctx->xprt_ctx = NULL;

	/* stack over the raw transport */
	ctx->xprt = xprt_get(XPRT_RAW);
	if (!ctx->xprt)
		goto err;
	if (ctx->xprt->init && ctx->xprt->init(conn, &ctx->xprt_ctx) != 0)
		goto err;

	/* JPSSL session setup (server side) */
	ctx->session.is_server = true;
	ctx->session.ver = TLSVersion::V12;
	ctx->session.alpn_protos = bctx->alpn;
	ctx->cert_mgr = &bctx->cert_mgr;
	ctx->state = JPSSL_HS_READ_CH;

	/* leave init state and start the handshake */
	conn->flags |= CO_FL_SSL_WAIT_HS | CO_FL_WAIT_L6_CONN;
	_HA_ATOMIC_INC(&global.sslconns);
	_HA_ATOMIC_INC(&global.totalsslconns);
	*xprt_ctx = ctx;
	return 0;

err:
	tasklet_free(ctx->wait_event.tasklet);
	delete ctx;
	return -1;
}

static int jpssl_sock_start(struct connection *conn, void *xprt_ctx)
{
	struct jpssl_sock_ctx *ctx = static_cast<jpssl_sock_ctx *>(xprt_ctx);

	if (ctx)
		tasklet_wakeup(ctx->wait_event.tasklet);
	return 0;
}

static int jpssl_sock_prepare_bind_conf(struct bind_conf *bc)
{
	jpssl_bind_ctx *bctx;

	{
		std::lock_guard<std::mutex> lock(jpssl_bind_lock);
		auto &slot = jpssl_bind_ctxs[bc];
		if (!slot)
			slot.reset(new jpssl_bind_ctx());
		bctx = slot.get();
	}

	if (!bctx->cert_mgr.count()) {
		ha_alert("jpssl: bind '%s' at [%s:%d] has no certificate; use "
		         "'jpssl cert <cert> [<key>]'.\n",
		         bc->arg, bc->file, bc->line);
		return -1;
	}

	/* decode the ALPN wire-format list ([len][proto]...) produced by
	 * ssl_sock_parse_alpn() into jpssl's vector<string> */
	bctx->alpn.clear();
	if (bc->ssl_conf.alpn_str && bc->ssl_conf.alpn_len > 0) {
		const char *p = bc->ssl_conf.alpn_str;
		int remain = bc->ssl_conf.alpn_len;
		while (remain > 0) {
			uint8_t l = (uint8_t)*p++;
			remain--;
			if (l > remain)
				break;
			bctx->alpn.emplace_back(p, l);
			p += l;
			remain -= l;
		}
	}
	return 0;
}

static void jpssl_sock_destroy_bind_conf(struct bind_conf *bc)
{
	std::lock_guard<std::mutex> lock(jpssl_bind_lock);
	jpssl_bind_ctxs.erase(bc);
}

static int jpssl_sock_show_fd(struct buffer *buf, const struct connection *conn,
                              const void *xprt_ctx)
{
	const struct jpssl_sock_ctx *ctx =
		static_cast<const struct jpssl_sock_ctx *>(xprt_ctx);

	chunk_appendf(buf, " state=%d", ctx ? (int)ctx->state : -1);
	return 0;
}

/* transport-layer operations for SSL sockets (JPSSL backend) */
extern "C" struct xprt_ops ssl_sock = {
	.rcv_buf      = jpssl_sock_to_buf,
	.snd_buf      = jpssl_sock_from_buf,
	.rcv_pipe     = NULL,
	.snd_pipe     = NULL,
	.shutr        = NULL,
	.shutw        = jpssl_sock_shutw,
	.close        = jpssl_sock_close,
	.init         = jpssl_sock_init,
	.start        = jpssl_sock_start,
	.prepare_bind_conf = jpssl_sock_prepare_bind_conf,
	.destroy_bind_conf = jpssl_sock_destroy_bind_conf,
	.prepare_srv  = NULL,
	.destroy_srv  = NULL,
	.get_alpn     = jpssl_sock_get_alpn,
	.takeover     = jpssl_takeover,
	.set_idle     = NULL,
	.set_used     = NULL,
	.name         = "SSL",
	.subscribe    = jpssl_subscribe,
	.unsubscribe  = jpssl_unsubscribe,
	.remove_xprt  = NULL,
	.add_xprt     = NULL,
	.get_ssl_sock_ctx = NULL,
	.show_fd      = jpssl_sock_show_fd,
	.dump_info    = NULL,
	.get_capability = NULL,
};

/* ------------------------------------------------------------------ */
/* Helpers exported for sample fetches / logs (JPSSL equivalents)     */
/* ------------------------------------------------------------------ */

extern "C" const char *ssl_sock_get_proto_version(struct connection *conn)
{
	struct jpssl_sock_ctx *ctx = jpssl_conn_ctx(conn);

	if (!ctx)
		return NULL;
	switch (ctx->session.ver) {
	case TLSVersion::V12: return "TLSv1.2";
	case TLSVersion::V13: return "TLSv1.3";
	default:              return NULL;
	}
}

extern "C" const char *ssl_sock_get_cipher_name(struct connection *conn)
{
	struct jpssl_sock_ctx *ctx = jpssl_conn_ctx(conn);

	if (!ctx)
		return NULL;
	switch (ctx->session.cipher_suite) {
	case CipherSuite::TLS_AES_128_GCM_SHA256: return "TLS_AES_128_GCM_SHA256";
	case CipherSuite::TLS_AES_256_GCM_SHA384: return "TLS_AES_256_GCM_SHA384";
	case CipherSuite::TLS_CHACHA20_POLY1305_SHA256: return "TLS_CHACHA20_POLY1305_SHA256";
	case CipherSuite::TLS_AES_128_CCM_SHA256: return "TLS_AES_128_CCM_SHA256";
	case CipherSuite::TLS_AES_128_CCM_8_SHA256: return "TLS_AES_128_CCM_8_SHA256";
	case CipherSuite::TLS_SM4_GCM_SM3: return "TLS_SM4_GCM_SM3";
	case CipherSuite::TLS_SM4_CCM_SM3: return "TLS_SM4_CCM_SM3";
	case CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: return "ECDHE-RSA-AES128-GCM-SHA256";
	case CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: return "ECDHE-RSA-AES256-GCM-SHA384";
	case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: return "ECDHE-ECDSA-AES128-GCM-SHA256";
	case CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: return "ECDHE-ECDSA-AES256-GCM-SHA384";
	default: return "UNKNOWN";
	}
}

extern "C" const char *ssl_sock_get_sni(struct connection *conn)
{
	struct jpssl_sock_ctx *ctx = jpssl_conn_ctx(conn);

	if (!ctx || ctx->session.server_name.empty())
		return NULL;
	return ctx->session.server_name.c_str();
}

/* ------------------------------------------------------------------ */
/* Registration                                                       */
/* ------------------------------------------------------------------ */

/* Register a certificate (+ optional key) for a bind_conf.  This is the
 * JPSSL-side hook that the future config glue (crt/crt-list parsing) will
 * call; it can also be used from tests. */
extern "C" int jpssl_sock_set_certfile(struct bind_conf *bc,
                                       const char *cert_path,
                                       const char *key_path)
{
	std::string err;
	auto cert = jpssl::tls::tls_certificate::from_pem_file(cert_path,
	                                                       key_path, &err);
	if (!cert) {
		ha_alert("jpssl: failed to load certificate '%s' (key '%s'): %s\n",
		         cert_path, key_path ? key_path : "", err.c_str());
		return -1;
	}

	std::string domain = cert->subject_name.empty() ? "default"
	                                                 : cert->subject_name;
	{
		std::lock_guard<std::mutex> lock(jpssl_bind_lock);
		auto &slot = jpssl_bind_ctxs[bc];
		if (!slot)
			slot.reset(new jpssl_bind_ctx());
		slot->cert_mgr.add_certificate(domain, std::move(cert));
	}
	return 0;
}

/* Return the JPSSL certificate manager attached to <bc>, or NULL.  Used by
 * the QUIC backend (quic_ssl.cpp) to share the same certificate registry. */
extern "C" const void *jpssl_sock_get_cert_mgr(struct bind_conf *bc)
{
	jpssl_bind_ctx *bctx = jpssl_bind_ctx_lookup(bc);

	return bctx ? &bctx->cert_mgr : NULL;
}

static void __jpssl_sock_init(void)
{
	xprt_register(XPRT_SSL, &ssl_sock);
	global.ssl_session_max_cost = 32 * 1024; /* rough per-conn cost */
	global.ssl_handshake_max_cost = 16 * 1024;
}
INITCALL0(STG_REGISTER, __jpssl_sock_init);

#endif /* USE_JPSSL */
