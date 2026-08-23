/*
 * src/quic_ssl.cpp
 *
 * QUIC TLS handshake layer backed by JPSSL.
 *
 * Drop-in replacement for src/quic_ssl.c used when USE_JPSSL is set.  The
 * exported entry points (qc_alloc_ssl_sock_ctx(), qc_ssl_provide_all_quic_data(),
 * qc_ssl_do_hanshake(), ...) keep the same signatures so that quic_conn.c,
 * xprt_quic.c and friends compile and link unchanged, but the handshake is
 * driven by jpssl::tls::tls_session in QUIC mode instead of OpenSSL's
 * SSL_QUIC_METHOD callbacks:
 *
 *   - tls_quic_make_server_flight() produces the whole server flight; the
 *     ServerHello part goes to the INITIAL encryption level and the
 *     encrypted extension/cert/verify/finished part to the HANDSHAKE level.
 *   - the handshake traffic secrets (jpssl quic_secrets_block) are installed
 *     into the HANDSHAKE quic_tls_ctx, and the application traffic secrets
 *     into the APPLICATION one (both needed for key update).
 *   - tls_quic_process_client_finished() validates the client Finished.
 *
 * Only the listener (frontend/server) path is implemented at this stage;
 * 0-RTT is not handled yet.
 *
 * Copyright (C) 2026 DaChengTechnology
 */

#ifdef USE_JPSSL

extern "C" {
#include <haproxy/errors.h>
#include <haproxy/ncbmbuf.h>
#include <haproxy/proxy.h>
#include <haproxy/quic_conn.h>
#include <haproxy/quic_sock.h>
#include <haproxy/quic_ssl.h>
#include <haproxy/quic_stats.h>
#include <haproxy/quic_tls.h>
#include <haproxy/quic_tp.h>
#include <haproxy/quic_trace.h>
#include <haproxy/ssl_sock.h>
#include <haproxy/trace.h>
}

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "tls.hpp"

using jpssl::tls::CipherSuite;
using jpssl::tls::HandshakeType;
using jpssl::tls::TLSVersion;

extern "C" {

DECLARE_TYPED_POOL(pool_head_quic_ssl_sock_ctx, "quic_ssl_sock_ctx",
                   struct ssl_sock_ctx);

const char *default_quic_ciphersuites = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384"
                           ":TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256";
const char *default_quic_curves = "X25519:P-256:P-384:P-521";

/* Certificate manager accessor exported by the JPSSL ssl_sock backend. */
extern "C" const void *jpssl_sock_get_cert_mgr(struct bind_conf *bc);

/* ------------------------------------------------------------------ */
/* Per-connection JPSSL QUIC session                                  */
/* ------------------------------------------------------------------ */
struct quic_jpssl_ctx {
	jpssl::tls::tls_session session;
	/* CRYPTO bytes received from the peer, in handshake-message order
	 * (INITIAL level first, then HANDSHAKE level). */
	std::vector<uint8_t> hs_buf;
	bool ch_ready  = false;   /* server flight emitted                */
	bool fin_ready = false;   /* client Finished processed            */
	bool done      = false;   /* handshake fully completed            */
};

static std::mutex jpssl_quic_ssl_lock;
static std::map<struct ssl_sock_ctx *, std::unique_ptr<quic_jpssl_ctx>>
	jpssl_quic_ssl_ctxs;

static quic_jpssl_ctx *jpssl_quic_ssl_lookup(struct ssl_sock_ctx *ctx)
{
	std::lock_guard<std::mutex> lock(jpssl_quic_ssl_lock);
	auto it = jpssl_quic_ssl_ctxs.find(ctx);
	return it != jpssl_quic_ssl_ctxs.end() ? it->second.get() : nullptr;
}

/* Release the JPSSL QUIC handshake context and the ssl_sock_ctx it was
 * attached to (used by qc_free_ssl_sock_ctx() under USE_JPSSL). */
extern "C" void qc_jpssl_free_ctx(struct ssl_sock_ctx *ctx)
{
	if (!ctx)
		return;
	{
		std::lock_guard<std::mutex> lock(jpssl_quic_ssl_lock);
		jpssl_quic_ssl_ctxs.erase(ctx);
	}
	pool_free(pool_head_quic_ssl_sock_ctx, ctx);
}

/* ------------------------------------------------------------------ */
/* CRYPTO buffering (same logic as the OpenSSL implementation)        */
/* ------------------------------------------------------------------ */
static int qc_ssl_crypto_data_cpy(struct quic_conn *qc, struct quic_enc_level *qel,
                                  const unsigned char *data, size_t len)
{
	struct quic_crypto_buf **qcb;
	size_t cf_offset, cf_len, *nb_buf;
	unsigned char *pos;
	int ret = 0;

	nb_buf = &qel->tx.crypto.nb_buf;
	qcb = &qel->tx.crypto.bufs[*nb_buf - 1];
	cf_offset = (*nb_buf - 1) * QUIC_CRYPTO_BUF_SZ + (*qcb)->sz;
	cf_len = len;

	while (len) {
		size_t to_copy, room;

		pos = (*qcb)->data + (*qcb)->sz;
		room = QUIC_CRYPTO_BUF_SZ - (*qcb)->sz;
		to_copy = len > room ? room : len;
		if (to_copy) {
			memcpy(pos, data, to_copy);
			qel->tx.crypto.sz += to_copy;
			(*qcb)->sz += to_copy;
			len -= to_copy;
			data += to_copy;
		} else {
			struct quic_crypto_buf **tmp;

			tmp = (struct quic_crypto_buf **)realloc(qel->tx.crypto.bufs,
			       (*nb_buf + 1) * sizeof *qel->tx.crypto.bufs);
			if (!tmp)
				break;
			qel->tx.crypto.bufs = tmp;
			qcb = &qel->tx.crypto.bufs[*nb_buf];
			*qcb = (struct quic_crypto_buf *)pool_alloc(pool_head_quic_crypto_buf);
			if (!*qcb)
				goto leave;
			(*qcb)->sz = 0;
			++*nb_buf;
		}
	}

	if (!len) {
		struct quic_frame *frm;
		struct quic_frame *found = NULL;

		list_for_each_entry(frm, &qel->pktns->tx.frms, list) {
			if (frm->type != QUIC_FT_CRYPTO)
				continue;
			found = frm;
			break;
		}
		if (found) {
			found->crypto.len += cf_len;
		} else {
			frm = qc_frm_alloc(QUIC_FT_CRYPTO);
			if (!frm)
				goto leave;
			frm->crypto.offset_node.key = cf_offset;
			frm->crypto.len = cf_len;
			frm->crypto.qel = qel;
			LIST_APPEND(&qel->pktns->tx.frms, &frm->list);
		}
	}
	ret = len == 0;
leave:
	return ret;
}

/* ------------------------------------------------------------------ */
/* Secret installation                                                */
/* ------------------------------------------------------------------ */
static void jpssl_quic_set_descs(struct quic_tls_secrets *secs,
                                 CipherSuite cs)
{
	switch (cs) {
	case CipherSuite::TLS_AES_256_GCM_SHA384:
		secs->aead = EVP_aes_256_gcm();
		secs->md   = EVP_sha384();
		secs->hp   = EVP_aes_256_ctr();
		break;
	case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
		secs->aead = EVP_chacha20_poly1305();
		secs->md   = EVP_sha256();
		secs->hp   = EVP_chacha20();
		break;
	case CipherSuite::TLS_AES_128_CCM_SHA256:
		secs->aead = EVP_aes_128_ccm();
		secs->md   = EVP_sha256();
		secs->hp   = EVP_aes_128_ctr();
		break;
	default: /* TLS_AES_128_GCM_SHA256 and friends */
		secs->aead = EVP_aes_128_gcm();
		secs->md   = EVP_sha256();
		secs->hp   = EVP_aes_128_ctr();
		break;
	}
}

static const struct quic_version *jpssl_quic_version(struct quic_conn *qc)
{
	return qc->negotiated_version ? qc->negotiated_version
	                              : qc->original_version;
}

/* Install the packet-protection keys for <qel> from the JPSSL traffic
 * secrets <rx_secret>/<tx_secret> (client/server direction) of <slen>
 * bytes each.  Returns 1 on success. */
static int jpssl_quic_install_secrets(struct quic_conn *qc,
                                      struct quic_enc_level *qel,
                                      const unsigned char *rx_secret,
                                      const unsigned char *tx_secret,
                                      size_t slen)
{
	struct quic_tls_ctx *tls_ctx = &qel->tls_ctx;
	struct quic_tls_secrets *rx = &tls_ctx->rx;
	struct quic_tls_secrets *tx = &tls_ctx->tx;
	const struct quic_version *ver = jpssl_quic_version(qc);

	if (!rx->aead) {
		/* descriptors must have been filled by the caller */
		return 0;
	}
	if (!quic_tls_secrets_keys_alloc(rx) ||
	    !quic_tls_secrets_keys_alloc(tx))
		return 0;

	if (!quic_tls_derive_keys(rx->aead, rx->hp, rx->md, ver,
	                          rx->key, rx->keylen, rx->iv, rx->ivlen,
	                          rx->hp_key, sizeof(rx->hp_key),
	                          rx_secret, slen) ||
	    !quic_tls_derive_keys(tx->aead, tx->hp, tx->md, ver,
	                          tx->key, tx->keylen, tx->iv, tx->ivlen,
	                          tx->hp_key, sizeof(tx->hp_key),
	                          tx_secret, slen))
		return 0;

	if (!quic_tls_rx_ctx_init(&rx->ctx, rx->aead, rx->key) ||
	    !quic_tls_dec_hp_ctx_init(&rx->hp_ctx, rx->hp, rx->hp_key) ||
	    !quic_tls_tx_ctx_init(&tx->ctx, tx->aead, tx->key) ||
	    !quic_tls_enc_hp_ctx_init(&tx->hp_ctx, tx->hp, tx->hp_key))
		return 0;

	/* keep the traffic secrets for key update */
	rx->secret = (unsigned char *)pool_alloc(pool_head_quic_tls_secret);
	tx->secret = (unsigned char *)pool_alloc(pool_head_quic_tls_secret);
	if (!rx->secret || !tx->secret)
		return 0;
	memcpy(rx->secret, rx_secret, slen);
	memcpy(tx->secret, tx_secret, slen);
	rx->secretlen = tx->secretlen = slen;
	return 1;
}

/* Install the HANDSHAKE-level keys from the session traffic secrets. */
static int jpssl_quic_install_handshake_secrets(struct quic_conn *qc,
                                                quic_jpssl_ctx *jctx)
{
	struct quic_enc_level *qel = qc->hel;
	size_t hl;

	if (!qel || !jctx->session.quic_secrets)
		return 0;
	jpssl_quic_set_descs(&qel->tls_ctx.rx, jctx->session.cipher_suite);
	jpssl_quic_set_descs(&qel->tls_ctx.tx, jctx->session.cipher_suite);
	hl = jpssl::tls::tls_hash_len(jctx->session.cipher_suite);
	return jpssl_quic_install_secrets(qc, qel,
	                                  jctx->session.quic_secrets->client_hs,
	                                  jctx->session.quic_secrets->server_hs,
	                                  hl);
}

/* Install the APPLICATION-level keys and prepare the key-update phase. */
static int jpssl_quic_install_app_secrets(struct quic_conn *qc,
                                          quic_jpssl_ctx *jctx)
{
	struct quic_enc_level *qel;
	size_t hl;

	if (!qc->ael &&
	    !qc_enc_level_alloc(qc, &qc->apktns, &qc->ael,
	                        ssl_encryption_application))
		return 0;
	qel = qc->ael;
	if (!jctx->session.quic_secrets)
		return 0;
	jpssl_quic_set_descs(&qel->tls_ctx.rx, jctx->session.cipher_suite);
	jpssl_quic_set_descs(&qel->tls_ctx.tx, jctx->session.cipher_suite);
	hl = jpssl::tls::tls_hash_len(jctx->session.cipher_suite);
	if (!jpssl_quic_install_secrets(qc, qel,
	                                jctx->session.quic_secrets->client_app,
	                                jctx->session.quic_secrets->server_app,
	                                hl))
		return 0;
	qc->ku.prv_rx.secretlen = qc->ku.nxt_rx.secretlen =
		qc->ku.nxt_tx.secretlen = hl;
	return 1;
}

/* Fill the JPSSL transport parameters sent by this server from the
 * HAProxy-configured <qp> parameters. */
static void jpssl_quic_tp_from_haproxy(struct quic_conn *qc,
                                       jpssl::tls::quic_transport_parameters& tp)
{
	const struct quic_transport_params *qp = &qc->rx.params;

	tp.max_idle_timeout = qp->max_idle_timeout;
	tp.max_udp_payload_size = qp->max_udp_payload_size;
	tp.initial_max_data = qp->initial_max_data;
	tp.initial_max_stream_data_bidi_local = qp->initial_max_stream_data_bidi_local;
	tp.initial_max_stream_data_bidi_remote = qp->initial_max_stream_data_bidi_remote;
	tp.initial_max_stream_data_uni = qp->initial_max_stream_data_uni;
	tp.initial_max_streams_bidi = qp->initial_max_streams_bidi;
	tp.initial_max_streams_uni = qp->initial_max_streams_uni;
	tp.ack_delay_exponent = qp->ack_delay_exponent;
	tp.max_ack_delay = qp->max_ack_delay;
	tp.active_connection_id_limit = qp->active_connection_id_limit;
	tp.disable_active_migration = qp->disable_active_migration != 0;
	if (qp->original_destination_connection_id_present)
		tp.original_destination_connection_id.assign(
			qp->original_destination_connection_id.data,
			qp->original_destination_connection_id.data +
			qp->original_destination_connection_id.len);
	if (qp->initial_source_connection_id_present)
		tp.initial_source_connection_id.assign(
			qp->initial_source_connection_id.data,
			qp->initial_source_connection_id.data +
			qp->initial_source_connection_id.len);
	if (qp->with_stateless_reset_token)
		tp.stateless_reset_token.assign(qp->stateless_reset_token,
		                                qp->stateless_reset_token +
		                                QUIC_STATELESS_RESET_TOKEN_LEN);
}

/* Decode the bind ALPN wire-format list into jpssl's vector<string>. */
static void jpssl_quic_set_alpn(struct bind_conf *bc, quic_jpssl_ctx *jctx)
{
	if (!bc->ssl_conf.alpn_str || bc->ssl_conf.alpn_len <= 0)
		return;
	const char *p = bc->ssl_conf.alpn_str;
	int remain = bc->ssl_conf.alpn_len;
	while (remain > 0) {
		uint8_t l = (uint8_t)*p++;
		remain--;
		if (l > remain)
			break;
		jctx->session.alpn_protos.emplace_back(p, l);
		p += l;
		remain -= l;
	}
}

/* ------------------------------------------------------------------ */
/* xprt-level entry points                                            */
/* ------------------------------------------------------------------ */

int qc_alloc_ssl_sock_ctx(struct quic_conn *qc, void *target)
{
	struct ssl_sock_ctx *ctx = NULL;
	struct bind_conf *bc;
	quic_jpssl_ctx *jctx;
	const jpssl::tls::tls_certificate_manager *cert_mgr;

	if (qc_is_back(qc)) {
		/* TODO: outbound (client) mode with tls_quic_make_client_hello() */
		TRACE_ERROR("JPSSL QUIC client mode not implemented",
		            QUIC_EV_CONN_NEW, qc);
		goto err;
	}

	ctx = (struct ssl_sock_ctx *)pool_alloc(pool_head_quic_ssl_sock_ctx);
	if (!ctx)
		goto err;

	ctx->conn = NULL;
	ctx->ssl = NULL;
	ctx->bio = NULL;
	ctx->xprt = NULL;
	ctx->xprt_ctx = NULL;
	memset(&ctx->wait_event, 0, sizeof(ctx->wait_event));
	ctx->subs = NULL;
	ctx->xprt_st = 0;
	ctx->error_code = 0;
	ctx->early_buf = BUF_NULL;
	ctx->sent_early_data = 0;
	ctx->qc = qc;

	bc = __objt_listener(target)->bind_conf;
	cert_mgr = (const jpssl::tls::tls_certificate_manager *)
		jpssl_sock_get_cert_mgr(bc);
	if (!cert_mgr)
		goto err;

	jctx = new (std::nothrow) quic_jpssl_ctx();
	if (!jctx)
		goto err;

	jctx->session.is_server = true;
	jctx->session.quic_mode = true;
	jctx->session.ver = TLSVersion::V13;
	jpssl_quic_tp_from_haproxy(qc, jctx->session.quic_transport_params);
	jpssl_quic_set_alpn(bc, jctx);
	jctx->session.quic_version =
		(qc->negotiated_version && qc->negotiated_version->num == 0x6b3343cf) ?
		jpssl::tls::QuicVersion::V2 : jpssl::tls::QuicVersion::V1;

	{
		std::lock_guard<std::mutex> lock(jpssl_quic_ssl_lock);
		jpssl_quic_ssl_ctxs[ctx] = std::unique_ptr<quic_jpssl_ctx>(jctx);
	}
	qc->xprt_ctx = ctx;
	_HA_ATOMIC_INC(&global.totalsslconns);
	return 1;

err:
	if (ctx)
		pool_free(pool_head_quic_ssl_sock_ctx, ctx);
	return 0;
}

/* Retrieve the JPSSL session attached to <ctx>. */
static quic_jpssl_ctx *jpssl_quic_ssl_get(struct ssl_sock_ctx *ctx)
{
	return jpssl_quic_ssl_lookup(ctx);
}

/* Driver for the JPSSL QUIC handshake.  Returns 1 on success, 0 on error. */
int qc_ssl_do_hanshake(struct quic_conn *qc, struct ssl_sock_ctx *ctx)
{
	quic_jpssl_ctx *jctx = jpssl_quic_ssl_get(ctx);
	struct bind_conf *bc;
	const jpssl::tls::tls_certificate_manager *cert_mgr;
	int ret = 1;

	if (!jctx || qc_is_back(qc))
		return 0;
	if (jctx->done)
		return 1;

	bc = qc->li->bind_conf;
	cert_mgr = (const jpssl::tls::tls_certificate_manager *)
		jpssl_sock_get_cert_mgr(bc);
	if (!cert_mgr)
		goto err;

	/* 1) server flight from the ClientHello */
	if (!jctx->ch_ready) {
		std::vector<uint8_t> &hs = jctx->hs_buf;
		if (hs.size() < 4 || hs[0] != (uint8_t)HandshakeType::CLIENT_HELLO)
			goto out;               /* wait for more CRYPTO data */
		size_t ch_len = ((size_t)hs[1] << 16) | ((size_t)hs[2] << 8) | hs[3];
		if (hs.size() < 4 + ch_len)
			goto out;               /* incomplete ClientHello */

		std::vector<uint8_t> flight;
		if (!jpssl::tls::tls_quic_make_server_flight(jctx->session,
		                                             hs.data(), 4 + ch_len,
		                                             flight, *cert_mgr))
			goto err;
		if (flight.size() < 4 ||
		    flight[0] != (uint8_t)HandshakeType::SERVER_HELLO)
			goto err;
		size_t sh_len = ((size_t)flight[1] << 16) |
		                ((size_t)flight[2] << 8) | flight[3];
		if (flight.size() < 4 + sh_len)
			goto err;

		/* ServerHello -> INITIAL encryption level */
		if (!qc->iel &&
		    !qc_enc_level_alloc(qc, &qc->ipktns, &qc->iel,
		                        ssl_encryption_initial))
			goto err;
		if (!qc_ssl_crypto_data_cpy(qc, qc->iel, flight.data(), 4 + sh_len))
			goto err;

		/* EE + Cert + CV + Finished -> HANDSHAKE level */
		if (!qc->hel &&
		    !qc_enc_level_alloc(qc, &qc->hpktns, &qc->hel,
		                        ssl_encryption_handshake))
			goto err;
		if (!qc_ssl_crypto_data_cpy(qc, qc->hel, flight.data() + 4 + sh_len,
		                            flight.size() - 4 - sh_len))
			goto err;

		/* install the handshake packet-protection keys */
		if (!jctx->session.quic_secrets ||
		    !jpssl_quic_install_handshake_secrets(qc, jctx))
			goto err;

		/* negotiate ALPN (frontend) */
		if (!jctx->session.alpn_selected.empty() &&
		    !qc_register_alpn(qc, jctx->session.alpn_selected.data(),
		                      (int)jctx->session.alpn_selected.size()))
			goto err;

		hs.erase(hs.begin(), hs.begin() + 4 + ch_len);
		jctx->ch_ready = true;
	}

	/* 2) client Finished -> application keys + completion */
	if (jctx->ch_ready && !jctx->fin_ready) {
		std::vector<uint8_t> &hs = jctx->hs_buf;
		size_t off = 0;
		bool found = false;

		/* scan for a complete Finished handshake message */
		while (hs.size() - off >= 4) {
			size_t mlen = ((size_t)hs[off + 1] << 16) |
			              ((size_t)hs[off + 2] << 8) | hs[off + 3];
			if (hs.size() - off < 4 + mlen)
				break;
			if (hs[off] == (uint8_t)HandshakeType::FINISHED) {
				if (!jpssl::tls::tls_quic_process_client_finished(
					    jctx->session, hs.data() + off, 4 + mlen))
					goto err;
				found = true;
			}
			off += 4 + mlen;
		}
		if (!found)
			goto out;               /* wait for more CRYPTO data */

		if (!jctx->session.quic_secrets ||
		    !jpssl_quic_install_app_secrets(qc, jctx))
			goto err;

		hs.erase(hs.begin(), hs.begin() + off);
		jctx->fin_ready = true;
		jctx->done = true;

		/* -- handshake completion, mirroring qc_ssl_do_hanshake() -- */
		if (!qc->alpn) {
			quic_set_tls_alert(qc, SSL_AD_NO_APPLICATION_PROTOCOL);
			goto err;
		}
		qc->flags |= QUIC_FL_CONN_NEED_POST_HANDSHAKE_FRMS;
		qc->wait_event.tasklet->process = quic_conn_app_io_cb;
		qc->state = QUIC_HS_ST_CONFIRMED;

		if (!(qc->flags & QUIC_FL_CONN_ACCEPT_REGISTERED)) {
			quic_accept_push_qc(qc);
		} else {
			tasklet_wakeup(qc->wait_event.tasklet);
		}
		if (qc->li->rx.quic_curr_handshake > 0)
			HA_ATOMIC_DEC(&qc->li->rx.quic_curr_handshake);

		/* prepare the next key update */
		if (!quic_tls_key_update(qc))
			goto err;
	}

	ret = 1;
out:
	return ret;
err:
	ret = 0;
	HA_ATOMIC_INC(&qc->prx_counters->hdshk_fail);
	quic_set_tls_alert(qc, SSL_AD_HANDSHAKE_FAILURE);
	goto out;
}

/* Provide all stored in-order CRYPTO data to the JPSSL session. */
int qc_ssl_provide_all_quic_data(struct quic_conn *qc, struct ssl_sock_ctx *ctx)
{
	quic_jpssl_ctx *jctx = jpssl_quic_ssl_get(ctx);
	struct quic_enc_level *qel;

	if (!jctx)
		return 0;

	list_for_each_entry(qel, &qc->qel_list, list) {
		struct quic_cstream *cstream = qel->cstream;
		struct ncbmbuf *ncbuf;
		ncb_sz_t data;

		if (!cstream)
			continue;
		ncbuf = &cstream->rx.ncbuf;
		if (ncbmb_is_null(ncbuf))
			continue;
		while ((data = ncbmb_data(ncbuf, 0))) {
			const unsigned char *cdata =
				(const unsigned char *)ncbmb_head(ncbuf);
			BUG_ON(cdata + data >=
			       (const unsigned char *)ncbmb_wrap(ncbuf));
			jctx->hs_buf.insert(jctx->hs_buf.end(), cdata, cdata + data);
			cstream->rx.offset += data;
			ncbmb_advance(ncbuf, data);
		}
		if (ncbmb_is_empty(ncbuf))
			quic_free_ncbuf(ncbuf);
	}

	return qc_ssl_do_hanshake(qc, ctx);
}

/* Minimal context setup: certificates are provided through the JPSSL
 * bind_conf registry (jpssl_sock_set_certfile). */
int ssl_quic_initial_ctx(struct bind_conf *bind_conf)
{
	return 0;
}

SSL_CTX *ssl_quic_srv_new_ssl_ctx(void)
{
	/* TODO: outbound (client) mode */
	return NULL;
}

} /* extern "C" */

#endif /* USE_JPSSL */
