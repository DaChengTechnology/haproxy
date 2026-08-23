/*
 * include/haproxy/quic_jpssl.h
 * JPSSL glue for the QUIC-TLS layer.
 *
 * This header is C-compatible and only exposes what the existing QUIC code
 * needs to hook into the JPSSL backend from C/C++ boundary points (mainly
 * the context cleanup used by the static inline helpers of quic_tls.h and
 * quic_ssl.h).
 *
 * The JPSSL QUIC backend keeps the OpenSSL object *types* as opaque handles
 * (so all existing struct layouts and inline helpers keep working), but
 * performs all the actual cryptographic work with JPSSL.  AEAD/HP cipher
 * contexts allocated by quic_tls_rx_ctx_init()/quic_tls_*_hp_ctx_init()
 * are real OpenSSL EVP_CIPHER_CTX objects registered in a JPSSL side table
 * which carries the key material; jpssl_quic_ctx_free() releases both.
 *
 * Copyright (C) 2026 DaChengTechnology
 */

#ifndef _HAPROXY_QUIC_JPSSL_H
#define _HAPROXY_QUIC_JPSSL_H

#ifdef USE_QUIC
#ifndef USE_OPENSSL
#error "Must define USE_OPENSSL"
#endif

#include <openssl/evp.h>
#include <haproxy/ssl_sock-t.h>

/* Register the JPSSL-side key material for an AEAD context <ctx> created
 * with <aead> and <key>.  Returns 1 on success, 0 on error. */
int jpssl_quic_aead_ctx_set(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *aead,
                            const unsigned char *key);

/* Register the JPSSL-side key material for a header-protection context
 * <ctx> created with <hp> cipher and <key>.  Returns 1 on success, 0 on
 * error. */
int jpssl_quic_hp_ctx_set(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *hp,
                          const unsigned char *key);

/* Release an AEAD or HP context: drops the JPSSL side table entry and
 * calls EVP_CIPHER_CTX_free().  Safe on NULL. */
void jpssl_quic_ctx_free(EVP_CIPHER_CTX *ctx);

/* Release the JPSSL QUIC handshake context attached to an ssl_sock_ctx
 * (used by qc_free_ssl_sock_ctx() under USE_JPSSL). */
void qc_jpssl_free_ctx(struct ssl_sock_ctx *ctx);

#endif /* USE_QUIC */
#endif /* _HAPROXY_QUIC_JPSSL_H */
