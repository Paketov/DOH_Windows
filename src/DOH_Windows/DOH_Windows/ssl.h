/* PChat
 * Copyright (C) 1998-2010 Peter Zelezny.
 * Copyright (C) 2009-2013 Berke Viktor.
 * Copyright (C) 2026 PChat-IRC contributors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * Backend-agnostic TLS abstraction. Two implementations live alongside
 * this header: ssl_openssl.c (POSIX/macOS/Windows OpenSSL builds) and
 * ssl_schannel.c (Windows native Schannel builds). The previous direct
 * use of OpenSSL types in callers has been replaced by the opaque
 * pchat_ssl_ctx / pchat_ssl handles below.
 */

/*
	https://github.com/PChat-IRC/PChat/blob/bece5362af045ea16c7ed531a12713878c324849/src/common/ssl.h
*/

#ifndef PCHAT_SSL_H
#define PCHAT_SSL_H

//#include "config.h"

#define USE_SSL

//#define USE_OPENSSL
#define USE_SCHANNEL

#ifdef USE_SSL

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct pchat_ssl_ctx pchat_ssl_ctx;
	typedef struct pchat_ssl     pchat_ssl;

	struct cert_info {
		char subject[256];
		char *subject_word[12];
		char issuer[256];
		char *issuer_word[12];
		char algorithm[32];
		int algorithm_bits;
		char sign_algorithm[32];
		int sign_algorithm_bits;
		char notbefore[32];
		char notafter[32];
		int rsa_tmp_bits;
	};

	struct chiper_info {
		char version[16];
		char chiper[48];
		int chiper_bits;
	};

	typedef enum {
		PCHAT_SSL_HANDSHAKE_PENDING = 1,
		PCHAT_SSL_HANDSHAKE_DONE = 0,
		PCHAT_SSL_HANDSHAKE_FAILED = -1
	} pchat_ssl_handshake_status;

	typedef struct {
		int verified;        /* 1 = chain verified AND hostname matched */
		int recoverable;     /* 1 = error class the user may "accept" with prefs */
		int hostname_error;  /* nonzero if the failure is hostname-mismatch */
		char error[256];     /* human-readable description for the UI */
	} pchat_ssl_verify_result;

	/* Returns a static string identifying the active backend. */
	const char *pchat_ssl_backend_name(void);
	const char *pchat_ssl_backend_version(void);

	pchat_ssl_ctx *pchat_ssl_ctx_new(void);
	void pchat_ssl_ctx_free(pchat_ssl_ctx *ctx);

	/* Configure peer-certificate verification. Returns NULL on success or a
	 * static error string on failure. */
	const char *pchat_ssl_ctx_set_verify(pchat_ssl_ctx *ctx, const char* cacert_pem_file);

	/* Load a client certificate + private key from a single PEM file.
	 * Returns 1 on success, 0 on failure. */
	int pchat_ssl_ctx_use_cert_file(pchat_ssl_ctx *ctx, const char *path);

	/* Create a TLS session bound to an already-connected socket. */
	pchat_ssl *pchat_ssl_new(pchat_ssl_ctx *ctx, int sd, const char *hostname);
	void pchat_ssl_free(pchat_ssl *ssl);

	/* Drive the TLS handshake one step. errbuf is filled on failure.
	 * If failure looks like a protocol/version mismatch, *wrong_version_hint=1. */
	pchat_ssl_handshake_status pchat_ssl_do_handshake(pchat_ssl *ssl,
		char *errbuf, size_t errbuf_size, int *wrong_version_hint);

	/* Returns nonzero if the handshake started more than timeout_secs ago. */
	int pchat_ssl_handshake_timed_out(pchat_ssl *ssl, int timeout_secs);

	/* Fill out the verification result after a successful handshake. */
	void pchat_ssl_get_verify_result(pchat_ssl *ssl, const char *hostname,
		pchat_ssl_verify_result *out);

	int pchat_ssl_get_cert_info(struct cert_info *out, pchat_ssl *ssl);

	/* Returns a pointer to a static buffer overwritten by each call. */
	struct chiper_info *pchat_ssl_get_cipher_info(pchat_ssl *ssl);

	int pchat_ssl_send(pchat_ssl *ssl, const char *buf, int len);
	int pchat_ssl_recv(pchat_ssl *ssl, char *buf, int len);


#ifdef __cplusplus
}
#endif

#endif /* USE_SSL */

#endif /* PCHAT_SSL_H */
