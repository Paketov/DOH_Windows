/* PChat
 * OpenSSL implementation of the pchat_ssl backend.
 *
 * Originally derived from HexChat's src/common/ssl.c by DaP <profeta@freemail.c3.hu>
 * and the HexChat developers, copyright (C) 2000-.
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
 */

/*
	https://github.com/PChat-IRC/PChat/blob/bece5362af045ea16c7ed531a12713878c324849/src/common/ssl_openssl.c
*/

#ifdef __APPLE__
#define __AVAILABILITYMACROS__
#define DEPRECATED_IN_MAC_OS_X_VERSION_10_7_AND_LATER
#endif

//#include "inet.h"
//#include "config.h"

#include "ssl.h"

#ifdef USE_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#ifdef WIN32
#include <openssl/rand.h>
#endif

#include <time.h>
#include <string.h>


#if defined(_WIN32) || defined(_WIN64)
# include <winsock2.h>
# include <ws2ipdef.h>
# include <Windows.h>
#endif

//#include <glib.h>
//#include <gio/gio.h>
//
//#include "ssl.h"
//#include "util.h"

typedef char gchar;
typedef int gsize;
typedef unsigned char guint8;

#define g_new0(type, count) calloc((count), sizeof(type))
#define g_malloc0(size) calloc(1, (size));
#define g_malloc malloc
#define g_realloc realloc
#define g_free free

#define g_strdup strdup
#define g_ascii_strcasecmp(str1, str2) stricmp((str1), (str2))

#define g_strlcpy(dest, src, max_size) strcpy_s((dest), (max_size), (src))
#define g_snprintf(dest, dest_size, fmt, ...) snprintf((dest), (dest_size), fmt, __VA_ARGS__)
#define safe_strcpy(dest, source, dest_size) strcpy_s((dest), (dest_size), (source))

#define g_strcmp0 strcmp

#define MIN(a,b) (((a) < (b))?(a):(b))

#ifndef SSL_OP_SINGLE_ECDH_USE
#define SSL_OP_SINGLE_ECDH_USE 0
#endif
#ifndef SSL_OP_NO_COMPRESSION
#define SSL_OP_NO_COMPRESSION 0
#endif

struct pchat_ssl_ctx {
	SSL_CTX *ctx;
};

struct pchat_ssl {
	SSL *ssl;
	char *hostname;
	time_t handshake_started;
};

static char err_buf[256];
static struct chiper_info chiper_info_buf;



int get_address_from_hostaname(const gchar *string, char* dest_addr, int* dest_addr_len)
{
#if defined(_WIN32) || defined(_WIN64)
	struct sockaddr_storage sa;
	struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
	int len;
#else /* !G_OS_WIN32 */
	struct in_addr in_addr;
	struct in6_addr in6_addr;
#endif

	/* Make sure _g_networking_init() has been called */
	//type = g_inet_address_get_type();

#if defined(_WIN32) || defined(_WIN64)
	memset(&sa, 0, sizeof(sa));
	len = sizeof(sa);
	if (WSAStringToAddressA(string, AF_INET, NULL, (LPSOCKADDR)&sa, &len) == 0) {
		memcpy(dest_addr, &sin->sin_addr, sizeof(sin->sin_addr));
		*dest_addr_len = sizeof(sin->sin_addr);
		return AF_INET;
	}
	else if (WSAStringToAddressA(string, AF_INET6, NULL, (LPSOCKADDR)&sa, &len) == 0) {
		memcpy(dest_addr, &sin6->sin6_addr, sizeof(sin6->sin6_addr));
		*dest_addr_len = sizeof(sin6->sin6_addr);
		return AF_INET6;
	}

#else /* !G_OS_WIN32 */

	if (inet_pton(AF_INET, string, &in_addr) > 0) {
		memcpy(dest_addr, &in_addr, sizeof(in_addr));
		*dest_addr_len = sizeof(in_addr);
		return AF_INET;
	} else if (inet_pton(AF_INET6, string, &in6_addr) > 0) {
		memcpy(dest_addr, &in6_addr, sizeof(in6_addr));
		*dest_addr_len = sizeof(in6_addr);
		return AF_INET6;
	}
#endif

	return NULL;
}

static void
fill_err_buf (const char *fn)
{
	int err = ERR_get_error ();
	char buf[256];
	ERR_error_string (err, buf);
	g_snprintf (err_buf, sizeof (err_buf), "%s: %s (%d)", fn, buf, err);
}

const char *
pchat_ssl_backend_name (void)
{
	return "OpenSSL";
}

const char *
pchat_ssl_backend_version (void)
{
#ifdef OPENSSL_VERSION_STRING
	/* Newer libcrypto exposes a short version string via OpenSSL_version. */
	return OpenSSL_version (OPENSSL_VERSION_STRING);
#elif defined(OPENSSL_VERSION)
	return OpenSSL_version (OPENSSL_VERSION);
#else
	return SSLeay_version (SSLEAY_VERSION);
#endif
}

/* Suppress the SSL info callback noise; legacy code wired one in. */
static void
ssl_info_cb (const SSL *s, int where, int ret)
{
	(void)s; (void)where; (void)ret;
}

pchat_ssl_ctx *
pchat_ssl_ctx_new (void)
{
	pchat_ssl_ctx *wrap;
	SSL_CTX *ctx;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	SSLeay_add_ssl_algorithms ();
	SSL_load_error_strings ();
	ctx = SSL_CTX_new (SSLv23_client_method ());
#else
	OPENSSL_init_ssl (OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
	ctx = SSL_CTX_new (TLS_client_method ());
#endif
	if (!ctx)
		return NULL;

	SSL_CTX_set_session_cache_mode (ctx, SSL_SESS_CACHE_BOTH);
	SSL_CTX_set_timeout (ctx, 300);
	SSL_CTX_set_options (ctx,
		SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION
		| SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE
		| SSL_OP_NO_TICKET | SSL_OP_CIPHER_SERVER_PREFERENCE);

	SSL_CTX_set_info_callback (ctx, ssl_info_cb);

	wrap = g_new0 (pchat_ssl_ctx, 1);
	wrap->ctx = ctx;
	return wrap;
}

void
pchat_ssl_ctx_free (pchat_ssl_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->ctx)
		SSL_CTX_free (ctx->ctx);
	g_free (ctx);
}

#if defined(_WIN32) || defined(_WIN64)

static int SetWindowsSSLStoreCerts(X509_STORE* X509_store) {
	HCERTSTORE hStore;
	PCCERT_CONTEXT pContext = NULL;
	X509 *x509;

	hStore = CertOpenSystemStoreW(NULL, L"ROOT");
	if (!hStore)
		return 0;
	while (pContext = CertEnumCertificatesInStore(hStore, pContext)) {
		//uncomment the line below if you want to see the certificates as pop ups
		//CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, pContext,   NULL, NULL, 0, NULL);
		if (x509 = d2i_X509(NULL, (const unsigned char **)&pContext->pbCertEncoded, pContext->cbCertEncoded)) {
			X509_STORE_add_cert(X509_store, x509);
			X509_free(x509);
		}
	}
	CertFreeCertificateContext(pContext);
	CertCloseStore(hStore, 0);
	return 1;
}

#endif

const char *
pchat_ssl_ctx_set_verify (pchat_ssl_ctx *wrap, const char* cacert_pem_file)
{
	SSL_CTX *ctx;
	X509_STORE* Store;
	int loaded = 0;

	if (!wrap || !wrap->ctx)
		return "SSL context not initialised";
	ctx = wrap->ctx;

//#ifdef WIN32
//	{
//		char *exe_path = portable_mode ()
//			? g_win32_get_package_installation_directory_of_module (NULL)
//			: g_strdup (XCHATSHAREDIR);
//
//		if (exe_path)
//		{
//			char *cert_path = g_build_filename (exe_path, "cert.pem", NULL);
//			g_free (exe_path);
//			if (g_file_test (cert_path, G_FILE_TEST_EXISTS))
//			{
//				if (SSL_CTX_load_verify_locations (ctx, cert_path, NULL))
//					loaded = 1;
//				else
//					fill_err_buf ("SSL_CTX_load_verify_locations");
//			}
//			g_free (cert_path);
//		}
//	}
//#endif

	if (cacert_pem_file) {
		if (SSL_CTX_load_verify_locations(ctx, cacert_pem_file, NULL) != 1) {
			fill_err_buf("SSL_CTX_load_verify_locations");
			return err_buf;
		} else {
			loaded = 1;
		}
	}

#if defined(_WIN32) || defined(_WIN64)
	if (!loaded) {
		Store = SSL_CTX_get_cert_store(ctx);
		if (Store != NULL) {
			if (SetWindowsSSLStoreCerts(Store)) {
				loaded = 1;
			}
		}
	}
#endif
	//SSL_CTX_load_verify_locations((SSL_CTX*)*(intptr_t*)ctx, "C:\\Users\\I\\Desktop\\cacert-2024-07-02.pem", NULL)
	if (!loaded)
	{
#ifdef DEFAULT_CERT_FILE
		if (!SSL_CTX_load_verify_locations (ctx, DEFAULT_CERT_FILE, NULL))
		{
			fill_err_buf ("SSL_CTX_load_verify_locations");
			return err_buf;
		}
#else
		if (!SSL_CTX_set_default_verify_paths (ctx))
		{
			fill_err_buf ("SSL_CTX_set_default_verify_paths");
			return err_buf;
		}
#endif
	}

	/* Verification result is checked manually after the handshake; using
	 * SSL_VERIFY_NONE here lets us produce nicer diagnostics ourselves. */
	SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER, NULL);
	return NULL;
}

int
pchat_ssl_ctx_use_cert_file (pchat_ssl_ctx *wrap, const char *path)
{
	if (!wrap || !wrap->ctx || !path)
		return 0;
	if (SSL_CTX_use_certificate_file (wrap->ctx, path, SSL_FILETYPE_PEM) != 1)
		return 0;
	if (SSL_CTX_use_PrivateKey_file (wrap->ctx, path, SSL_FILETYPE_PEM) != 1)
		return 0;
	return 1;
}

pchat_ssl *
pchat_ssl_new (pchat_ssl_ctx *wrap, int sd, const char *hostname)
{
	pchat_ssl *s;
	SSL *ssl;

	if (!wrap || !wrap->ctx)
		return NULL;

	ssl = SSL_new (wrap->ctx);
	if (!ssl)
		return NULL;

	SSL_set_fd (ssl, sd);
	SSL_set_connect_state (ssl);
	if (hostname && *hostname)
		SSL_set_tlsext_host_name (ssl, hostname);

	s = g_new0 (pchat_ssl, 1);
	s->ssl = ssl;
	s->hostname = g_strdup (hostname ? hostname : "");
	s->handshake_started = time (NULL);
	return s;
}

void
pchat_ssl_free (pchat_ssl *s)
{
	if (!s)
		return;
	if (s->ssl)
	{
		SSL_set_shutdown (s->ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
		SSL_free (s->ssl);
	}
	g_free (s->hostname);
	g_free (s);
}

pchat_ssl_handshake_status
pchat_ssl_do_handshake (pchat_ssl *s, char *errbuf, size_t errbuf_size,
                        int *wrong_version_hint)
{
	int rc;

	if (wrong_version_hint)
		*wrong_version_hint = 0;
	if (!s || !s->ssl)
	{
		if (errbuf && errbuf_size)
			g_strlcpy (errbuf, "TLS session not initialised", errbuf_size);
		return PCHAT_SSL_HANDSHAKE_FAILED;
	}

	rc = SSL_connect (s->ssl);
	if (rc == 1)
		return PCHAT_SSL_HANDSHAKE_DONE;

	{
		int sslerr = SSL_get_error (s->ssl, rc);
		if (sslerr == SSL_ERROR_WANT_READ || sslerr == SSL_ERROR_WANT_WRITE)
			return PCHAT_SSL_HANDSHAKE_PENDING;
	}

	{
		int err = ERR_get_error ();
		if (err > 0)
		{
			char tmp[128];
			ERR_error_string (err, tmp);
			if (errbuf && errbuf_size)
				g_snprintf (errbuf, errbuf_size, "(%d) %s", err, tmp);
			if (wrong_version_hint && ERR_GET_REASON (err) == SSL_R_WRONG_VERSION_NUMBER)
				*wrong_version_hint = 1;
		}
		else if (errbuf && errbuf_size)
		{
			g_strlcpy (errbuf, "TLS handshake failed", errbuf_size);
		}
	}
	return PCHAT_SSL_HANDSHAKE_FAILED;
}

int
pchat_ssl_handshake_timed_out (pchat_ssl *s, int timeout_secs)
{
	if (!s)
		return 0;
	return (s->handshake_started + timeout_secs) < time (NULL);
}

/* ---------- hostname verification (libtls-style) ---------- */

static int
match_hostname (const char *cert_hostname, const char *hostname)
{
	const char *cert_domain, *domain, *next_dot;

	if (g_ascii_strcasecmp (cert_hostname, hostname) == 0)
		return 0;
	if (cert_hostname[0] != '*')
		return -1;
	cert_domain = &cert_hostname[1];
	if (cert_domain[0] == '\0' || cert_domain[0] != '.' || cert_domain[1] == '.')
		return -1;
	next_dot = strchr (&cert_domain[1], '.');
	if (next_dot == NULL || next_dot[1] == '.')
		return -1;
	domain = strchr (hostname, '.');
	if (domain == NULL || strlen (domain) == 1)
		return -1;
	if (g_ascii_strcasecmp (cert_domain, domain) == 0)
		return 0;
	return -1;
}

static int
check_subject_altname (X509 *cert, const char *host)
{
	STACK_OF(GENERAL_NAME) *altname_stack;
	int addr_fam;
	int type = GEN_DNS;
	int count, i, rv = -1;
	char addr_buf[50];
	int addr_len = 0;

	altname_stack = X509_get_ext_d2i (cert, NID_subject_alt_name, NULL, NULL);
	if (!altname_stack)
		return -1;

	//addr_fam = get_address_from_hostaname(host, addr_buf, &addr_len);
	//if (addr_fam != AF_UNSPEC)
	//{
	//	//GSocketFamily family = g_inet_address_get_family (addr);
	//	if (addr_fam == AF_INET || addr_fam == AF_INET6)
	//		type = GEN_IPADD;
	//}

	count = sk_GENERAL_NAME_num (altname_stack);
	for (i = 0; i < count; i++)
	{
		GENERAL_NAME *altname = sk_GENERAL_NAME_value (altname_stack, i);
		if (altname->type != type)
			continue;
		if (type == GEN_DNS)
		{
			const unsigned char *data;
			if (ASN1_STRING_type (altname->d.dNSName) != V_ASN1_IA5STRING)
				continue;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			data = ASN1_STRING_get0_data (altname->d.dNSName);
#else
			data = ASN1_STRING_data (altname->d.dNSName);
#endif
			if (ASN1_STRING_length (altname->d.dNSName) != (int)strlen ((const char *)data))
			{
				rv = -2;
				break;
			}
			if (match_hostname ((const char *)data, host) == 0)
			{
				rv = 0;
				break;
			}
		}
		else
		{
			const unsigned char *data;
			const guint8 *addr_bytes;
			int datalen;
			datalen = ASN1_STRING_length (altname->d.iPAddress);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
			data = ASN1_STRING_get0_data (altname->d.iPAddress);
#else
			data = ASN1_STRING_data (altname->d.iPAddress);
#endif
			addr_bytes = addr_buf;
			if (datalen == addr_len && memcmp (data, addr_bytes, addr_len) == 0)
			{
				rv = 0;
				break;
			}
		}
	}

	//if (addr)
	//	g_object_unref (addr);
	sk_GENERAL_NAME_pop_free (altname_stack, GENERAL_NAME_free);
	return rv;
}

#if defined(_WIN32) || defined(_WIN64)
# undef X509_NAME
#endif

static int
check_common_name (X509 *cert, const char *host)
{
	X509_NAME *name;
	char *common_name;
	int common_name_len, rv = -1;
	char addr_buf[50];
	int addr_len = 0;
	//GInetAddress *addr;

	name = X509_get_subject_name (cert);
	if (!name)
		return -1;
	common_name_len = X509_NAME_get_text_by_NID (name, NID_commonName, NULL, 0);
	if (common_name_len < 0)
		return -1;
	common_name = g_malloc0 (common_name_len + 1);
	X509_NAME_get_text_by_NID (name, NID_commonName, common_name, common_name_len + 1);
	if (common_name_len != (int)strlen (common_name))
	{
		g_free (common_name);
		return -2;
	}

	/*if (get_address_from_hostaname(host, addr_buf, &addr_len) != AF_UNSPEC)
	{
		rv = (g_strcmp0 (common_name, host) == 0) ? 0 : -1;
		//g_object_unref (addr);
	}
	else */if (match_hostname (common_name, host) == 0)
		rv = 0;

	g_free (common_name);
	return rv;
}

static int
check_hostname (X509 *cert, const char *host)
{
	int rv = check_subject_altname (cert, host);
	if (rv == 0 || rv == -2)
		return rv;
	return check_common_name (cert, host);
}

/* ---------- post-handshake info ---------- */

void
pchat_ssl_get_verify_result (pchat_ssl *s, const char *hostname,
                             pchat_ssl_verify_result *out)
{
	long verr;

	memset (out, 0, sizeof (*out));
	if (!s || !s->ssl)
	{
		g_strlcpy (out->error, "TLS session not initialised", sizeof (out->error));
		return;
	}

	verr = SSL_get_verify_result (s->ssl);
	switch (verr)
	{
	case X509_V_OK:
	{
		X509 *cert = SSL_get_peer_certificate (s->ssl);
		if (!cert)
		{
			g_strlcpy (out->error, "No certificate", sizeof (out->error));
			return;
		}
		if (check_hostname (cert, hostname ? hostname : s->hostname) != 0)
		{
			out->hostname_error = 1;
			out->recoverable = 1;
			g_snprintf (out->error, sizeof (out->error),
				"Failed to validate hostname");
		}
		else
		{
			out->verified = 1;
		}
		X509_free (cert);
		return;
	}
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
	case X509_V_ERR_CERT_HAS_EXPIRED:
		out->recoverable = 1;
		break;
	default:
		out->recoverable = 0;
		break;
	}
	g_snprintf (out->error, sizeof (out->error), "%s (%ld)",
		X509_verify_cert_error_string (verr), verr);
}

static void
asn1_time_to_str (char *buf, int buf_len, ASN1_TIME *tm)
{
	BIO *mem = BIO_new (BIO_s_mem ());
	char *expires = NULL;
	ASN1_TIME_print (mem, tm);
	BIO_get_mem_data (mem, &expires);
	buf[0] = 0;
	if (expires)
		safe_strcpy (buf, expires, MIN (24, buf_len));
	BIO_free (mem);
}

static void
broke_oneline (char *oneline, char *parray[])
{
	char *pt, *ppt;
	int i = 0;
	ppt = pt = oneline + 1;
	while ((pt = strchr (pt, '/')))
	{
		*pt = 0;
		parray[i++] = ppt;
		ppt = ++pt;
	}
	parray[i++] = ppt;
	parray[i] = NULL;
}

int
pchat_ssl_get_cert_info (struct cert_info *out, pchat_ssl *s)
{
	X509 *cert;
	X509_PUBKEY *key;
	X509_ALGOR *algor = NULL;
	EVP_PKEY *pkey;
	int alg, sign_alg;
	char nb[64], na[64];

	if (!s || !s->ssl)
		return 1;
	cert = SSL_get_peer_certificate (s->ssl);
	if (!cert)
		return 1;

	X509_NAME_oneline (X509_get_subject_name (cert), out->subject, sizeof (out->subject));
	X509_NAME_oneline (X509_get_issuer_name (cert), out->issuer, sizeof (out->issuer));
	broke_oneline (out->subject, out->subject_word);
	broke_oneline (out->issuer, out->issuer_word);

	key = X509_get_X509_PUBKEY (cert);
	if (!X509_PUBKEY_get0_param (NULL, NULL, 0, &algor, key))
	{
		X509_free (cert);
		return 1;
	}
	alg = OBJ_obj2nid (algor->algorithm);
#if OPENSSL_VERSION_NUMBER < 0x10100000L && !defined(HAVE_X509_GET_SIGNATURE_NID)
	sign_alg = OBJ_obj2nid (cert->sig_alg->algorithm);
#else
	sign_alg = X509_get_signature_nid (cert);
#endif

	asn1_time_to_str (nb, sizeof (nb), X509_get_notBefore (cert));
	asn1_time_to_str (na, sizeof (na), X509_get_notAfter (cert));

	pkey = X509_get_pubkey (cert);
	safe_strcpy (out->algorithm, (alg == NID_undef) ? "Unknown" : OBJ_nid2ln (alg),
		sizeof (out->algorithm));
	out->algorithm_bits = EVP_PKEY_bits (pkey);
	safe_strcpy (out->sign_algorithm,
		(sign_alg == NID_undef) ? "Unknown" : OBJ_nid2ln (sign_alg),
		sizeof (out->sign_algorithm));
	out->sign_algorithm_bits = 0;
	safe_strcpy (out->notbefore, nb, sizeof (out->notbefore));
	safe_strcpy (out->notafter, na, sizeof (out->notafter));
	out->rsa_tmp_bits = 0;

	EVP_PKEY_free (pkey);
	X509_free (cert);
	return 0;
}

struct chiper_info *
pchat_ssl_get_cipher_info (pchat_ssl *s)
{
	const SSL_CIPHER *c;
	if (!s || !s->ssl)
		return NULL;
	c = SSL_get_current_cipher (s->ssl);
	safe_strcpy (chiper_info_buf.version, SSL_CIPHER_get_version (c),
		sizeof (chiper_info_buf.version));
	safe_strcpy (chiper_info_buf.chiper, SSL_CIPHER_get_name (c),
		sizeof (chiper_info_buf.chiper));
	SSL_CIPHER_get_bits (c, &chiper_info_buf.chiper_bits);
	return &chiper_info_buf;
}


int
pchat_ssl_send (pchat_ssl *s, const char *buf, int len)
{
	int n;
	if (!s || !s->ssl)
		return -1;
	n = SSL_write (s->ssl, buf, len);
	if (n <= 0) {
		switch (SSL_get_error(s->ssl, n))
		{
		case SSL_ERROR_SSL:
			fill_err_buf("SSL_write");
			fprintf(stderr, "%s\n", err_buf);
			break;
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
#if defined(_WIN32) || defined(_WIN64)
			WSASetLastError(WSAEWOULDBLOCK);
#endif
			errno = EWOULDBLOCK;
			break;
		case SSL_ERROR_SYSCALL:
			perror("SSL_write/write");
			break;
		default:
			break;
		}
	}
	return n;
}

#if defined(_WIN32) || defined(_WIN64)
static int
sock_would_block(void)
{
	int e = WSAGetLastError();
	return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == ERROR_IO_PENDING;
}

#else

static int
sock_would_block(void)
{
#  if defined(__sun__)
	return (uwsgi_is_again());
#  elif defined(EWOULDBLOCK) && defined(EAGAIN) && defined(EINPROGRESS)
	return ((errno == EWOULDBLOCK) || (errno == EAGAIN) || (errno == EINPROGRESS));
#  elif defined(EWOULDBLOCK) && defined(EINPROGRESS)
	return ((errno == EWOULDBLOCK) || (errno == EINPROGRESS));
#  elif defined(EAGAIN) && defined(EINPROGRESS)
	return ((errno == EAGAIN) || (errno == EINPROGRESS));
#  elif defined(EWOULDBLOCK) && defined(EAGAIN)
	return ((errno == EWOULDBLOCK) || (errno == EAGAIN));
#  else
	return (errno == EAGAIN);
#  endif
}


#endif


int
pchat_ssl_recv (pchat_ssl *s, char *buf, int len)
{
	int n;
	if (!s || !s->ssl)
		return -1;
	n = SSL_read (s->ssl, buf, len);
	if (n <= 0) {
		switch (SSL_get_error(s->ssl, n))
		{
		case SSL_ERROR_SSL:
			fill_err_buf("SSL_read");
			fprintf(stderr, "%s\n", err_buf);
			break;
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
#if defined(_WIN32) || defined(_WIN64)
			WSASetLastError(WSAEWOULDBLOCK);
#endif
			errno = EWOULDBLOCK;
			break;
		case SSL_ERROR_SYSCALL:
			if (!sock_would_block())
				perror("SSL_read/read");
			break;
		default:
			break;
		}
	}
	return n;
}

#endif /* USE_OPENSSL */
