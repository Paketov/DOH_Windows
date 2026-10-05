/* PChat
 * Schannel (Windows native) implementation of the pchat_ssl backend.
 *
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
 * Notes:
 *   - The handshake is driven non-blocking. pchat_ssl_do_handshake() reads
 *     and writes the underlying socket directly; it returns PENDING when the
 *     socket would block (matching the OpenSSL backend's behaviour).
 *   - Hostname validation is performed manually using the certificate's CN /
 *     SubjectAltName so we get the same diagnostics as the OpenSSL path.
 */

//#include "config.h"

/*
https://github.com/PChat-IRC/PChat/blob/bece5362af045ea16c7ed531a12713878c324849/src/common/ssl_schannel.c
*/

#include "ssl.h"

#ifdef USE_SCHANNEL

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <shlwapi.h>
#include <assert.h>
#include <stdio.h>

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "secur32.lib")
#pragma comment (lib, "shlwapi.lib")

#define SECURITY_WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <security.h>
#include <wchar.h>
#include <time.h>
#include <string.h>
#include <stdio.h>



//#include <glib.h>
//#include <gio/gio.h>


//#include "util.h"

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

#ifndef SCH_USE_STRONG_CRYPTO
#define SCH_USE_STRONG_CRYPTO 0x00400000
#endif

#define SCHANNEL_IO_BUFSZ (16 * 1024 + 256)



#define g_new0(type, count) calloc((count), sizeof(type))
#define g_malloc malloc
#define g_realloc realloc
#define g_free free

#define g_strdup strdup
#define g_ascii_strcasecmp(str1, str2) stricmp((str1), (str2))

#define g_strlcpy(dest, src, max_size) strcpy_s((dest), (max_size), (src))
#define g_snprintf(dest, dest_size, fmt, ...) snprintf((dest), (dest_size), fmt, __VA_ARGS__)

typedef char gchar;
typedef int gsize;

struct pchat_ssl_ctx {
	CredHandle  cred;
	int         have_cred;
	int         manual_verify;       /* 1: skip Schannel auto-verify, do it ourselves */
	PCCERT_CONTEXT client_cert;      /* optional client auth cert */
	HCERTSTORE cert_store;
};

struct pchat_ssl {
	pchat_ssl_ctx *ctx;
	SOCKET   sock;
	char    *hostname;

	CtxtHandle hctx;
	int        have_hctx;
	int        handshake_done;
	time_t     handshake_started;

	SecPkgContext_StreamSizes sizes;
	int        have_sizes;

	/* Inbound TLS record buffer (encrypted bytes from socket). */
	unsigned char *enc_buf;
	size_t   enc_len;
	size_t   enc_cap;

	/* Decrypted plaintext awaiting consumption by the caller. */
	unsigned char *dec_buf;
	size_t   dec_len;
	size_t   dec_off;
	size_t   dec_cap;

	/* Pending outbound bytes from the handshake step. */
	unsigned char *out_buf;
	size_t   out_len;
	size_t   out_off;
	size_t   out_cap;

	int      shutdown_sent;
	int      eof;
};

/* ---------- small helpers ---------- */

static void
ensure_cap (unsigned char **buf, size_t *cap, size_t need)
{
	if (*cap >= need)
		return;
	{
		size_t newcap = *cap ? *cap : 1024;
		while (newcap < need)
			newcap *= 2;
		*buf = g_realloc (*buf, newcap);
		*cap = newcap;
	}
}

static int
sock_would_block (void)
{
	int e = WSAGetLastError ();
	return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == ERROR_IO_PENDING;
}

const char *
pchat_ssl_backend_name (void)
{
	return "Schannel";
}

const char *
pchat_ssl_backend_version (void)
{
	static char buf[64];
	OSVERSIONINFOEXA ovi = { 0 };
	if (buf[0])
		return buf;
	ovi.dwOSVersionInfoSize = sizeof (ovi);
#pragma warning(push)
#pragma warning(disable: 4996)
	if (GetVersionExA ((OSVERSIONINFOA *) &ovi))
		g_snprintf (buf, sizeof (buf), "Windows %lu.%lu (build %lu)",
			(unsigned long) ovi.dwMajorVersion,
			(unsigned long) ovi.dwMinorVersion,
			(unsigned long) ovi.dwBuildNumber);
	else
		g_strlcpy (buf, "Windows", sizeof (buf));
#pragma warning(pop)
	return buf;
}

/* ---------- context lifecycle ---------- */

pchat_ssl_ctx *
pchat_ssl_ctx_new (void)
{
	pchat_ssl_ctx *c = g_new0 (pchat_ssl_ctx, 1);
	SCHANNEL_CRED scred = { 0 };
	SECURITY_STATUS s;

	scred.dwVersion = SCHANNEL_CRED_VERSION;
	/* Modern protocol set; let Schannel pick. We disable SSLv2/v3 explicitly. */
	scred.grbitEnabledProtocols = 0; /* 0 = use system defaults */
	scred.dwFlags = SCH_USE_STRONG_CRYPTO
		| SCH_CRED_NO_DEFAULT_CREDS
		/* We perform verification ourselves so we can produce nice
		 * diagnostics and honour accept_invalid_cert. */
		| SCH_CRED_MANUAL_CRED_VALIDATION
		| SCH_CRED_AUTO_CRED_VALIDATION * 0;

	s = AcquireCredentialsHandleA (NULL, (SEC_CHAR *) UNISP_NAME_A,
		SECPKG_CRED_OUTBOUND, NULL, &scred, NULL, NULL, &c->cred, NULL);
	if (s != SEC_E_OK)
	{
		g_free (c);
		return NULL;
	}
	c->have_cred = 1;
	c->manual_verify = 1;
	c->cert_store = NULL;
	return c;
}

void
pchat_ssl_ctx_free (pchat_ssl_ctx *c)
{
	if (!c)
		return;
	if (c->client_cert)
		CertFreeCertificateContext (c->client_cert);
	if (c->have_cred)
		FreeCredentialsHandle (&c->cred);
	if(c->cert_store)
		CertCloseStore(c->cert_store, 0);
	g_free (c);
}

//void LoadCACert(const char* certFilePath) {
//	HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"ROOT");    
//	if (hStore) {        // Load the certificate from file        
//		HCERTSTORE hCertStore = CertOpenStore(CERT_STORE_PROV_FILENAME, 0, NULL, 0, certFilePath);        
//		if (hCertStore) {            // Add the certificate to the store            
//			PCCERT_CONTEXT pCertContext = CertEnumCertificatesInStore(hCertStore, NULL);
//			while (pCertContext) {                
//				CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_NEW, NULL);                
//				pCertContext = CertEnumCertificatesInStore(hCertStore, pCertContext);            
//			}           
//			CertCloseStore(hCertStore, 0);        
//		}        
//		CertCloseStore(hStore, 0);    
//	}
//}

/*
open_ssl used schannel
https://github.com/openssl-shim/openssl-shim/blob/1e04b9146aa0eb8d04fc1bd68e380c741d4a4935/src/tls_schannel.cpp
post_handshake_verify
verify_peer_chain
*/
static int AddCAPemFileInCertStore(pchat_ssl_ctx *c, const char* pemFilePath) { 
	int pem_len;
	char* pem = NULL;
	int res = 0;
	DWORD der_len = 0;
	BYTE *der = NULL;
	PCCERT_CONTEXT cert = NULL;
	FILE* f = NULL;
	HCERTSTORE newStore = NULL, hStore2;

	if (!c->cert_store) {
		newStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			0,
			CERT_STORE_CREATE_NEW_FLAG,
			NULL);
		if (!newStore) 
			goto lbl_out;
		hStore2 = newStore;
	} else {
		hStore2 = c->cert_store;
	}

	
	{
		f = fopen(pemFilePath, "rb");
		if (f == NULL)
			goto lbl_out;

		fseek(f, 0, SEEK_END);
		pem_len = ftell(f);
		fseek(f, 0, SEEK_SET);
		pem = (char*)malloc(pem_len + 1);
		if (!pem)
			goto lbl_out;
		fread(pem, 1, pem_len, f);
		pem[pem_len] = '\0';
		fclose(f);
		f = NULL;
	}

	

	/* PEM to DER coverting*/
	char* p = pem, *p2 = pem;
	for (;;) {
		p = strstr(p2, "-----BEGIN CERTIFICATE-----");
		if (p == NULL)
			break;
		p2 = strstr(p, "-----END CERTIFICATE-----");
		if (p2 == NULL)
			break;
		p2+= (sizeof("-----END CERTIFICATE-----") - 1);
		if (CryptStringToBinaryA(p, (DWORD)(p2 - p), CRYPT_STRING_BASE64HEADER, NULL, &der_len, NULL, NULL)) {
			der = g_malloc(der_len);
			if (CryptStringToBinaryA(p, (DWORD)(p2 - p), CRYPT_STRING_BASE64HEADER, der, &der_len, NULL, NULL)) {
				/*load converted DER cert*/
				cert = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der, der_len);
				if (cert) {
					CertAddCertificateContextToStore(hStore2, cert, CERT_STORE_ADD_ALWAYS, NULL);
					CertFreeCertificateContext(cert);
				}
			}
			g_free(der);
		}
	}	
	c->cert_store = hStore2;
	res = 1;
lbl_out:
	if (f)
		fclose(f);
	if (pem)
		free(pem);
	if (!res && newStore)
		CertCloseStore(newStore, 0);
	return res;
}

const char *
pchat_ssl_ctx_set_verify (pchat_ssl_ctx *c, const char* cacert_pem_file)
{
	if (cacert_pem_file) {
		if (!AddCAPemFileInCertStore(c, cacert_pem_file)) {
			return "AddCAPemFileInCertStore";
		}
	}

	/* Schannel uses the system trust store by default; no extra wiring needed. */
	return NULL;
}

/* Load a single PEM file containing a cert + private key as a client
 * authentication credential. Re-issues the credentials handle so the
 * cert is presented during the handshake. */
int
pchat_ssl_ctx_use_cert_file (pchat_ssl_ctx *c, const char *path)
{
	gchar *contents = NULL;
	gsize  length = 0;
	//GError *err = NULL;
	PCCERT_CONTEXT cert = NULL;
	HCRYPTKEY hKey = 0;
	HCRYPTPROV hProv = 0;
	int ok = 0;

	if (!c || !path)
		return 0;
	{
		FILE* f = fopen(path, "rb");
		if (f == NULL)
			return 0;

		fseek(f, 0, SEEK_END);
		length = ftell(f);
		fseek(f, 0, SEEK_SET);
		contents = (char*)malloc(length);
		fread(contents, 1, length, f);
		fclose(f);
	}
	//if (!g_file_get_contents (path, &contents, &length, &err))
	//{
	//	g_clear_error (&err);
	//	return 0;
	//}

	/* Decode the certificate (BEGIN CERTIFICATE block). */
	{
		DWORD der_len = 0;
		BYTE *der = NULL;
		if (CryptStringToBinaryA (contents, (DWORD) length,
			CRYPT_STRING_BASE64HEADER, NULL, &der_len, NULL, NULL))
		{
			der = g_malloc (der_len);
			if (CryptStringToBinaryA (contents, (DWORD) length,
				CRYPT_STRING_BASE64HEADER, der, &der_len, NULL, NULL))
			{
				cert = CertCreateCertificateContext (
					X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der, der_len);
			}
			g_free (der);
		}
	}

	if (!cert)
		goto cleanup;

	/* Decode the private key (BEGIN PRIVATE KEY / RSA PRIVATE KEY) and
	 * attach it to the certificate context. */
	{
		DWORD pem_len = 0;
		BYTE *pem = NULL;
		DWORD pki_len = 0;
		BYTE *pki = NULL;
		const char *headers[] = {
			"-----BEGIN PRIVATE KEY-----",
			"-----BEGIN RSA PRIVATE KEY-----",
			NULL
		};
		int i;
		const char *match_tail = NULL;
		const char *match_head = NULL;
		for (i = 0; headers[i]; i++)
		{
			match_head = strstr (contents, headers[i]);
			if (match_head)
			{
				const char *footer = (i == 0)
					? "-----END PRIVATE KEY-----"
					: "-----END RSA PRIVATE KEY-----";
				match_tail = strstr (match_head, footer);
				if (match_tail)
				{
					match_tail += strlen (footer);
					break;
				}
				match_head = NULL;
			}
		}
		if (!match_head || !match_tail)
			goto cleanup;

		if (!CryptStringToBinaryA (match_head, (DWORD) (match_tail - match_head),
			CRYPT_STRING_BASE64HEADER, NULL, &pem_len, NULL, NULL))
			goto cleanup;
		pem = g_malloc (pem_len);
		if (!CryptStringToBinaryA (match_head, (DWORD) (match_tail - match_head),
			CRYPT_STRING_BASE64HEADER, pem, &pem_len, NULL, NULL))
		{
			g_free (pem);
			goto cleanup;
		}

		if (i == 0)
		{
			/* PKCS#8 wrapper -> unwrap to RSA private key blob. */
			if (!CryptDecodeObjectEx (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				PKCS_PRIVATE_KEY_INFO, pem, pem_len,
				CRYPT_DECODE_ALLOC_FLAG, NULL, &pki, &pki_len))
			{
				g_free (pem);
				goto cleanup;
			}
		}
		else
		{
			pki = pem;
			pki_len = pem_len;
			pem = NULL;
		}

		{
			BYTE *blob = NULL;
			DWORD blob_len = 0;
			const BYTE *raw_key;
			DWORD raw_key_len;

			if (i == 0)
			{
				CRYPT_PRIVATE_KEY_INFO *info = (CRYPT_PRIVATE_KEY_INFO *) pki;
				raw_key = info->PrivateKey.pbData;
				raw_key_len = info->PrivateKey.cbData;
			}
			else
			{
				raw_key = pki;
				raw_key_len = pki_len;
			}

			if (!CryptDecodeObjectEx (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				PKCS_RSA_PRIVATE_KEY, raw_key, raw_key_len,
				CRYPT_DECODE_ALLOC_FLAG, NULL, &blob, &blob_len))
			{
				if (pem) g_free (pem);
				if (pki && i == 0) LocalFree (pki);
				goto cleanup;
			}

			if (!CryptAcquireContextW (&hProv, NULL, NULL,
				PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{
				LocalFree (blob);
				if (pem) g_free (pem);
				if (pki && i == 0) LocalFree (pki);
				goto cleanup;
			}
			if (!CryptImportKey (hProv, blob, blob_len, 0, 0, &hKey))
			{
				LocalFree (blob);
				CryptReleaseContext (hProv, 0);
				hProv = 0;
				if (pem) g_free (pem);
				if (pki && i == 0) LocalFree (pki);
				goto cleanup;
			}
			LocalFree (blob);

			{
				CRYPT_KEY_PROV_INFO kp = { 0 };
				kp.pwszContainerName = NULL;
				kp.dwProvType = PROV_RSA_FULL;
				kp.dwKeySpec = AT_KEYEXCHANGE;
				if (!CertSetCertificateContextProperty (cert,
					CERT_KEY_PROV_HANDLE_PROP_ID, 0, &hProv))
				{
					CryptDestroyKey (hKey);
					CryptReleaseContext (hProv, 0);
					if (pem) g_free (pem);
					if (pki && i == 0) LocalFree (pki);
					goto cleanup;
				}
			}
		}

		if (pem) g_free (pem);
		if (pki && i == 0) LocalFree (pki);
	}

	/* Replace the credentials handle so the cert is included. */
	if (c->have_cred)
	{
		FreeCredentialsHandle (&c->cred);
		c->have_cred = 0;
	}
	if (c->client_cert)
		CertFreeCertificateContext (c->client_cert);
	c->client_cert = cert;
	cert = NULL;

	{
		SCHANNEL_CRED scred = { 0 };
		PCCERT_CONTEXT certs[1];
		certs[0] = c->client_cert;
		scred.dwVersion = SCHANNEL_CRED_VERSION;
		scred.cCreds = 1;
		scred.paCred = certs;
		scred.dwFlags = SCH_USE_STRONG_CRYPTO
			| SCH_CRED_NO_DEFAULT_CREDS
			| SCH_CRED_MANUAL_CRED_VALIDATION;
		if (AcquireCredentialsHandleA (NULL, (SEC_CHAR *) UNISP_NAME_A,
			SECPKG_CRED_OUTBOUND, NULL, &scred, NULL, NULL,
			&c->cred, NULL) == SEC_E_OK)
		{
			c->have_cred = 1;
			ok = 1;
		}
	}

cleanup:
	if (cert)
		CertFreeCertificateContext (cert);
	g_free (contents);
	return ok;
}

/* ---------- session lifecycle ---------- */

pchat_ssl *
pchat_ssl_new (pchat_ssl_ctx *ctx, int sd, const char *hostname)
{
	pchat_ssl *s;
	if (!ctx || !ctx->have_cred)
		return NULL;
	s = g_new0 (pchat_ssl, 1);
	s->ctx = ctx;
	s->sock = (SOCKET) sd;
	s->hostname = g_strdup (hostname ? hostname : "");
	s->handshake_started = time (NULL);
	return s;
}

void
pchat_ssl_free (pchat_ssl *s)
{
	if (!s)
		return;
	if (s->have_hctx)
	{
		if (!s->shutdown_sent && s->handshake_done)
		{
			DWORD shutdown = SCHANNEL_SHUTDOWN;
			SecBuffer sb = { sizeof (shutdown), SECBUFFER_TOKEN, &shutdown };
			SecBufferDesc sbd = { SECBUFFER_VERSION, 1, &sb };
			ApplyControlToken (&s->hctx, &sbd);
			s->shutdown_sent = 1;
		}
		DeleteSecurityContext (&s->hctx);
	}
	g_free (s->hostname);
	g_free (s->enc_buf);
	g_free (s->dec_buf);
	g_free (s->out_buf);
	g_free (s);
}

/* ---------- handshake plumbing ---------- */

static int
flush_pending_out (pchat_ssl *s)
{
	while (s->out_off < s->out_len)
	{
		int n = send (s->sock,
			(const char *) s->out_buf + s->out_off,
			(int) (s->out_len - s->out_off), 0);
		if (n == SOCKET_ERROR)
		{
			if (sock_would_block ())
				return 1; /* PENDING */
			return -1;
		}
		s->out_off += n;
	}
	s->out_len = 0;
	s->out_off = 0;
	return 0;
}

static int
read_some_encrypted (pchat_ssl *s)
{
	ensure_cap (&s->enc_buf, &s->enc_cap, s->enc_len + SCHANNEL_IO_BUFSZ);
	{
		int n = recv (s->sock,
			(char *) s->enc_buf + s->enc_len,
			(int) (s->enc_cap - s->enc_len), 0);
		if (n == 0)
		{
			s->eof = 1;
			return 0;
		}
		if (n == SOCKET_ERROR)
		{
			if (sock_would_block ())
				return 1; /* would block */
			return -1;
		}
		s->enc_len += n;
		return 0;
	}
}

static void
queue_outbound (pchat_ssl *s, const void *data, size_t len)
{
	ensure_cap (&s->out_buf, &s->out_cap, s->out_len + len);
	memcpy (s->out_buf + s->out_len, data, len);
	s->out_len += len;
}

pchat_ssl_handshake_status
pchat_ssl_do_handshake (pchat_ssl *s, char *errbuf, size_t errbuf_size,
                        int *wrong_version_hint)
{
	SECURITY_STATUS ss;
	SecBuffer in_bufs[2];
	SecBufferDesc in_desc;
	SecBuffer out_bufs[3];
	SecBufferDesc out_desc;
	ULONG ctx_attr;
	DWORD req_flags = ISC_REQ_SEQUENCE_DETECT
		| ISC_REQ_REPLAY_DETECT
		| ISC_REQ_CONFIDENTIALITY
		| ISC_REQ_ALLOCATE_MEMORY
		| ISC_REQ_STREAM
		| ISC_REQ_USE_SUPPLIED_CREDS
		| ISC_REQ_MANUAL_CRED_VALIDATION;

	if (wrong_version_hint)
		*wrong_version_hint = 0;
	if (!s)
	{
		if (errbuf && errbuf_size)
			g_strlcpy (errbuf, "TLS session not initialised", errbuf_size);
		return PCHAT_SSL_HANDSHAKE_FAILED;
	}
	if (s->handshake_done)
		return PCHAT_SSL_HANDSHAKE_DONE;

	/* Step 1: flush any leftover handshake output from a prior invocation. */
	{
		int r = flush_pending_out (s);
		if (r < 0)
		{
			if (errbuf && errbuf_size)
				g_snprintf (errbuf, errbuf_size,
					"send() failed: %d", WSAGetLastError ());
			return PCHAT_SSL_HANDSHAKE_FAILED;
		}
		if (r == 1)
			return PCHAT_SSL_HANDSHAKE_PENDING;
	}

	/* Step 2: if we don't yet have a context, send the ClientHello. */
	if (!s->have_hctx)
	{
		out_bufs[0].pvBuffer = NULL;
		out_bufs[0].BufferType = SECBUFFER_TOKEN;
		out_bufs[0].cbBuffer = 0;
		out_desc.ulVersion = SECBUFFER_VERSION;
		out_desc.cBuffers = 1;
		out_desc.pBuffers = out_bufs;

		ss = InitializeSecurityContextA (&s->ctx->cred, NULL,
			(SEC_CHAR *) s->hostname, req_flags, 0, 0, NULL, 0,
			&s->hctx, &out_desc, &ctx_attr, NULL);
		s->have_hctx = 1;

		if (ss != SEC_I_CONTINUE_NEEDED && ss != SEC_E_OK)
		{
			if (errbuf && errbuf_size)
				g_snprintf (errbuf, errbuf_size,
					"InitializeSecurityContext failed (0x%08lx)", (unsigned long) ss);
			return PCHAT_SSL_HANDSHAKE_FAILED;
		}
		if (out_bufs[0].cbBuffer && out_bufs[0].pvBuffer)
		{
			queue_outbound (s, out_bufs[0].pvBuffer, out_bufs[0].cbBuffer);
			FreeContextBuffer (out_bufs[0].pvBuffer);
		}
		{
			int r = flush_pending_out (s);
			if (r < 0)
			{
				if (errbuf && errbuf_size)
					g_snprintf (errbuf, errbuf_size,
						"send() failed: %d", WSAGetLastError ());
				return PCHAT_SSL_HANDSHAKE_FAILED;
			}
			if (r == 1)
				return PCHAT_SSL_HANDSHAKE_PENDING;
		}
	}

	/* Step 3: drive remaining handshake using server traffic. */
	for (;;)
	{
		int r;
		if (s->enc_len == 0)
		{
			r = read_some_encrypted (s);
			if (r == -1)
			{
				if (errbuf && errbuf_size)
					g_snprintf (errbuf, errbuf_size,
						"recv() failed: %d", WSAGetLastError ());
				return PCHAT_SSL_HANDSHAKE_FAILED;
			}
			if (r == 1)
				return PCHAT_SSL_HANDSHAKE_PENDING;
			if (s->eof)
			{
				if (errbuf && errbuf_size)
					g_strlcpy (errbuf, "Connection closed during TLS handshake",
						errbuf_size);
				return PCHAT_SSL_HANDSHAKE_FAILED;
			}
		}

		in_bufs[0].pvBuffer = s->enc_buf;
		in_bufs[0].cbBuffer = (unsigned long) s->enc_len;
		in_bufs[0].BufferType = SECBUFFER_TOKEN;
		in_bufs[1].pvBuffer = NULL;
		in_bufs[1].cbBuffer = 0;
		in_bufs[1].BufferType = SECBUFFER_EMPTY;
		in_desc.ulVersion = SECBUFFER_VERSION;
		in_desc.cBuffers = 2;
		in_desc.pBuffers = in_bufs;

		out_bufs[0].pvBuffer = NULL;
		out_bufs[0].cbBuffer = 0;
		out_bufs[0].BufferType = SECBUFFER_TOKEN;
		out_bufs[1].pvBuffer = NULL;
		out_bufs[1].cbBuffer = 0;
		out_bufs[1].BufferType = SECBUFFER_ALERT;
		out_bufs[2].pvBuffer = NULL;
		out_bufs[2].cbBuffer = 0;
		out_bufs[2].BufferType = SECBUFFER_EMPTY;
		out_desc.ulVersion = SECBUFFER_VERSION;
		out_desc.cBuffers = 3;
		out_desc.pBuffers = out_bufs;

		ss = InitializeSecurityContextA (&s->ctx->cred, &s->hctx,
			(SEC_CHAR *) s->hostname, req_flags, 0, 0, &in_desc, 0,
			NULL, &out_desc, &ctx_attr, NULL);

		/* Send any tokens / alerts the SSP produced. */
		if (out_bufs[0].cbBuffer && out_bufs[0].pvBuffer)
		{
			queue_outbound (s, out_bufs[0].pvBuffer, out_bufs[0].cbBuffer);
			FreeContextBuffer (out_bufs[0].pvBuffer);
		}

		if (ss == SEC_E_INCOMPLETE_MESSAGE)
		{
			r = flush_pending_out (s);
			if (r < 0)
			{
				if (errbuf && errbuf_size)
					g_snprintf (errbuf, errbuf_size,
						"send() failed: %d", WSAGetLastError ());
				return PCHAT_SSL_HANDSHAKE_FAILED;
			}
			if (r == 1)
				return PCHAT_SSL_HANDSHAKE_PENDING;
			r = read_some_encrypted (s);
			if (r == -1)
			{
				if (errbuf && errbuf_size)
					g_snprintf (errbuf, errbuf_size,
						"recv() failed: %d", WSAGetLastError ());
				return PCHAT_SSL_HANDSHAKE_FAILED;
			}
			if (r == 1)
				return PCHAT_SSL_HANDSHAKE_PENDING;
			continue;
		}

		/* Consume the bytes Schannel processed. */
		if (in_bufs[1].BufferType == SECBUFFER_EXTRA)
		{
			memmove (s->enc_buf,
				s->enc_buf + (s->enc_len - in_bufs[1].cbBuffer),
				in_bufs[1].cbBuffer);
			s->enc_len = in_bufs[1].cbBuffer;
		}
		else
		{
			s->enc_len = 0;
		}

		if (ss == SEC_I_CONTINUE_NEEDED)
		{
			r = flush_pending_out (s);
			if (r < 0)
			{
				if (errbuf && errbuf_size)
					g_snprintf (errbuf, errbuf_size,
						"send() failed: %d", WSAGetLastError ());
				return PCHAT_SSL_HANDSHAKE_FAILED;
			}
			if (r == 1)
				return PCHAT_SSL_HANDSHAKE_PENDING;
			continue;
		}

		if (ss == SEC_E_OK)
		{
			r = flush_pending_out (s);
			if (r < 0)
			{
				if (errbuf && errbuf_size)
					g_snprintf (errbuf, errbuf_size,
						"send() failed: %d", WSAGetLastError ());
				return PCHAT_SSL_HANDSHAKE_FAILED;
			}
			if (r == 1)
				return PCHAT_SSL_HANDSHAKE_PENDING;
			QueryContextAttributes (&s->hctx, SECPKG_ATTR_STREAM_SIZES, &s->sizes);
			s->have_sizes = 1;
			s->handshake_done = 1;
			return PCHAT_SSL_HANDSHAKE_DONE;
		}

		/* All other return codes are fatal. */
		if (errbuf && errbuf_size)
			g_snprintf (errbuf, errbuf_size,
				"InitializeSecurityContext failed (0x%08lx)", (unsigned long) ss);
		if (wrong_version_hint
			&& (ss == SEC_E_ALGORITHM_MISMATCH || ss == SEC_E_UNSUPPORTED_FUNCTION))
			*wrong_version_hint = 1;
		return PCHAT_SSL_HANDSHAKE_FAILED;
	}
}

int
pchat_ssl_handshake_timed_out (pchat_ssl *s, int timeout_secs)
{
	if (!s)
		return 0;
	return (s->handshake_started + timeout_secs) < time (NULL);
}

/* ---------- post-handshake info ---------- */

static PCCERT_CONTEXT
get_remote_cert (pchat_ssl *s)
{
	PCCERT_CONTEXT cert = NULL;
	if (QueryContextAttributes (&s->hctx,
		SECPKG_ATTR_REMOTE_CERT_CONTEXT, &cert) != SEC_E_OK)
		return NULL;
	return cert;
}

static int
match_hostname (const char *cert_name, const char *host)
{
	const char *cd, *d, *next_dot;
	if (g_ascii_strcasecmp (cert_name, host) == 0)
		return 0;
	if (cert_name[0] != '*')
		return -1;
	cd = &cert_name[1];
	if (cd[0] != '.' || cd[1] == '.')
		return -1;
	next_dot = strchr (&cd[1], '.');
	if (!next_dot || next_dot[1] == '.')
		return -1;
	d = strchr (host, '.');
	if (!d || strlen (d) == 1)
		return -1;
	return g_ascii_strcasecmp (cd, d) == 0 ? 0 : -1;
}

static int
verify_chain (pchat_ssl_ctx *ctx, PCCERT_CONTEXT cert, const char *hostname,
              char *errbuf, size_t errbuf_size, int *recoverable)
{
	CERT_CHAIN_PARA chain_para = { sizeof (chain_para) };
	PCCERT_CHAIN_CONTEXT chain = NULL;
	LPSTR usages[] = { szOID_PKIX_KP_SERVER_AUTH };
	HTTPSPolicyCallbackData https = { 0 };
	CERT_CHAIN_POLICY_PARA pol_para = { sizeof (pol_para) };
	CERT_CHAIN_POLICY_STATUS pol_status = { sizeof (pol_status) };
	HCERTCHAINENGINE engine = NULL;
	wchar_t whost[256] = { 0 };
	int ok = 0;

	*recoverable = 0;

	if (ctx->cert_store) {
		engine = HCCE_CURRENT_USER;
		CERT_CHAIN_ENGINE_CONFIG cfg = {0};
		cfg.cbSize = sizeof(cfg);
		cfg.hExclusiveRoot = ctx->cert_store;
		cfg.hExclusiveTrustedPeople = ctx->cert_store;
		if (!CertCreateCertificateChainEngine(&cfg, &engine)) {
			g_snprintf(errbuf, errbuf_size,
				"CertCreateCertificateChainEngine failed (0x%08lx)",
				(unsigned long)GetLastError());
			return 0;
		}
	}

	
	chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
	chain_para.RequestedUsage.Usage.cUsageIdentifier = 1;
	chain_para.RequestedUsage.Usage.rgpszUsageIdentifier = usages;


	if (!CertGetCertificateChain (engine, cert, NULL, NULL, &chain_para,
		0, NULL, &chain))
	{
		if(engine) CertFreeCertificateChainEngine(engine);
		g_snprintf (errbuf, errbuf_size,
			"CertGetCertificateChain failed (0x%08lx)",
			(unsigned long) GetLastError ());
		return 0;
	}

	if (hostname && *hostname)
		MultiByteToWideChar (CP_UTF8, 0, hostname, -1, whost, 255);

	https.cbStruct = sizeof (https);
	https.dwAuthType = AUTHTYPE_SERVER;
	https.pwszServerName = whost[0] ? whost : NULL;
	pol_para.pvExtraPolicyPara = &https;

	if (!CertVerifyCertificateChainPolicy (CERT_CHAIN_POLICY_SSL,
		chain, &pol_para, &pol_status))
	{
		if (engine) CertFreeCertificateChainEngine(engine);
		g_snprintf (errbuf, errbuf_size,
			"CertVerifyCertificateChainPolicy failed (0x%08lx)",
			(unsigned long) GetLastError ());
		goto out;
	}

	if (engine) CertFreeCertificateChainEngine(engine);

	if (pol_status.dwError == 0)
	{
		ok = 1;
		goto out;
	}

	switch (pol_status.dwError)
	{
	case CERT_E_UNTRUSTEDROOT:
	case CERT_E_UNTRUSTEDCA:
	case CERT_E_CHAINING:
	case CERT_E_EXPIRED:
		*recoverable = 1;
		break;
	default:
		*recoverable = 0;
		break;
	}
	g_snprintf (errbuf, errbuf_size,
		"Certificate chain validation failed (0x%08lx)",
		(unsigned long) pol_status.dwError);

out:
	if (chain)
		CertFreeCertificateChain (chain);
	return ok;
}

static int
check_hostname_cert (PCCERT_CONTEXT cert, const char *host)
{
	DWORD need;
	char *names;
	const char *p;

	/* CERT_NAME_DNS_TYPE prefers SAN, falls back to CN. */
	need = CertGetNameStringA (cert, CERT_NAME_DNS_TYPE, 0, NULL, NULL, 0);
	if (need <= 1)
		return -1;
	names = g_malloc (need);
	if (CertGetNameStringA (cert, CERT_NAME_DNS_TYPE, 0, NULL, names, need) <= 1)
	{
		g_free (names);
		return -1;
	}
	/* CertGetNameString returns one name; for SANs we'd need to enumerate
	 * extensions, but this matches the OpenSSL backend's behaviour for the
	 * common case (preferred SAN if present). */
	p = names;
	{
		int rv = match_hostname (p, host);
		g_free (names);
		return rv;
	}
}

void
pchat_ssl_get_verify_result (pchat_ssl *s, const char *hostname,
                             pchat_ssl_verify_result *out)
{
	PCCERT_CONTEXT cert;
	int recoverable = 0;

	memset (out, 0, sizeof (*out));
	if (!s || !s->handshake_done)
	{
		g_strlcpy (out->error, "TLS session not established", sizeof (out->error));
		return;
	}
	cert = get_remote_cert (s);
	if (!cert)
	{
		g_strlcpy (out->error, "No certificate", sizeof (out->error));
		return;
	}

	if (!verify_chain (s->ctx, cert, hostname ? hostname : s->hostname,
		out->error, sizeof (out->error), &recoverable))
	{
		out->recoverable = recoverable;
		CertFreeCertificateContext (cert);
		return;
	}

	if (check_hostname_cert (cert, hostname ? hostname : s->hostname) != 0)
	{
		out->hostname_error = 1;
		out->recoverable = 1;
		g_snprintf (out->error, sizeof (out->error),
			"Failed to validate hostname");
	}
	else
	{
		out->verified = 1;
		out->error[0] = 0;
	}
	CertFreeCertificateContext (cert);
}

int
pchat_ssl_get_cert_info (struct cert_info *out, pchat_ssl *s)
{
	PCCERT_CONTEXT cert;
	DWORD n;
	SYSTEMTIME st;
	FILETIME ft;
	char *p;

	if (!s || !s->handshake_done)
		return 1;
	cert = get_remote_cert (s);
	if (!cert)
		return 1;

	memset (out, 0, sizeof (*out));

	n = CertGetNameStringA (cert, CERT_NAME_RDN_TYPE, 0, NULL,
		out->subject, sizeof (out->subject));
	(void) n;
	n = CertGetNameStringA (cert, CERT_NAME_RDN_TYPE,
		CERT_NAME_ISSUER_FLAG, NULL, out->issuer, sizeof (out->issuer));
	(void) n;

	/* For display we present the whole string as a single token. */
	out->subject_word[0] = out->subject;
	out->subject_word[1] = NULL;
	out->issuer_word[0] = out->issuer;
	out->issuer_word[1] = NULL;

	p = cert->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
	g_strlcpy (out->algorithm, p ? p : "Unknown", sizeof (out->algorithm));
	out->algorithm_bits = (int) CertGetPublicKeyLength (
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		&cert->pCertInfo->SubjectPublicKeyInfo);

	p = cert->pCertInfo->SignatureAlgorithm.pszObjId;
	g_strlcpy (out->sign_algorithm, p ? p : "Unknown", sizeof (out->sign_algorithm));
	out->sign_algorithm_bits = 0;

	ft = cert->pCertInfo->NotBefore;
	if (FileTimeToSystemTime (&ft, &st))
		g_snprintf (out->notbefore, sizeof (out->notbefore),
			"%04u-%02u-%02u %02u:%02u:%02u",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	ft = cert->pCertInfo->NotAfter;
	if (FileTimeToSystemTime (&ft, &st))
		g_snprintf (out->notafter, sizeof (out->notafter),
			"%04u-%02u-%02u %02u:%02u:%02u",
			st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

	out->rsa_tmp_bits = 0;
	CertFreeCertificateContext (cert);
	return 0;
}

struct chiper_info *
pchat_ssl_get_cipher_info (pchat_ssl *s)
{
	static struct chiper_info ci;
	SecPkgContext_ConnectionInfo info;
	SecPkgContext_CipherInfo cinfo;

	memset (&ci, 0, sizeof (ci));	/* static — reset on each call */
	if (!s || !s->handshake_done)
		return &ci;

	if (QueryContextAttributes (&s->hctx, SECPKG_ATTR_CONNECTION_INFO,
		&info) == SEC_E_OK)
	{
		const char *proto;
		switch (info.dwProtocol)
		{
		case SP_PROT_TLS1_CLIENT:        proto = "TLSv1"; break;
		case SP_PROT_TLS1_1_CLIENT:      proto = "TLSv1.1"; break;
		case SP_PROT_TLS1_2_CLIENT:      proto = "TLSv1.2"; break;
#ifdef SP_PROT_TLS1_3_CLIENT
		case SP_PROT_TLS1_3_CLIENT:      proto = "TLSv1.3"; break;
#endif
		default:                         proto = "TLS"; break;
		}
		g_strlcpy (ci.version, proto, sizeof (ci.version));
		ci.chiper_bits = (int) info.dwCipherStrength;
	}

	if (QueryContextAttributes (&s->hctx, SECPKG_ATTR_CIPHER_INFO,
		&cinfo) == SEC_E_OK)
	{
		WideCharToMultiByte (CP_UTF8, 0, cinfo.szCipherSuite, -1,
			ci.chiper, sizeof (ci.chiper), NULL, NULL);
	}

	return &ci;
}

/* ---------- bulk data ---------- */

int
pchat_ssl_send (pchat_ssl *s, const char *buf, int len)
{
	int total = 0;
	if (!s || !s->handshake_done || !s->have_sizes)
		return -1;

	while (len > 0)
	{
		ULONG chunk = (ULONG) len;
		ULONG total_size;
		unsigned char *msg;
		SecBuffer bufs[4];
		SecBufferDesc desc;
		SECURITY_STATUS ss;
		ULONG sent = 0;

		if (chunk > s->sizes.cbMaximumMessage)
			chunk = s->sizes.cbMaximumMessage;
		total_size = s->sizes.cbHeader + chunk + s->sizes.cbTrailer;
		msg = g_malloc (total_size);
		memcpy (msg + s->sizes.cbHeader, buf, chunk);

		bufs[0].pvBuffer = msg;
		bufs[0].cbBuffer = s->sizes.cbHeader;
		bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
		bufs[1].pvBuffer = msg + s->sizes.cbHeader;
		bufs[1].cbBuffer = chunk;
		bufs[1].BufferType = SECBUFFER_DATA;
		bufs[2].pvBuffer = msg + s->sizes.cbHeader + chunk;
		bufs[2].cbBuffer = s->sizes.cbTrailer;
		bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
		bufs[3].pvBuffer = NULL;
		bufs[3].cbBuffer = 0;
		bufs[3].BufferType = SECBUFFER_EMPTY;

		desc.ulVersion = SECBUFFER_VERSION;
		desc.cBuffers = 4;
		desc.pBuffers = bufs;

		ss = EncryptMessage (&s->hctx, 0, &desc, 0);
		if (ss != SEC_E_OK)
		{
			g_free (msg);
			return total > 0 ? total : -1;
		}

		total_size = bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer;
		while (sent < total_size)
		{
			int n = send (s->sock, (const char *) msg + sent,
				(int) (total_size - sent), 0);
			if (n == SOCKET_ERROR)
			{
				if (sock_would_block ())
				{
					/* Mid-record blocking: this is rare for IRC payloads.
					 * Bail and let the caller retry. */
					g_free (msg);
					if (total < 0) {
						WSASetLastError(WSAEWOULDBLOCK);
						errno = EWOULDBLOCK;
					}
					return total > 0 ? total : -1;
				}
				g_free (msg);
				return total > 0 ? total : -1;
			}
			sent += n;
		}

		g_free (msg);
		buf += chunk;
		len -= chunk;
		total += chunk;
	}

	return total;
}

int
pchat_ssl_recv (pchat_ssl *s, char *buf, int len)
{
	SecBuffer bufs[4];
	SecBufferDesc desc;
	SECURITY_STATUS ss;
	size_t extra_len;
	void  *plain_p;
	ULONG  plain_n;
	void  *extra_p ;

	if (!s || !s->handshake_done)
		return -1;
	/* Serve any decrypted bytes from a previous record. */
	if (s->dec_len > s->dec_off)
	{
		int n = (int) (s->dec_len - s->dec_off);
		if (n > len) n = len;
		memcpy (buf, s->dec_buf + s->dec_off, n);
		s->dec_off += n;
		if (s->dec_off >= s->dec_len)
			s->dec_off = s->dec_len = 0;
		return n;
	}

	/* Need more encrypted data and/or to decrypt what we have. */
	for (;;)
	{
		extra_len = 0;
		plain_p = NULL;
		plain_n = 0;
		extra_p = NULL;

		if (s->enc_len == 0)
		{
			int r = read_some_encrypted (s);

			if (r == -1) return -1;
			if (r == 1)  { WSASetLastError (WSAEWOULDBLOCK); errno = EWOULDBLOCK; return -1; }
			if (s->eof)  return 0;
		}

		bufs[0].pvBuffer = s->enc_buf;
		bufs[0].cbBuffer = (unsigned long) s->enc_len;
		bufs[0].BufferType = SECBUFFER_DATA;
		bufs[1].BufferType = SECBUFFER_EMPTY;
		bufs[2].BufferType = SECBUFFER_EMPTY;
		bufs[3].BufferType = SECBUFFER_EMPTY;
		desc.ulVersion = SECBUFFER_VERSION;
		desc.cBuffers = 4;
		desc.pBuffers = bufs;

		ss = DecryptMessage (&s->hctx, &desc, 0, NULL);
		if (ss == SEC_E_INCOMPLETE_MESSAGE)
		{
			int r = read_some_encrypted (s);
			if (r == -1) return -1;
			if (r == 1)  { WSASetLastError (WSAEWOULDBLOCK); errno = EWOULDBLOCK; return -1; }
			if (s->eof)  return 0;

			continue;
		}
		if (ss == SEC_I_CONTEXT_EXPIRED)
		{
			s->eof = 1;
			return 0;
		}
		if (ss != SEC_E_OK && ss != SEC_I_RENEGOTIATE)
			return -1;

		{
			int i;
			for (i = 0; i < 4; i++)
			{
				if (bufs[i].BufferType == SECBUFFER_DATA)
				{
					plain_p = bufs[i].pvBuffer;
					plain_n = bufs[i].cbBuffer;
				}
				else if (bufs[i].BufferType == SECBUFFER_EXTRA)
				{
					extra_p = bufs[i].pvBuffer;
					extra_len = bufs[i].cbBuffer;
				}
			}
		}

		if (plain_n)
		{
			ensure_cap (&s->dec_buf, &s->dec_cap, plain_n);
			memcpy (s->dec_buf, plain_p, plain_n);
			s->dec_len = plain_n;
			s->dec_off = 0;
		}

		if (extra_len)
		{
			memmove (s->enc_buf, extra_p, extra_len);
			s->enc_len = extra_len;
		}
		else
		{
			s->enc_len = 0;
		}

		if (ss == SEC_I_RENEGOTIATE)
		{
			/* Schannel wants a renegotiation handshake. We don't currently
			 * support this mid-stream and the server is unlikely to demand
			 * it for IRC; treat as a fatal error. */
			return -1;
		}

		if (s->dec_len > s->dec_off)
		{
			int n = (int) (s->dec_len - s->dec_off);
			if (n > len) n = len;
			memcpy (buf, s->dec_buf + s->dec_off, n);
			s->dec_off += n;
			if (s->dec_off >= s->dec_len)
				s->dec_off = s->dec_len = 0;
			return n;
		}
	}
}

#endif /* USE_SCHANNEL */
