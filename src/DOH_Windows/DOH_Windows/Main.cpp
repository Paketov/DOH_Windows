/*
* DOH_Windows, DNS Over HTTPS for windows
* Solodov A. N. (hotSAN)
* 2021
*/

#include "LqFile.h"

#ifdef LQPLATFORM_WINDOWS

# if  defined(_WINDOWS_) && !defined(_WINSOCK2API_)
#  error "Must stay before windows.h!"
# endif
# include <winsock2.h>
# include <ws2tcpip.h>
# include <ws2def.h>
# include <ws2ipdef.h>
# include <wchar.h>

# pragma comment(lib, "Ws2_32.lib")
# pragma comment(lib, "Mswsock.lib")
# pragma comment(lib, "legacy_stdio_definitions.lib")
//#pragma comment(lib, "msvcrt.lib")

# include <Windows.h>
# include <stdio.h>
# include <stdint.h>
# include <process.h>
# include <wincrypt.h>
# include <cryptuiapi.h>

# pragma comment (lib, "crypt32.lib")
# pragma comment (lib, "cryptui.lib")

#else
# include <sys/socket.h> 
# include <sys/sendfile.h>
# include <fcntl.h>


#endif

#include "LqFile.h"
#include "LqParse.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/opensslv.h>



#include "LqAlloc.hpp"


#define REQ_PKT_SIZE 4096


# ifndef WSA_VERSION
#  define WSA_VERSION MAKEWORD(2, 2)
# endif

# include <io.h>
static struct _wsa_data {
	LPWSADATA wsa;
	_wsa_data() {
		static WSADATA wd;
		WSAStartup(WSA_VERSION, &wd);
		wsa = &wd;
	}
	~_wsa_data() {
		WSACleanup();
	}
} wsa_data;

//If compile as .exe
#ifndef _WINDLL
# define DOH_CONSOLE_DBG
#endif

typedef struct HttpsServerInfo {
	char* Query;
	char* Ip;
	char* Port;
}HttpsServerInfo;

typedef union ConnAddr {
	struct sockaddr         Addr;
	struct sockaddr_in      AddrInet;
	struct sockaddr_in6     AddrInet6;
	struct sockaddr_storage AddrStorage;
} ConnAddr;

typedef struct DnsReq {
	DnsReq* NextTsk;
	DnsReq* PrevTsk;
	ConnAddr From;
	int FromLen;
	uint8_t Buf[REQ_PKT_SIZE];
	int BufLen;
}DnsReq;

typedef struct Worker {
	LqLocker<unsigned> TskLoker;
	DnsReq* StartTsk;
	DnsReq* EndTsk;
	DnsReq* CurTsk;
	int TskLen;
	int Event;
	unsigned ThreadId;
	HANDLE ThreadHandle;
	HttpsServerInfo* ServerInfo;
	volatile bool IsEndWork;
} Worker;

typedef struct ResponceHost {
	char* Name;
	ConnAddr RspIP;
	bool IsNotResponse;
} ResponceHost;


#pragma pack(push)
#pragma pack(1)

typedef struct DnsPkt{
	uint16_t Id;
	uint16_t Flags;
	uint16_t QueryCount;
	uint16_t AnsRRs;
	uint16_t AutorRRs;
	uint16_t AddisRRs;
} DnsPkt;

typedef struct DnsPktQuery {
	uint16_t Type;
	uint16_t Class;
} DnsPktQuery;

typedef struct DnsPktResp {
	uint16_t Name;
	uint16_t Type;
	uint16_t Class;
	uint32_t TTL;
	uint16_t DataLen;
	uint8_t  IpAddr[1]; //Various size
} DnsPktResp;

#pragma pack(pop)



FILE _iob[] = { *stdin, *stdout, *stderr };

extern "C" FILE * __cdecl __iob_func(void) {
	return _iob;
}
/* match: search for regexp anywhere in text */
static int match(char *regexp, char *text);

static int ConnBindUDP(
	const char* Host,
	const char* Port,
	int MaxConnections
	) {
	static const int True = 1;
	int s;
	addrinfo *Addrs = nullptr, HostInfo = { 0 };
	HostInfo.ai_family = AF_UNSPEC;
	HostInfo.ai_socktype = SOCK_DGRAM; // SOCK_STREAM;
	HostInfo.ai_flags = AI_PASSIVE;//AI_ALL;
	HostInfo.ai_protocol = IPPROTO_UDP; // IPPROTO_TCP;
	int res;
	if ((res = getaddrinfo(((Host != NULL) && (*Host != '\0')) ? Host : (const char*)NULL, Port, &HostInfo, &Addrs)) != 0) {
		return -1;
	}

	for (auto i = Addrs; i != NULL; i = i->ai_next) {
		if ((s = socket(i->ai_family, i->ai_socktype, i->ai_protocol)) == -1)
			continue;
		LqDescrSetInherit(s, 0);
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&True, sizeof(True)) == -1) {
			continue;
		}
		if (i->ai_family == AF_INET6) {
			if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&True, sizeof(True)) == -1) {
				continue;
			}
		}
		if (bind(s, i->ai_addr, i->ai_addrlen) == -1) {
			closesocket(s);
			s = -1;
			continue;
		}
		break;
	}

	if (Addrs != nullptr)
		freeaddrinfo(Addrs);
	return s;
}

static int ConnConnectTCP(
	const char* Address,
	const char* Port
) {
	int s = -1;
	addrinfo hi = { 0 }, *ah = nullptr, *i;

	hi.ai_family = AF_UNSPEC;
	hi.ai_socktype = SOCK_STREAM; // SOCK_STREAM;
	hi.ai_protocol = IPPROTO_TCP; // IPPROTO_TCP;
	hi.ai_flags = 0;//AI_ALL;

	int res;
	if ((res = getaddrinfo(((Address != NULL) && (*Address != '\0')) ? Address : (const char*)NULL, Port, &hi, &ah)) != 0) {
		return -1;
	}

	for (i = ah; i != NULL; i = i->ai_next) {
		if ((s = socket(i->ai_family, i->ai_socktype, i->ai_protocol)) == -1)
			continue;
		if (connect(s, i->ai_addr, i->ai_addrlen) != -1)
			break;
		closesocket(s);
	}
	if (i == NULL) {
		if (ah != NULL)
			freeaddrinfo(ah);
		return -1;
	}
	if (ah != NULL)
		freeaddrinfo(ah);
	return s;
}


int CountServers = 0;
int CountWorkers = 2;
int UDPSocket = -1;
Worker** Workers = NULL;
HttpsServerInfo* ServersInfo = NULL;
LqTimeMillisec DisconnectWaitTime = 12000; //12 seconds
char* LocalAddress = "0.0.0.0", *LocalAddress2 = LocalAddress;
char* LocalPort = "53", *LocalPort2 = LocalPort;
int StopServiceEvent = -1;
int CountRspHosts = 0;
ResponceHost* RspHosts = NULL;
char*SSL_CACertFileForVerify = NULL;


//Service
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;
#define SVCNAME L"DOH_Windows"


static void ParseConfigFile(int ConfigFileSize, char* ConfigFile) {
	//Parse config file
	typedef enum CUR_READ_STATE {
		CUR_STATE_DEFAULT,
		CUR_STATE_LOC_ADDR,
		CUR_STATE_DOH_SERV,
		CUR_STATE_HOSTS
	} CUR_READ_STATE;
	CUR_READ_STATE State = CUR_STATE_DEFAULT;

	CountServers = 0;
	CountRspHosts = 0;
	ServersInfo = NULL;
	RspHosts = NULL;
	DisconnectWaitTime = 12000;
	LocalAddress = LocalAddress2;
	LocalPort = LocalPort2;
	SSL_CACertFileForVerify = NULL;


	for (char* c = ConfigFile, *m = c + ConfigFileSize; (c < m) && (*c != '\0'); ) {
		for (; (c < m) && ((*c == ' ') || (*c == '\t') || (*c == '\n') || (*c == '\r')); c++);
		if ((c >= m) || (*c == '\0'))
			break;
		if (strnicmp(c, "localaddress:", sizeof("localaddress:") - 1) == 0) {
			State = CUR_STATE_LOC_ADDR;
			c += (sizeof("localaddress:") - 1);
			for (; (c < m) && ((*c == ' ') || (*c == '\t') || (*c == ':')); c++);
			continue;
		}
		if (strnicmp(c, "dohservers:", sizeof("dohservers:") - 1) == 0) {
			State = CUR_STATE_DOH_SERV;
			c += (sizeof("dohservers:") - 1);
			for (; (c < m) && ((*c == ' ') || (*c == '\t') || (*c == ':')); c++);
			continue;
		}
		if (strnicmp(c, "countworkers:", sizeof("countworkers:") - 1) == 0) {
			State = CUR_STATE_DEFAULT;
			c += (sizeof("countworkers:") - 1);
			for (; (c < m) && ((*c == ' ') || (*c == '\t') || (*c == ':') || (*c == '\n') || (*c == '\r')); c++);
			CountWorkers = atoi(c);
			for (; (c < m) && (*c != ' ') && (*c != '\t') && (*c != '\n') && (*c != '\r'); c++);
		}

		if (strnicmp(c, "disconnectwaittime:", sizeof("disconnectwaittime:") - 1) == 0) {
			State = CUR_STATE_DEFAULT;
			c += (sizeof("disconnectwaittime:") - 1);
			for (; (c < m) && ((*c == ' ') || (*c == '\t') || (*c == ':') || (*c == '\n') || (*c == '\r')); c++);
			DisconnectWaitTime = atoi(c);
			for (; (c < m) && (*c != ' ') && (*c != '\t') && (*c != '\n') && (*c != '\r'); c++);
		}

		if (strnicmp(c, "hostsmatch:", sizeof("hostsmatch:") - 1) == 0) {
			State = CUR_STATE_HOSTS;
			c += (sizeof("hostsmatch:") - 1);
			for (; (c < m) && ((*c == ' ') || (*c == '\t') || (*c == ':')); c++);
			continue;
		}

		if (strnicmp(c, "cacertfile:", sizeof("cacertfile:") - 1) == 0) { //pem file for verify root certs
			State = CUR_STATE_DEFAULT;
			c += (sizeof("cacertfile:") - 1);
			for (; (c < m) && ((*c == ' ') || (*c == '\t') || (*c == ':') || (*c == '\n') || (*c == '\r')); c++);
			char* StartPath = c;
			for (; (c < m) && (*c != '\n') && (*c != '\r'); c++);
			char* EndPath = c;

			SSL_CACertFileForVerify = (char*)malloc((EndPath - StartPath) + 10);
			strncpy(SSL_CACertFileForVerify, StartPath, EndPath - StartPath);
			SSL_CACertFileForVerify[EndPath - StartPath] = '\0';
		}

		switch (State) {
			case CUR_STATE_LOC_ADDR: {
				for (; (c < m) && ((*c == ' ') || (*c == '\t')); c++);
				char* StartIpAddress = c;
				for (; (c < m) && (*c != ' ') && (*c != '\t'); c++);
				char* EndIpAddress = c;

				for (; (c < m) && ((*c == ' ') || (*c == '\t')); c++);
				char* StartPort = c;
				for (; (c < m) && (*c != ' ') && (*c != '\t') && (*c != '\n') && (*c != '\r'); c++);
				char* EndPort = c;

				for (; (c < m) && ((*c == ' ') || (*c == '\t')); c++);

				LocalAddress = (char*)malloc((EndIpAddress - StartIpAddress) + 10);
				strncpy(LocalAddress, StartIpAddress, EndIpAddress - StartIpAddress);
				LocalAddress[EndIpAddress - StartIpAddress] = '\0';

				LocalPort = (char*)malloc((EndPort - StartPort) + 10);
				strncpy(LocalPort, StartPort, EndPort - StartPort);
				LocalPort[EndPort - StartPort] = '\0';
			}break;
			case CUR_STATE_DOH_SERV: {
				for (; (c < m) && ((*c == ' ') || (*c == '\t')); c++);
				char* StartIpAddress = c;
				for (; (c < m) && (*c != ' ') && (*c != '\t'); c++);
				char* EndIpAddress = c;

				for (; (c < m) && ((*c == ' ') || (*c == '\t')); c++);
				char* StartPort = c;
				for (; (c < m) && (*c != ' ') && (*c != '\t'); c++);
				char* EndPort = c;

				for (; (c < m) && ((*c == ' ') || (*c == '\t')); c++);
				char* StartQuery = c;
				for (; (c < m) && (*c != '\r') && (*c != '\n'); c++);
				char* EndQuery = c;

				CountServers++;
				ServersInfo = (HttpsServerInfo*)realloc(ServersInfo, CountServers* sizeof(HttpsServerInfo));

				ServersInfo[CountServers - 1].Ip = (char*)malloc((EndIpAddress - StartIpAddress) + 2);
				strncpy(ServersInfo[CountServers - 1].Ip, StartIpAddress, EndIpAddress - StartIpAddress);
				ServersInfo[CountServers - 1].Ip[EndIpAddress - StartIpAddress] = '\0';

				ServersInfo[CountServers - 1].Port = (char*)malloc((EndPort - StartPort) + 2);
				strncpy(ServersInfo[CountServers - 1].Port, StartPort, EndPort - StartPort);
				ServersInfo[CountServers - 1].Port[EndPort - StartPort] = '\0';


				ServersInfo[CountServers - 1].Query = (char*)malloc((EndQuery - StartQuery) + 2);
				strncpy(ServersInfo[CountServers - 1].Query, StartQuery, EndQuery - StartQuery);
				ServersInfo[CountServers - 1].Query[EndQuery - StartQuery] = '\0';
			}break;
			case CUR_STATE_HOSTS: {
				for (; (c < m) && ((*c == ' ') || (*c == '\t')); c++);
				char* StartHost = c;
				for (; (c < m) && (*c != ' ') && (*c != '\t') && (*c != '\r') && (*c != '\n') && (*c != '\0'); c++);
				char* EndHost = c;

				for (; (c < m) && ((*c == ' ') || (*c == '\t')); c++);
				char* StartIp = c;
				for (; (c < m) && (*c != ' ') && (*c != '\t') && (*c != '\0') && (*c != '\r') && (*c != '\n'); c++);
				char* EndIp = c;

				RspHosts = (ResponceHost*)realloc(RspHosts, (CountRspHosts + 1) * sizeof(RspHosts[0]));
				RspHosts[CountRspHosts].Name = (char*)malloc((EndHost - StartHost) + 2);
				strncpy(RspHosts[CountRspHosts].Name, StartHost, EndHost - StartHost);
				RspHosts[CountRspHosts].Name[EndHost - StartHost] = '\0';
				char OrigEndIp = *EndIp;
				*EndIp = '\0';
				RspHosts[CountRspHosts].IsNotResponse = false;

				if (StartIp == EndIp)
					goto lblIpIsEmpty;

				if (inet_pton(AF_INET, StartIp, &RspHosts[CountRspHosts].RspIP.AddrInet.sin_addr) > 0) {
					RspHosts[CountRspHosts].RspIP.Addr.sa_family = AF_INET;
				} else if(inet_pton(AF_INET6, StartIp, &RspHosts[CountRspHosts].RspIP.AddrInet6.sin6_addr) > 0) {
					RspHosts[CountRspHosts].RspIP.Addr.sa_family = AF_INET6;
				} else {
lblIpIsEmpty:
					RspHosts[CountRspHosts].IsNotResponse = true;
					memset(&RspHosts[CountRspHosts].RspIP, 0, sizeof(RspHosts[CountRspHosts].RspIP));
					RspHosts[CountRspHosts].RspIP.Addr.sa_family = AF_INET;
				}
				*EndIp = OrigEndIp;
				CountRspHosts++;
			}break;
		}
	}
}


/* string match pattern */
static int matchhere(char *regexp, char *text);
static int matchstar(int c, char *regexp, char *text);

//c    matches any literal character c
//?    matches any single character
//^    matches the beginning of the input string
//$    matches the end of the input string
//*    matches zero or more occurrences of the previous character

/* match: search for regexp anywhere in text */
static int match(char *regexp, char *text){
	if (regexp[0] == '^')
		return matchhere(regexp + 1, text);
	do {    /* must look even if string is empty */
		if (matchhere(regexp, text))
			return 1;
	} while (*text++ != '\0');
	return 0;
}

/* matchhere: search for regexp at beginning of text */
static int matchhere(char *regexp, char *text){
	if (regexp[0] == '\0')
		return 1;
	if (regexp[1] == '*')
		return matchstar(regexp[0], regexp + 2, text);
	if (regexp[0] == '$' && regexp[1] == '\0')
		return *text == '\0';
	if (*text != '\0' && (regexp[0] == '?' || regexp[0] == *text))
		return matchhere(regexp + 1, text + 1);
	return 0;
}

/* matchstar: search for c*regexp at beginning of text */
static int matchstar(int c, char *regexp, char *text) {
	do {    /* a * matches zero or more instances */
		if (matchhere(regexp, text))
			return 1;
	} while (*text != '\0' && (*text++ == c || c == '?'));
	return 0;
}




static int GetDomainsNamesFromDNSPkt(const void* Dns, size_t DnsLen, char* DstBuf, size_t DstBufLen) {
	if (DnsLen <= (sizeof(DnsPkt) + sizeof(DnsPktQuery) + 1))
		return 0;
	const DnsPkt* DnsVal = (const DnsPkt*)Dns;
	const char* Querys = (const char*)(DnsVal + 1);
	int QueryCount = htons(DnsVal->QueryCount);
	if (QueryCount > 100)
		return 0;
	char* DstPos = DstBuf;
	const char* c = Querys;
	int i = 0;
	for (; (i < QueryCount) && (c < ((const char*)Dns + DnsLen)); i++) {
		for (; c < ((const char*)Dns + DnsLen);) {
			uint8_t CountCharsInSubDomen = *((uint8_t*)c);
			if (CountCharsInSubDomen == 0)
				break;
			c++;
			for (
				const char *m = (const char*)Dns + DnsLen, *m2 = DstBuf + DstBufLen, *m3 = c + CountCharsInSubDomen;
				(c < m3) && (c < m) && (DstPos < m2);
				c++, DstPos++
			) {
				*DstPos = *c;
			}
			if ((DstPos + 2) >= (DstBuf + DstBufLen))
				return 0;
			if (c >= ((const char*)Dns + DnsLen))
				return 0;
			if (*((uint8_t*)c) > 0) {
				*DstPos = '.';
				DstPos++;
			}
		}

		if ((DstPos + 2) >= (DstBuf + DstBufLen))
			return 0;
		*DstPos = '\0';
		DstPos++;
		c += sizeof(DnsPktQuery);
	}
	return i;
}

static bool SetWindowsSSLStoreCerts(X509_STORE* X509_store) {
	HCERTSTORE hStore;
	PCCERT_CONTEXT pContext = NULL;
	X509 *x509;

	hStore = CertOpenSystemStoreW(NULL, L"ROOT");
	if (!hStore)
		return false;
	while (pContext = CertEnumCertificatesInStore(hStore, pContext)) {
		//uncomment the line below if you want to see the certificates as pop ups
		//CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, pContext,   NULL, NULL, 0, NULL);
		if (x509 = d2i_X509(NULL, (const unsigned char **)&pContext->pbCertEncoded, pContext->cbCertEncoded)){
			X509_STORE_add_cert(X509_store, x509);
			X509_free(x509);
		}
	}
	CertFreeCertificateContext(pContext);
	CertCloseStore(hStore, 0);
	return true;
}

static unsigned __stdcall WorkerProc(void* data) {
	Worker* Wrk = (Worker*)data;

	int Socket = -1;
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
	SSL* ssl = NULL;
	bool IsVerifyCA = true;
	SSL_CTX_set_default_verify_paths(ctx);
	if (SSL_CACertFileForVerify != NULL) {
		if (SSL_CTX_load_verify_locations(ctx, SSL_CACertFileForVerify, NULL) != 1) {
			OutputDebugString(TEXT("DOH_Windows: SSL SSL_CTX_load_verify_locations() returned 0, PEM file cert for verify not used"));
#ifdef DOH_CONSOLE_DBG
			printf("SSL_CTX_load_verify_locations() returned 0, PEM file cert for verify not used on ip %s\n", Wrk->ServerInfo->Ip);
#endif
			IsVerifyCA = false;
		}
	} else {
		//Used for not get X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY error from SSL_get_verify_result()
		X509_STORE* Store = SSL_CTX_get_cert_store(ctx);
		if (Store == NULL) {
			IsVerifyCA = false;
#ifdef DOH_CONSOLE_DBG
			printf("SSL_CTX_get_cert_store() returned NULL, cert verify not used on ip %s\n", Wrk->ServerInfo->Ip);
#endif
			OutputDebugString(TEXT("DOH_Windows: SSL SSL_CTX_get_cert_store() returned NULL, cert verify not used"));
		} else {
			if (!SetWindowsSSLStoreCerts(Store)) {
				IsVerifyCA = false;
#ifdef DOH_CONSOLE_DBG
				printf("Cannot set local windows root certs, cert verify not used on ip %s\n", Wrk->ServerInfo->Ip);
#endif
				OutputDebugString(TEXT("DOH_Windows: SSL Cannot set local windows root certs, cert verify not used"));
			}
		}
	}


	LqTimeMillisec WaitTime = INFINITE;
	int CountFds = 1;
	LqPoll Fds[2];
	DnsReq* CurTsk;
	Fds[0].fd = Wrk->Event;
	Fds[0].events = LQ_POLLIN;
	int QueryStringLen = strlen(Wrk->ServerInfo->Query);
	char* QueryString = (char*)malloc(QueryStringLen + 3);
	char* HostString = (char*)malloc(QueryStringLen + 3);
	char* PathString = (char*)malloc(QueryStringLen + 3);
	strncpy(QueryString, Wrk->ServerInfo->Query, QueryStringLen);
	QueryString[QueryStringLen] = '\0';

	char* SchemeStart; char* SchemeEnd;
	char* UserInfoStart; char* UserInfoEnd;
	char* HostStart; char* HostEnd;
	char* PortStart; char* PortEnd;
	char* DirStart; char* DirEnd;
	char* QueryStart; char* QueryEnd;
	char* FragmentStart; char* FragmentEnd;
	char* End; char TypeHost;

	LqHttpPrsUrl(QueryString,
		&SchemeStart, &SchemeEnd,
		&UserInfoStart, &UserInfoEnd,
		&HostStart, &HostEnd,
		&PortStart, &PortEnd,
		&DirStart, &DirEnd,
		&QueryStart, &QueryEnd,
		&FragmentStart, &FragmentEnd,
		&End, &TypeHost,
		NULL, NULL
		);
	strncpy(HostString, HostStart, HostEnd - HostStart);
	HostString[HostEnd - HostStart] = '\0';
	strncpy(PathString, DirStart, End - DirStart);
	PathString[End - DirStart] = '\0';

	if (IsVerifyCA) {
		char Buf[500];
		//SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
		snprintf(
			Buf,
			sizeof(Buf),
			"DOH_Windows: SSL cert verification is used on ip: %s, host: %s",
			Wrk->ServerInfo->Ip, 
			HostString
			);
		OutputDebugStringA(Buf);
#ifdef DOH_CONSOLE_DBG
		printf("SSL cert verification is used on ip: %s, host: %s\n", Wrk->ServerInfo->Ip, HostString);
#endif
	}

	char SendBuffer[6000];
	char* SendBufferFilledPos = SendBuffer;
	char* SendBufferFilledPosEnd = SendBuffer;
	char Base64Buf[1024];

	char ReciveBuffer[6000];
	char* ReciveBufferFilledPosEnd = ReciveBuffer;

	for (;;) {

		Fds[1].revents = 0;
		int PollRes = LqPollCheck(Fds, CountFds, WaitTime);
		if (Fds[0].revents & LQ_POLLIN) { //If have input task event
#ifdef DOH_CONSOLE_DBG
			printf("Event recived %s\n", Wrk->ServerInfo->Ip);
#endif
			LqEventReset(Fds[0].fd);
			if ((Wrk->StartTsk != NULL) && (Socket == -1)) { //???? ???? ?????????? ? HTTPS ????????, ??????????
				Socket = ConnConnectTCP(Wrk->ServerInfo->Ip, Wrk->ServerInfo->Port);
				if (Socket == -1) {
#ifdef DOH_CONSOLE_DBG
					printf("Conn error %s\n", Wrk->ServerInfo->Ip);
#endif
					goto lblPollHup;
				}
				ssl = SSL_new(ctx);

				if (SSL_set_fd(ssl, Socket) == 0) {
					goto lblPollHup;
				}

				if (IsVerifyCA) {
					SSL_set_hostflags(ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
					if (!SSL_set1_host(ssl, HostString)) {
						goto lblPollHup;
					}
				}
				int SslConnectRes;
				if ((SslConnectRes = SSL_connect(ssl)) < 0) {
					goto lblPollHup;
				}

				if (IsVerifyCA) {
					long VerRes = SSL_get_verify_result(ssl);
					if (VerRes != X509_V_OK) {//X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
						char Buf[500];
						const char * VerErrStr = X509_verify_cert_error_string(VerRes);
						snprintf(
							Buf, 
							sizeof(Buf), 
							"DOH_Windows: SSL_get_verify_result() on host %s(ip %s) returned error num = %i, str = \"%s\"", 
							HostString,
							Wrk->ServerInfo->Ip, 
							(int)VerRes, 
							VerErrStr
						);
						OutputDebugStringA(Buf);
#ifdef DOH_CONSOLE_DBG
						printf(
							"SSL_get_verify_result() on host %s (ip %s) returned error num=%i, str=\"%s\"\n", 
							HostString, 
							Wrk->ServerInfo->Ip, 
							(int)VerRes, 
							VerErrStr
						);
#endif
						goto lblPollHup;
					}
				}
				
				LqConnSwitchNonBlock(Socket, true);
				WaitTime = DisconnectWaitTime;
				Fds[1].fd = Socket;
				Fds[1].events = LQ_POLLHUP;
				CountFds = 2;
#ifdef DOH_CONSOLE_DBG
				printf("Conn created %s\n", Wrk->ServerInfo->Ip);
#endif
			}
			for (;;) {
				Wrk->TskLoker.LockReadYield();
				CurTsk = Wrk->CurTsk;
				Wrk->TskLoker.UnlockRead();

				if (CurTsk == NULL) {
					break;
				}

				int Base64Len = LqDataToBase64(true, false, CurTsk->Buf, CurTsk->BufLen, Base64Buf, sizeof(Base64Buf) - 3);
				if ((SendBufferFilledPosEnd + (Base64Len + 256)) > (SendBuffer + sizeof(SendBuffer))) {
					int FilledSize = SendBufferFilledPosEnd - SendBufferFilledPos;
					memmove(SendBuffer, SendBufferFilledPos, FilledSize);
					SendBufferFilledPosEnd = SendBuffer + FilledSize;
					SendBufferFilledPos = SendBuffer;
				}
				if ((SendBufferFilledPosEnd + (Base64Len + 256)) > (SendBuffer + sizeof(SendBuffer))) { //If queue very hight
					goto Continue4;
				}
				int WrittenInBuf = snprintf(
					SendBufferFilledPosEnd,
					sizeof(SendBuffer) - (SendBufferFilledPosEnd - SendBuffer),
					"GET %s?dns=%s HTTP/1.1\r\n"
					"Host: %s\r\n"
					"Accept: application/dns-udpwireformat\r\n"
					"Connection: keep-alive\r\n"
					"\r\n",
					PathString,
					Base64Buf,
					HostString
					);
				Fds[1].events |= LQ_POLLOUT;
				Fds[1].revents |= LQ_POLLOUT;
				SendBufferFilledPosEnd += WrittenInBuf;

				Wrk->TskLoker.LockWriteYield();
				Wrk->CurTsk = Wrk->CurTsk->PrevTsk;
				Wrk->TskLoker.UnlockWrite();
			}


		Continue4:;
		}
		if ((CountFds > 1) && ((Fds[1].revents & LQ_POLLOUT) || ((SendBufferFilledPosEnd - SendBufferFilledPos) > 0))) { //Is need send data via socket
			int FilledSize = SendBufferFilledPosEnd - SendBufferFilledPos;

			if (FilledSize > 0) {
				int Written = SSL_write(ssl, SendBufferFilledPos, FilledSize);
				if (Written <= 0) {
					switch (SSL_get_error(ssl, Written)) {
					case SSL_ERROR_NONE: break;
					case SSL_ERROR_WANT_READ: Fds[1].events |= LQ_POLLIN; goto lblContinue1;
					case SSL_ERROR_WANT_WRITE: Fds[1].events |= LQ_POLLOUT; goto lblContinue1;
					case SSL_ERROR_ZERO_RETURN: goto lblPollHup;
					default: goto lblContinue1;
					}
				}
				SendBufferFilledPos += Written;
				FilledSize = SendBufferFilledPosEnd - SendBufferFilledPos;
				Fds[1].events |= LQ_POLLIN;
			}
		lblContinue1:;
			if (FilledSize <= 0) {
				Fds[1].events &= ~LQ_POLLOUT;
				WaitTime = DisconnectWaitTime;
			} else {
				WaitTime = 500;
			}
		}
		if ((CountFds > 1) && (Fds[1].revents & LQ_POLLIN)) { //If have data in socket
			int FilledSize = ReciveBufferFilledPosEnd - ReciveBuffer;
			int Readed = SSL_read(ssl, ReciveBufferFilledPosEnd, sizeof(ReciveBuffer) - FilledSize);
			if (Readed <= 0) {
				switch (SSL_get_error(ssl, Readed)) {
				case SSL_ERROR_NONE: break;
				case SSL_ERROR_WANT_READ: Fds[1].events |= LQ_POLLIN; goto lblContinue2;
				case SSL_ERROR_WANT_WRITE: Fds[1].events |= LQ_POLLOUT; goto lblContinue2;
				case SSL_ERROR_ZERO_RETURN: goto lblPollHup;
				default: goto lblContinue2;
				}
			}
			ReciveBufferFilledPosEnd += Readed;
		lblContinue2:;
			int ContentLen = -1;
			int RetStatus = -1;
			bool IsHaveEndHeaders = false;
			char* c;

			for (c = ReciveBuffer; c < (ReciveBufferFilledPosEnd - 4); c++) {
				if ((c[0] == '\r') && (c[1] == '\n') && (c[2] == '\r') && (c[3] == '\n')) { //If have all headers
					IsHaveEndHeaders = true;
					{
						char *k = ReciveBuffer;
						for (; (k < c) && ((*k == ' ') || (*k == '\t')); k++);
						for (; (k < c) && (*k != ' ') && (*k != '\t'); k++);
						for (; (k < c) && ((*k == ' ') || (*k == '\t')); k++);
						RetStatus = atoi(k);
					}
					for (char* u = ReciveBuffer; u < c; u++) {
						if ((u[0] == '\r') && (u[1] == '\n')) {
							u += 2;
							for (; (u < c) && ((*u == ' ') || (*u == '\t')); u++);
							if (strnicmp(u, "content-length", sizeof("content-length") - 1) == 0) {
								u += (sizeof("content-length") - 1);
								for (; (u < c) && ((*u == '\t') || (*u == ' ') || (*u == ':')); u++);
								ContentLen = atoi(u);
								if ((ContentLen <= 0) || (ContentLen > (((int)sizeof(ReciveBuffer)) - ((c + 20) - ReciveBuffer))))
									goto lblPollHup;

								goto lblContinue3;
							}
						}
					}
				}
			}
		lblContinue3:;
			if (IsHaveEndHeaders && (((c + 4) + ContentLen) <= ReciveBufferFilledPosEnd)) {
				if (ContentLen < 0) {
					goto lblPollHup;
				}
				c += 4;

				Wrk->TskLoker.LockReadYield();
				DnsReq* FisrtReq = Wrk->EndTsk;
				Wrk->TskLoker.UnlockRead();
				if (RetStatus == 200) {
#ifdef DOH_CONSOLE_DBG
					printf("Call sendto() send DNS pkt %s\n", Wrk->ServerInfo->Ip);
#endif
					sendto(UDPSocket, c, ContentLen, 0, (sockaddr*)&FisrtReq->From, FisrtReq->FromLen);
				} else {
					if (ContentLen == -1)
						ContentLen = 0;
				}
				Wrk->TskLoker.LockWriteYield();
				FisrtReq = Wrk->EndTsk;
				Wrk->EndTsk = FisrtReq->PrevTsk;
				if (Wrk->CurTsk == FisrtReq) {
					Wrk->CurTsk = FisrtReq->PrevTsk;
				}
				if (Wrk->EndTsk == NULL) {
					Wrk->StartTsk = NULL;
				} else {
					Wrk->EndTsk->NextTsk = NULL;
				}
				Wrk->TskLen--;
				Wrk->TskLoker.UnlockWrite();

				LqFastAlloc::Delete(FisrtReq);


				memmove(ReciveBuffer, c + ContentLen, ReciveBufferFilledPosEnd - (c + ContentLen));
				ReciveBufferFilledPosEnd -= ((c + ContentLen) - ReciveBuffer);

				if (ReciveBufferFilledPosEnd > ReciveBuffer)
					goto lblContinue2;
			}
		}

		if ((Fds[1].revents & LQ_POLLHUP) || ((WaitTime == DisconnectWaitTime) && (PollRes == 0)) || Wrk->IsEndWork) {
		lblPollHup:;
#ifdef DOH_CONSOLE_DBG
			printf("Conn closed %s\n", Wrk->ServerInfo->Ip);
#endif
			if (ssl != NULL) {
				SSL_shutdown(ssl);
				SSL_free(ssl);
				ssl = NULL;
			}
			if (Socket != -1) {
				closesocket(Socket);
				Socket = -1;
			}
			WaitTime = INFINITE;
			CountFds = 1;

			Fds[1].events = 0;

			SendBufferFilledPos = SendBuffer;
			SendBufferFilledPosEnd = SendBuffer;
			ReciveBufferFilledPosEnd = ReciveBuffer;

			Wrk->TskLoker.LockWriteYield();
			//LqEventReset(Fds[0].fd);
			for (DnsReq* r = Wrk->StartTsk, *f; r != NULL; r = f) {
				f = r->NextTsk;
				LqFastAlloc::Delete(r);
			}
			Wrk->CurTsk = NULL;
			Wrk->StartTsk = NULL;
			Wrk->EndTsk = NULL;
			Wrk->TskLen = 0;
			Wrk->TskLoker.UnlockWrite();
			if (Wrk->IsEndWork)
				break;
		}
	}
	SSL_CTX_free(ctx);
	free(QueryString);
	free(HostString);
	free(PathString);
	return 0;
}

VOID UpdateServiceStatus(DWORD currentState) {
	serviceStatus.dwCurrentState = currentState;
	SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

static unsigned __stdcall MainDOH(void* data) {
	OutputDebugString(TEXT("DOH_Windows: Start DOH_Main()"));
	StopServiceEvent = LqEventCreate(1);

	char HostsListInputReq[4096];

	int ConfigFileSize;
	char ConfigFile2[] =
		"CountWorkers:\n"
		"2\n"
		"LocalAddress:\n"
		" 0.0.0.0 53\n"
		"DOHServers:\n"
		" 1.1.1.1 443 https://cloudflare-dns.com/dns-query\n"
		" 8.8.8.8 443 https://dns.google/dns-query\n",
		*ConfigFile = ConfigFile2;

	ConfigFileSize = sizeof(ConfigFile2);

	OutputDebugString(TEXT("DOH_Windows: DOH_Main() open doh.txt"));
	FILE* OpenedConfigFile = fopen("C:\\Windows\\System32\\drivers\\etc\\doh.txt", "rb");
	if (OpenedConfigFile != NULL) {
		fseek(OpenedConfigFile, 0, SEEK_END);
		ConfigFileSize = ftell(OpenedConfigFile);
		fseek(OpenedConfigFile, 0, SEEK_SET);
		ConfigFile = (char*)malloc(ConfigFileSize + 2);
		fread(ConfigFile, 1, ConfigFileSize, OpenedConfigFile);
		fclose(OpenedConfigFile);
		ConfigFile[ConfigFileSize] = '\0';
		OutputDebugString(TEXT("DOH_Windows: DOH_Main() doh.txt readed"));
	}

	ParseConfigFile(ConfigFileSize, ConfigFile);
	OutputDebugString(TEXT("DOH_Windows: ParseConfigFile() executed"));
	SSL_load_error_strings();
	SSL_library_init();

	OutputDebugString(TEXT("DOH_Windows: SSL_library_init() executed"));
	UDPSocket = ConnBindUDP(LocalAddress, LocalPort, 1024);
	if (UDPSocket == -1) {
		OutputDebugString(TEXT("DOH_Windows: Error not binded to UDP port"));
		goto lblOut;
	}
	OutputDebugString(TEXT("DOH_Windows: ConnBindUDP() executed"));

	CountWorkers = max(CountWorkers, CountServers);
	if (CountServers < 1) {
		OutputDebugString(TEXT("DOH_Windows: DOH_Main() Error CountServers < 1"));
		closesocket(UDPSocket);
		goto lblOut;
	}
	Workers = (Worker**)malloc(sizeof(*Workers) * CountWorkers);

	for (int i = 0; i < CountWorkers; i++) {
		OutputDebugString(TEXT("DOH_Windows: Register worker"));
		Worker* Wrk = LqFastAlloc::New<Worker>();
		Workers[i] = Wrk;
		Wrk->CurTsk = Wrk->EndTsk = Wrk->StartTsk = NULL;
		Wrk->TskLen = 0;
		Wrk->IsEndWork = false;
		Wrk->Event = LqEventCreate(1);
		Wrk->ServerInfo = &(ServersInfo[i % CountServers]);
		uintptr_t Handler = _beginthreadex(NULL, 0, WorkerProc, Wrk, 0, &Wrk->ThreadId);
		Wrk->ThreadHandle = (HANDLE)Handler;
	}
	OutputDebugString(TEXT("DOH_Windows: Enter recvfrom loop"));
	UpdateServiceStatus(SERVICE_RUNNING);
	for (;;) {
		DnsReq* Req = LqFastAlloc::New<DnsReq>();
	lblContinue5:;
		Req->FromLen = sizeof(Req->From);
		Req->BufLen = 0;

		int res = recvfrom(UDPSocket, (char*)Req->Buf, sizeof(Req->Buf), 0, (sockaddr*)&Req->From, &Req->FromLen);
#ifdef DOH_CONSOLE_DBG
		if (res <= 0) {
			int RecvfromErr = WSAGetLastError(); //WSAECONNRESET
			printf("recvfrom() return -1, error code: %i\n", RecvfromErr);
		} else {
			printf("Recived DNS pkt\n");
		}
#endif
		if (LqPollCheckSingle(StopServiceEvent, LQ_POLLIN, 1) & LQ_POLLIN) {
			OutputDebugString(TEXT("DOH_Windows: MainDOH() recive stop event"));
			LqFastAlloc::Delete(Req);
			break;
		}

		if (res <= 0) {
			//if (UDPSocket != -1)
			//closesocket(UDPSocket);
			//UDPSocket = ConnBindUDP(LocalAddress, LocalPort, 1024);
			//Sleep(500);
			goto lblContinue5;
		}
		Req->BufLen = res;

		if (CountRspHosts > 0) { //If have hosts list, then enum all elements in host list and match patterns
			int CountQuer = GetDomainsNamesFromDNSPkt(Req->Buf, Req->BufLen, HostsListInputReq, sizeof(HostsListInputReq));
			if (CountQuer > 0) {
				char* c = HostsListInputReq;
				for (int i = 0; i < CountQuer; i++) {
					char* t = c;
					for (int k = 0; k < CountRspHosts; k++) {
						if (match(RspHosts[k].Name, t)) {
							if(RspHosts[k].IsNotResponse)
								goto lblContinue5;
							int RspLen = 0;
							if (RspHosts[k].RspIP.Addr.sa_family == AF_INET) {
								if((Req->BufLen + sizeof(DnsPktResp) + 4) >= sizeof(Req->Buf))
									goto lblContinue5;
								RspLen = (Req->BufLen + sizeof(DnsPktResp) + 3);
							} else {
								if ((Req->BufLen + sizeof(DnsPktResp) + 16) >= sizeof(Req->Buf))
									goto lblContinue5;
								RspLen = (Req->BufLen + sizeof(DnsPktResp) + 15);
							}
							DnsPkt* DnsVal = (DnsPkt*)Req->Buf;
							DnsPktResp* Response = (DnsPktResp*)(((char*)DnsVal) + Req->BufLen);
							DnsVal->AnsRRs = htons(1u);
							DnsVal->Flags |= htons(0x8000u);
							Response->Class = htons(0x0001u);
							Response->TTL = htonl(200);
							Response->Name = htons(0xC00Cu);

							if (RspHosts[k].RspIP.Addr.sa_family == AF_INET) {
								Response->Type = htons(1u);
								Response->DataLen = htons(4u);
								memcpy(Response->IpAddr, &RspHosts[k].RspIP.AddrInet.sin_addr, 4);
							} else {
								Response->Type = htons(28u);
								Response->DataLen = htons(16u);
								memcpy(Response->IpAddr, &RspHosts[k].RspIP.AddrInet6.sin6_addr, 16);
							}
							sendto(UDPSocket, (char*)Req->Buf, RspLen, 0, (sockaddr*)&Req->From, Req->FromLen);
							goto lblContinue5;
						}
					}
					for (; *c != '\0'; c++);
					c++;
				}
			}
		}
		

		int TargetWrk = 0;
		for (int i = 0, MinTskLen = 0x7fffffff; i < CountWorkers; i++) {
			if (Workers[i]->TskLen < MinTskLen) {
				MinTskLen = Workers[i]->TskLen;
				TargetWrk = i;
			}
		}
		Workers[TargetWrk]->TskLoker.LockWriteYield();

		Req->NextTsk = Workers[TargetWrk]->StartTsk;
		Req->PrevTsk = NULL;
		if (Req->NextTsk != NULL) {
			Req->NextTsk->PrevTsk = Req;
		}
		Workers[TargetWrk]->StartTsk = Req;

		if (Workers[TargetWrk]->EndTsk == NULL) {
			Workers[TargetWrk]->EndTsk = Req;
		}
		if (Workers[TargetWrk]->CurTsk == NULL) {
			Workers[TargetWrk]->CurTsk = Req;
		}
		Workers[TargetWrk]->TskLen++;
		Workers[TargetWrk]->TskLoker.UnlockWrite();

		LqEventSet(Workers[TargetWrk]->Event);
#ifdef DOH_CONSOLE_DBG
		printf("Send job to worker(set event)\n");
#endif
	}
lblOut:

	OutputDebugString(TEXT("DOH_Windows: Service stopping in process"));

	if (Workers != NULL) {
		for (int i = 0; i < CountWorkers; i++) {
			Workers[i]->IsEndWork = true;
			LqEventSet(Workers[i]->Event);
			WaitForSingleObject(Workers[i]->ThreadHandle, INFINITE);
			CloseHandle(Workers[i]->ThreadHandle);
			LqFileClose(Workers[i]->Event);
			LqFastAlloc::Delete(Workers[i]);
		}
		free(Workers);
	}
	//if (UDPSocket != -1) {
	//	closesocket(UDPSocket);
	//}

	if (ConfigFile2 != ConfigFile) {
		free(ConfigFile);
	}
	if (ServersInfo != NULL) {
		for (int i = 0; i < CountServers; i++) {
			free(ServersInfo[i].Ip);
			free(ServersInfo[i].Port);
			free(ServersInfo[i].Query);
		}
		free(ServersInfo);
	}

	if (LocalAddress2 != LocalAddress) {
		free(LocalAddress);
	}
	if (LocalPort2 != LocalPort) {
		free(LocalPort);
	}
	if (SSL_CACertFileForVerify != NULL) {
		free(SSL_CACertFileForVerify);
	}

	if (CountRspHosts > 0) {
		for (int i = 0; i < CountRspHosts; i++)
			free(RspHosts[i].Name);
		free(RspHosts);
	}
	if(StopServiceEvent != -1)
		LqFileClose(StopServiceEvent);

	UpdateServiceStatus(SERVICE_STOPPED);
	OutputDebugString(TEXT("DOH_Windows: Service return from MainDOH()"));
	return 0;
}


DWORD WINAPI ServiceHandler(DWORD dwControl) {
	switch (dwControl) {
	case SERVICE_CONTROL_STOP:
		OutputDebugString(TEXT("DOH_Windows: Runing ServiceHandler(SERVICE_CONTROL_STOP)"));
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		LqEventSet(StopServiceEvent);
		if(UDPSocket != -1)
			closesocket(UDPSocket);
		break;
	case SERVICE_CONTROL_SHUTDOWN:
		OutputDebugString(TEXT("DOH_Windows: Runing ServiceHandler(SERVICE_CONTROL_SHUTDOWN)"));
		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		LqEventSet(StopServiceEvent);
		if(UDPSocket != -1)
			closesocket(UDPSocket);
		break;
	case SERVICE_CONTROL_PAUSE:
		OutputDebugString(TEXT("DOH_Windows: Runing ServiceHandler(SERVICE_CONTROL_PAUSE)"));
		serviceStatus.dwCurrentState = SERVICE_PAUSED;
		break;
	case SERVICE_CONTROL_CONTINUE:
		OutputDebugString(TEXT("DOH_Windows: Runing ServiceHandler(SERVICE_CONTROL_CONTINUE)"));
		serviceStatus.dwCurrentState = SERVICE_RUNNING;
		break;
	case SERVICE_CONTROL_INTERROGATE:
		break;
	default:
		break;
	}
	//serviceStatus.dwCurrentState
	UpdateServiceStatus(serviceStatus.dwCurrentState);
	//UpdateServiceStatus(SERVICE_RUNNING);

	return NO_ERROR;
}

#ifdef DOH_CONSOLE_DBG

int main() {
	MainDOH(NULL);
	return 0;
}

#endif

extern "C" __declspec(dllexport) VOID WINAPI ServiceMain(DWORD argc, LPTSTR argv[]) {
	OutputDebugString(TEXT("DOH_Windows: Start ServiceMain()"));

	serviceStatusHandle = RegisterServiceCtrlHandlerW(SVCNAME, (LPHANDLER_FUNCTION)ServiceHandler);

	serviceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
	serviceStatus.dwServiceSpecificExitCode = 0;
	serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	serviceStatus.dwWin32ExitCode = NO_ERROR;
	serviceStatus.dwServiceSpecificExitCode = 0;
	serviceStatus.dwCheckPoint = 0;
	UpdateServiceStatus(SERVICE_START_PENDING);

	//unsigned int ThreadId = 0;
	//_beginthreadex(NULL, 0, MainDOH, NULL, 0, &ThreadId);
	MainDOH(NULL);
}


extern "C" __declspec(dllexport) VOID WINAPI InstallService() {
	OutputDebugString(TEXT("DOH_Windows: Start InstallService()"));

	HKEY hKey;
	DWORD dwType, cbData;
	char Buf[1024];
	wchar_t* wBuf = (wchar_t*)Buf;
	LSTATUS Ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost", 0, KEY_READ | KEY_SET_VALUE | KEY_WRITE, &hKey);
	if (Ret != ERROR_SUCCESS) {
		OutputDebugString(TEXT("DOH_Windows: RegOpenKeyExW() Cannot open Svchost reg key"));
		return;
	}

	cbData = sizeof(Buf);
	Ret = RegQueryValueExW(hKey, L"NetworkService", NULL, &dwType, (LPBYTE)Buf, &cbData);
	if (Ret != ERROR_SUCCESS) {
		OutputDebugString(TEXT("DOH_Windows: RegQueryValueExW() Cannot open NetworkService reg value"));
		return;
	}
	for (wchar_t* c = wBuf, *m = (wchar_t*)(((char*)wBuf) + cbData); c < m; c++) {
		int len = wcslen(c);
		if (wcsicmp(L"DOH_Windows", c) == 0) {
			OutputDebugString(TEXT("DOH_Windows: wcsicmp() has been added service"));
			return;
		}
		OutputDebugStringW((LPCWSTR)c);
		c += len;
	}

	memmove(Buf + sizeof(L"DOH_Windows"), Buf, cbData);
	memcpy(Buf, L"DOH_Windows", sizeof(L"DOH_Windows"));
	cbData += sizeof(L"DOH_Windows");
	Ret = RegSetValueExW(hKey, L"NetworkService", NULL, dwType, (BYTE*)Buf, cbData);
	if (Ret != ERROR_SUCCESS) {
		OutputDebugString(TEXT("DOH_Windows: RegSetValueExW() Reg value NetworkService not setted"));
	}
	else {
		OutputDebugString(TEXT("DOH_Windows: RegSetValueExW() Reg value NetworkService has been setted"));
	}
}




#define __METHOD_DECLS__
#include "LqAlloc.hpp"