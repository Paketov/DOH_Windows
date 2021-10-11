/*
* DOH_Windows, DNS Over HTTPS for windows
* Solodov A. N. (hotSAN)
* 2021
*/

# if  defined(_WINDOWS_) && !defined(_WINSOCK2API_)
#  error "Must stay before windows.h!"
# endif
# include <winsock2.h>
# include <ws2tcpip.h>
# include <ws2def.h>
# include <ws2ipdef.h>
# include <wchar.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "legacy_stdio_definitions.lib")
//#pragma comment(lib, "msvcrt.lib")

#include <Windows.h>
#include <stdio.h>
#include <stdint.h>
#include <process.h>
#include "LqFile.h"
#include "LqParse.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#include "LqAlloc.hpp"





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


typedef struct HttpsServerInfo {
	wchar_t* Query;
	wchar_t* Ip;
	wchar_t* Port;

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
	uint8_t Buf[4096];
	int BufLen;
}DnsReq;

typedef struct Worker {
	LqLocker<unsigned> TskLoker;
	DnsReq* StartTsk;
	DnsReq* EndTsk;
	DnsReq* CurTsk;
	int TskLen;
	int Event;
	unsigned TreadId;
	HANDLE ThreadHandle;
	HttpsServerInfo* ServerInfo;
	bool IsEndWork;
} Worker;

FILE _iob[] = { *stdin, *stdout, *stderr };

extern "C" FILE * __cdecl __iob_func(void) {
	return _iob;
}


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
	if ((res = getaddrinfo(((Host != nullptr) && (*Host != '\0')) ? Host : (const char*)nullptr, Port, &HostInfo, &Addrs)) != 0) {
		return -1;
	}

	for (auto i = Addrs; i != nullptr; i = i->ai_next) {
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

int ConnConnectTCP(
	const wchar_t* Address,
	const wchar_t* Port
) {
	int s = -1;
	ADDRINFOW hi = { 0 }, *ah = nullptr, *i;

	hi.ai_family = AF_UNSPEC;
	hi.ai_socktype = SOCK_STREAM; // SOCK_STREAM;
	hi.ai_protocol = IPPROTO_TCP; // IPPROTO_TCP;
	hi.ai_flags = 0;//AI_ALL;

	int res;
	if ((res = GetAddrInfoW(((Address != nullptr) && (*Address != '\0')) ? Address : (const wchar_t*)nullptr, Port, &hi, &ah)) != 0) {
		return -1;
	}

	for (i = ah; i != nullptr; i = i->ai_next) {
		if ((s = socket(i->ai_family, i->ai_socktype, i->ai_protocol)) == -1)
			continue;
		if (connect(s, i->ai_addr, i->ai_addrlen) != -1)
			break;
		closesocket(s);
	}
	if (i == nullptr) {
		if (ah != nullptr)
			FreeAddrInfoW(ah);
		return -1;
	}
	if (ah != nullptr)
		FreeAddrInfoW(ah);
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
int StopServiceEvent = NULL;

//Service
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle;
#define SVCNAME L"DOH_Windows"


void ParseConfigFile(int ConfigFileSize, char* ConfigFile) {
	//Parse config file
	bool CurLocalAddress = false;
	bool CurDOHServers = false;


	for (char* c = ConfigFile, *m = c + ConfigFileSize; (c < m) && (*c != '\0'); ) {
		for (; (c < m) && ((*c == ' ') || (*c == '\t') || (*c == '\n') || (*c == '\r')); c++);
		if ((c >= m) || (*c == '\0'))
			break;
		if (strnicmp(c, "localaddress", sizeof("localaddress") - 1) == 0) {
			CurLocalAddress = true;
			CurDOHServers = false;
			c += (sizeof("localaddress") - 1);
			for (; (c < m) && ((*c == ' ') || (*c == '\t') || (*c == ':')); c++);
			continue;
		}
		if (strnicmp(c, "dohservers", sizeof("dohservers") - 1) == 0) {
			CurLocalAddress = false;
			CurDOHServers = true;
			c += (sizeof("dohservers") - 1);
			for (; (c < m) && ((*c == ' ') || (*c == '\t') || (*c == ':')); c++);
			continue;
		}
		if (strnicmp(c, "countworkers", sizeof("countworkers") - 1) == 0) {
			c += (sizeof("countworkers") - 1);
			for (; (c < m) && ((*c == ' ') || (*c == '\t') || (*c == ':') || (*c == '\n') || (*c == '\r')); c++);
			CountWorkers = atoi(c);
			for (; (c < m) && (*c != ' ') && (*c != '\t') && (*c != '\n') && (*c != '\r'); c++);
			for (; (c < m) && ((*c == ' ') || (*c == '\t')); c++);
		}

		if (CurLocalAddress) {
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
		}

		if (CurDOHServers) {
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

			ServersInfo[CountServers - 1].Ip = (wchar_t*)malloc(((EndIpAddress - StartIpAddress) + 10) * sizeof(wchar_t));
			int Written = MultiByteToWideChar(
				CP_UTF8,
				0,
				StartIpAddress,
				EndIpAddress - StartIpAddress,
				ServersInfo[CountServers - 1].Ip,
				(EndIpAddress - StartIpAddress) + 10
				);
			ServersInfo[CountServers - 1].Ip[Written] = L'\0';

			ServersInfo[CountServers - 1].Port = (wchar_t*)malloc(((EndPort - StartPort) + 10) * sizeof(wchar_t));
			Written = MultiByteToWideChar(
				CP_UTF8,
				0,
				StartPort,
				EndPort - StartPort,
				ServersInfo[CountServers - 1].Port,
				(EndPort - StartPort) + 10
				);
			ServersInfo[CountServers - 1].Port[Written] = L'\0';


			ServersInfo[CountServers - 1].Query = (wchar_t*)malloc(((EndQuery - StartQuery) + 10) * sizeof(wchar_t));
			Written = MultiByteToWideChar(
				CP_UTF8,
				0,
				StartQuery,
				EndQuery - StartQuery,
				ServersInfo[CountServers - 1].Query,
				(EndQuery - StartQuery) + 10
				);
			ServersInfo[CountServers - 1].Query[Written] = L'\0';
		}
	}
}

static unsigned __stdcall WorkerProc(void* data) {
	Worker* Wrk = (Worker*)data;

	int Socket = -1;
	SSL_CTX* ctx = NULL;
	SSL* ssl = NULL;

	LqTimeMillisec WaitTime = INFINITE;
	int CountFds = 1;
	LqPoll Fds[2];
	DnsReq* CurTsk;
	Fds[0].fd = Wrk->Event;
	Fds[0].events = LQ_POLLIN;
	int QueryStringLen = wcslen(Wrk->ServerInfo->Query) * 3;
	char* QueryString = (char*)malloc(QueryStringLen);
	char* HostString = (char*)malloc(QueryStringLen);
	char* PathString = (char*)malloc(QueryStringLen);
	WideCharToMultiByte(CP_UTF8, 0, Wrk->ServerInfo->Query, -1, QueryString, QueryStringLen, NULL, NULL);

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
			LqEventReset(Fds[0].fd);
			if ((Wrk->StartTsk != NULL) && (Socket == -1)) { //???? ???? ?????????? ? HTTPS ????????, ??????????
				Socket = ConnConnectTCP(Wrk->ServerInfo->Ip, Wrk->ServerInfo->Port);
				if (Socket == -1) {
					goto lblPollHup;
				}
				ctx = SSL_CTX_new(SSLv23_client_method());
				ssl = SSL_new(ctx);

				if (SSL_set_fd(ssl, Socket) == 0) {
					goto lblPollHup;
				}

				if (SSL_connect(ssl) < 0) {
					goto lblPollHup;
				}
				LqConnSwitchNonBlock(Socket, true);
				WaitTime = DisconnectWaitTime;
				Fds[1].fd = Socket;
				Fds[1].events = LQ_POLLHUP;
				CountFds = 2;
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
					"GET %s%s HTTP/1.1\r\n"
					"Host: %s\r\n"
					"Accept: application/dns-udpwireformat\r\n"
					"Connection: keep-alive\r\n"
					"\r\n\r\n",
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
					sendto(UDPSocket, c, ContentLen, 0, (sockaddr*)&FisrtReq->From, FisrtReq->FromLen);
				}
				else {
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
				}
				else {
					Wrk->EndTsk->NextTsk = NULL;
				}
				Wrk->TskLen--;
				Wrk->TskLoker.UnlockWrite();

				LqFastAlloc::Delete(FisrtReq);


				memmove(ReciveBuffer, c + ContentLen, ReciveBufferFilledPosEnd - (c + ContentLen));
				ReciveBufferFilledPosEnd -= ((c + ContentLen) - ReciveBuffer);
			}
		}

		if ((Fds[1].revents & LQ_POLLHUP) || ((WaitTime == DisconnectWaitTime) && (PollRes == 0)) || Wrk->IsEndWork) {
		lblPollHup:;
			if (ssl != NULL) {
				SSL_shutdown(ssl);
				SSL_free(ssl);
				ssl = NULL;
				SSL_CTX_free(ctx);
				ctx = NULL;
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
			LqEventReset(Fds[0].fd);
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

	int ConfigFileSize;
	char* ConfigFile =
		"CountWorkers:\n"
		"2\n"
		"LocalAddress:\n"
		" 0.0.0.0 53\n"
		"DOHServers:\n"
		" 1.1.1.1 443 https://cloudflare-dns.com/dns-query?dns=\n"
		" 8.8.8.8 443 https://dns.google/dns-query?dns=\n",
		*ConfigFile2 = ConfigFile;

	ConfigFileSize = sizeof(ConfigFile);


	FILE* OpenedConfigFile = fopen("C:\\Windows\\System32\\drivers\\etc\\doh.txt", "rb");
	if (OpenedConfigFile != NULL) {
		fseek(OpenedConfigFile, 0, SEEK_END);
		ConfigFileSize = ftell(OpenedConfigFile);
		fseek(OpenedConfigFile, 0, SEEK_SET);
		ConfigFile = (char*)malloc(ConfigFileSize);
		fread(ConfigFile, 1, ConfigFileSize, OpenedConfigFile);
		fclose(OpenedConfigFile);
	}

	ParseConfigFile(ConfigFileSize, ConfigFile);

	SSL_load_error_strings();
	SSL_library_init();

	UDPSocket = ConnBindUDP(LocalAddress, LocalPort, 1024);
	CountWorkers = max(CountWorkers, CountServers);
	if (CountServers < 1)
		return 0;
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
		uintptr_t Handler = _beginthreadex(NULL, 0, WorkerProc, Wrk, 0, &Wrk->TreadId);
		Wrk->ThreadHandle = (HANDLE)Handler;
	}
	OutputDebugString(TEXT("DOH_Windows: Enter "));
	UpdateServiceStatus(SERVICE_RUNNING);
	for (;;) {
		DnsReq* Req = LqFastAlloc::New<DnsReq>();
	lblContinue5:;
		Req->FromLen = sizeof(Req->From);
		Req->BufLen = 0;

		int res = recvfrom(UDPSocket, (char*)Req->Buf, sizeof(Req->Buf), 0, (sockaddr*)&Req->From, &Req->FromLen);
		if (LqPollCheckSingle(StopServiceEvent, LQ_POLLIN, 1) & LQ_POLLIN) {
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
	}
	OutputDebugString(TEXT("DOH_Windows: Service stopped"));

	if (Workers != NULL) {
		for (int i = 0; i < CountWorkers; i++) {
			Workers[i]->IsEndWork = true;
			LqEventSet(Workers[i]->Event);
			Sleep(700);
			LqFastAlloc::Delete(Workers[i]);
		}
		free(Workers);
	}

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
	UpdateServiceStatus(SERVICE_STOPPED);
	return 0;
}


DWORD ServiceHandler(DWORD controlCode, DWORD eventType, LPVOID eventData, LPVOID context) {
	switch (controlCode) {
	case SERVICE_CONTROL_STOP:
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		LqEventSet(StopServiceEvent);
		break;
	case SERVICE_CONTROL_SHUTDOWN:
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		LqEventSet(StopServiceEvent);
		break;
	case SERVICE_CONTROL_PAUSE:
		serviceStatus.dwCurrentState = SERVICE_PAUSED;
		break;
	case SERVICE_CONTROL_CONTINUE:
		serviceStatus.dwCurrentState = SERVICE_RUNNING;
		break;
	case SERVICE_CONTROL_INTERROGATE:
		break;
	default:
		break;
	}

	UpdateServiceStatus(SERVICE_RUNNING);

	return NO_ERROR;
}

extern "C" __declspec(dllexport) VOID WINAPI ServiceMain(DWORD argc, LPTSTR argv[]) {
	OutputDebugString(TEXT("DOH_Windows: Start ServiceMain()"));

	serviceStatusHandle = RegisterServiceCtrlHandlerW(SVCNAME, (LPHANDLER_FUNCTION)ServiceHandler);

	serviceStatus.dwServiceType = SERVICE_WIN32_SHARE_PROCESS;
	serviceStatus.dwServiceSpecificExitCode = 0;

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
	LSTATUS Ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost", 0, KEY_READ|KEY_SET_VALUE| KEY_WRITE, &hKey);
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
	} else {
		OutputDebugString(TEXT("DOH_Windows: RegSetValueExW() Reg value NetworkService has been setted"));
	}
}



#define __METHOD_DECLS__
#include "LqAlloc.hpp"