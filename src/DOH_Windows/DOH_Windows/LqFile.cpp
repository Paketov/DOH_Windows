
/*
* Lanq(Lan Quick)
* Solodov A. N. (hotSAN)
* 2016
*   LqFile... - File layer between os and server.
*/


# if  defined(_WINDOWS_) && !defined(_WINSOCK2API_)
#  error "Must stay before windows.h!"
# endif
# include <winsock2.h>
# include <ws2tcpip.h>
# include <ws2def.h>
# include <ws2ipdef.h>
# include <wchar.h>


#include <Windows.h>
#include <Psapi.h>
#include <ntstatus.h>
#include <Winternl.h>
#include "LqFile.h"

#include "LqAlloc.hpp"


#pragma comment(lib, "ntdll.lib")

typedef enum _EVENT_TYPE {
	NotificationEvent,
	SynchronizationEvent
} EVENT_TYPE, *PEVENT_TYPE;

typedef struct __FILE_PIPE_LOCAL_INFORMATION {
	ULONG NamedPipeType;
	ULONG NamedPipeConfiguration;
	ULONG MaximumInstances;
	ULONG CurrentInstances;
	ULONG InboundQuota;
	ULONG ReadDataAvailable;
	ULONG OutboundQuota;
	ULONG WriteQuotaAvailable;
	ULONG NamedPipeState;
	ULONG NamedPipeEnd;
} __FILE_PIPE_LOCAL_INFORMATION;

extern "C" __kernel_entry NTSTATUS NTAPI NtCreateEvent(
	OUT PHANDLE             EventHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN EVENT_TYPE           EventType,
	IN BOOLEAN              InitialState
	);

extern "C" __kernel_entry NTSTATUS NTAPI NtSetEvent(
	IN HANDLE EventHandle,
	OUT PLONG PreviousState OPTIONAL
	);

extern "C" __kernel_entry NTSTATUS NTAPI NtResetEvent(
	IN HANDLE               EventHandle,
	OUT PLONG               PreviousState OPTIONAL
	);

extern "C" NTSYSAPI NTSTATUS NTAPI NtCancelIoFile(
	_In_ HANDLE               FileHandle,
	_Out_ PIO_STATUS_BLOCK    IoStatusBlock
	);

extern "C" __kernel_entry NTSTATUS NTAPI NtQueryInformationFile(
	__in HANDLE FileHandle,
	__out PIO_STATUS_BLOCK IoStatusBlock,
	__out_bcount(Length) PVOID FileInformation,
	__in ULONG Length,
	__in FILE_INFORMATION_CLASS FileInformationClass
	);

extern "C" __kernel_entry NTSTATUS NTAPI NtReadFile(
	_In_     HANDLE           FileHandle,
	_In_opt_ HANDLE           Event,
	_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
	_In_opt_ PVOID            ApcContext,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_Out_    PVOID            Buffer,
	_In_     ULONG            Length,
	_In_opt_ PLARGE_INTEGER   ByteOffset,
	_In_opt_ PULONG           Key
	);


int LqDescrSetInherit(int Descriptor, int IsInherit) {
	return (SetHandleInformation((HANDLE)Descriptor, HANDLE_FLAG_INHERIT, IsInherit) == TRUE) ? 0 : -1;
}

int LqConnSwitchNonBlock(int Fd, int IsNonBlock) {
	u_long nonBlocking = IsNonBlock;
	if (ioctlsocket(Fd, FIONBIO, &nonBlocking) == -1)
		return -1;
	return 0;
}

bool LqDescrIsSocket(int Fd) {
	int val;
	socklen_t len = sizeof(val);
	return getsockopt(Fd, SOL_SOCKET, SO_ACCEPTCONN, (char*)&val, &len) != -1;
}

bool LqDescrIsTerminal(int Fd) {
	DWORD Mode;
	return GetConsoleMode((HANDLE)Fd, &Mode) == TRUE;
}

int LqEventCreate(int InheritFlag) {
	OBJECT_ATTRIBUTES Attr;
	HANDLE h;
	NTSTATUS Stat;

	InitializeObjectAttributes(&Attr, NULL, (InheritFlag == 0) ? 0 : OBJ_INHERIT, NULL, NULL);
	Stat = NtCreateEvent(&h, EVENT_ALL_ACCESS, &Attr, NotificationEvent, FALSE);
	if (!NT_SUCCESS(Stat)) {
		SetLastError(RtlNtStatusToDosError(Stat));
		return -1;
	}
	return (int)h;
}

int LqEventSet(int FileEvent) {
	return (NtSetEvent((HANDLE)FileEvent, NULL) == STATUS_SUCCESS) ? 0 : -1;
}

int LqEventReset(int FileEvent) {
	LONG PrevVal = 0;
	if (NtResetEvent((HANDLE)FileEvent, &PrevVal) != STATUS_SUCCESS)
		return -1;
	return PrevVal ? 1 : 0;
}

void LqThreadYield() {
	Sleep(0);
}

static DWORD CheckAllEvents(const HANDLE* EventObjs, const intptr_t EventsCount) {
	intptr_t StartIndex = ((intptr_t)0);
	intptr_t Count;
	DWORD Status;
	while (true) {
		Count = EventsCount - StartIndex;
		if (Count >= ((intptr_t)MAXIMUM_WAIT_OBJECTS))
			Count = ((intptr_t)MAXIMUM_WAIT_OBJECTS) - ((intptr_t)1);
		Status = WaitForMultipleObjects(Count, EventObjs + StartIndex, FALSE, 0);
		if ((Status >= WAIT_OBJECT_0) && (Status < (WAIT_OBJECT_0 + MAXIMUM_WAIT_OBJECTS))) {
			return Status;
		}
		else if (Status != WAIT_TIMEOUT) {
			return Status;
		}
		StartIndex += Count;
		if (StartIndex >= ((intptr_t)EventsCount))
			return Status;
	}
}

static char LqPollCheckBuf;

int LqPollCheck(LqPoll* Fds, size_t CountFds, LqTimeMillisec TimeoutMillisec) {
	bool HavePipeOrTerminal = false;
	bool HaveEvents = false;
	LARGE_INTEGER li, *pli;
	IO_STATUS_BLOCK StatusBlock;
	static IO_STATUS_BLOCK ReadStatusBlock;
	WSANETWORKEVENTS NetEvnts;
	DWORD num_read;
	INPUT_RECORD ir;
	NTSTATUS Status;
	DWORD WaitRes;
	__FILE_PIPE_LOCAL_INFORMATION PipeInfo;
	int CountEvents = 0;
	HANDLE* Handles;
	uint8_t* Types;
	LqTimeMillisec CurWaitTime, CurWaitTime2, WaitTime;
	if (CountFds == 0) {
		Sleep(TimeoutMillisec);
		return 0;
	}
	Handles = (HANDLE*)LqMemAlloc(CountFds * sizeof(HANDLE) + CountFds * sizeof(uint8_t));
	Types = (uint8_t*)(Handles + CountFds);
	for (size_t i = 0; i < CountFds; i++) {
		Fds[i].revents = 0;
		if (LqDescrIsSocket(Fds[i].fd)) {
			Types[i] = LQ_POLL_TYPE_SOCKET;
			Handles[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
			WSAEventSelect(Fds[i].fd, Handles[i], LqEvntSystemEventByConnFlag(Fds[i].events));
			WSAEnumNetworkEvents(Fds[i].fd, Handles[i], &NetEvnts);
			if (NetEvnts.lNetworkEvents != 0) {
				Fds[i].revents = LqConnFlagBySysEvent(NetEvnts.lNetworkEvents);
				CountEvents++;
				CloseHandle(Handles[i]);
				Handles[i] = (HANDLE)Fds[i].fd;
			}
		}
		else if (LqDescrIsTerminal(Fds[i].fd)) {
			Types[i] = LQ_POLL_TYPE_TERMINAL;
			HavePipeOrTerminal = true;
			if (Fds[i].events & LQ_POLLIN) {
				while (true) {
					if (!PeekConsoleInputW((HANDLE)Fds[i].fd, &ir, 1, &num_read)) {
						Fds[i].revents = LQ_POLLERR;
						break;
					}
					if (num_read <= 0)
						break;
					if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
						Fds[i].revents = LQ_POLLIN;
						break;
					}
					else {
						ReadConsoleInputW((HANDLE)Fds[i].fd, &ir, 1, &num_read);
					}
				}
			}
			Fds[i].revents |= (Fds[i].events & LQ_POLLOUT);
			if (Fds[i].revents != 0)
				CountEvents++;
			if (CountEvents > 0)
				Handles[i] = (HANDLE)Fds[i].fd;
			else
				Handles[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
		}
		else if (NtCancelIoFile((HANDLE)Fds[i].fd, &StatusBlock) == STATUS_OBJECT_TYPE_MISMATCH) { /* Is Event */
			Types[i] = LQ_POLL_TYPE_EVENT;
			if (Fds[i].events & (LQ_POLLIN | LQ_POLLOUT)) {
				Handles[i] = (HANDLE)Fds[i].fd;
				switch (WaitForSingleObject((HANDLE)Fds[i].fd, 0)) {
				case WAIT_OBJECT_0:
					Fds[i].revents = Fds[i].events & (LQ_POLLIN | LQ_POLLOUT);
					break;
				case WAIT_TIMEOUT:
					break;
				default:
					Fds[i].revents = LQ_POLLERR;
					break;
				}
			}
			if (Fds[i].revents != 0)
				CountEvents++;
			if ((CountEvents > 0) || (Fds[i].events & (LQ_POLLIN | LQ_POLLOUT)))
				Handles[i] = (HANDLE)Fds[i].fd;
			else
				Handles[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
		}
		else if (
			(Status = NtQueryInformationFile((HANDLE)Fds[i].fd, &StatusBlock, &PipeInfo, sizeof(PipeInfo), (FILE_INFORMATION_CLASS)24)) !=
			STATUS_INVALID_PARAMETER
			) { /* Is pipe */
			Types[i] = LQ_POLL_TYPE_PIPE;
			HavePipeOrTerminal = true;

			if (Status != STATUS_SUCCESS) {
				Fds[i].revents |= LQ_POLLERR;
			}
			else {
				if ((Fds[i].events & LQ_POLLOUT) && (PipeInfo.WriteQuotaAvailable > 0))
					Fds[i].revents |= LQ_POLLOUT;
				if ((Fds[i].events & LQ_POLLIN) && (PipeInfo.ReadDataAvailable > 0))
					Fds[i].revents |= LQ_POLLIN;
				if ((Fds[i].events & LQ_POLLHUP) && (PipeInfo.NamedPipeState != 3))
					Fds[i].revents |= LQ_POLLHUP;
			}
			if (Fds[i].revents != 0)
				CountEvents++;
			if (CountEvents > 0)
				Handles[i] = (HANDLE)Fds[i].fd;
			else
				Handles[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
		}
		else {
			Types[i] = LQ_POLL_TYPE_DRIVER;
			Fds[i].revents = 0;
			if (Fds[i].events & LQ_POLLOUT) {
				Fds[i].revents |= LQ_POLLERR;
			}
			else {
				Handles[i] = CreateEventW(NULL, TRUE, FALSE, NULL);
				if (Fds[i].events & (LQ_POLLIN | LQ_POLLHUP)) {
					pli = NULL;
				lblAgain:
					switch (NtReadFile((HANDLE)Fds[i].fd, Handles[i], NULL, NULL, &ReadStatusBlock, &LqPollCheckBuf, 0, pli, NULL)) {
					case STATUS_SUCCESS:
						if (Fds[i].events & LQ_POLLIN)
							Fds[i].revents |= LQ_POLLIN;
						else
							ResetEvent(Handles[i]);
						break;
					case STATUS_PENDING:
						if (!(Fds[i].events & LQ_POLLIN)) {
							CancelIo((HANDLE)Fds[i].fd);
							ResetEvent(Handles[i]);
							HavePipeOrTerminal = true;
						}
						break;
					case STATUS_PIPE_BROKEN:
					case STATUS_PIPE_CLOSING:
						if (Fds[i].events & LQ_POLLHUP)
							Fds[i].revents |= LQ_POLLHUP;
						ResetEvent(Handles[i]);
						break;
					case STATUS_INVALID_PARAMETER:
						if (pli == NULL) {
							pli = &li;
							NtQueryInformationFile((HANDLE)Fds[i].fd, &ReadStatusBlock, &li.QuadPart, sizeof(li.QuadPart), (FILE_INFORMATION_CLASS)14);
							goto lblAgain;
						}
					default:
						Fds[i].revents |= LQEVNT_FLAG_ERR;
					}
				}
			}
			if (Fds[i].revents != 0)
				CountEvents++;
			if (CountEvents > 0) {
				CancelIo((HANDLE)Fds[i].fd);
				CloseHandle(Handles[i]);
				Handles[i] = (HANDLE)Fds[i].fd;
			}
		}
	}

	if (CountEvents > 0)
		goto lblOut;

	WaitTime = TimeoutMillisec;
lblAgainCheck:

	if (HavePipeOrTerminal)
		CurWaitTime2 = CurWaitTime = LQ_POLLCHECK_WAIT_WHEN_HAVE_PIPE_OR_TERMINAL;
	else
		CurWaitTime2 = CurWaitTime = WaitTime;

	if (CountFds >= MAXIMUM_WAIT_OBJECTS) {
		while (true) {
			WaitRes = CheckAllEvents(Handles, CountFds);
			if (((WaitRes >= WAIT_OBJECT_0) && (WaitRes < (WAIT_OBJECT_0 + MAXIMUM_WAIT_OBJECTS))) || (WaitRes != WAIT_TIMEOUT))
				break;
			CurWaitTime -= ((LqTimeMillisec)LQ_POLLCHECK_WAIT_WHEN_GR_MAXIMUM_WAIT_OBJECTS);
			WaitRes = WaitForMultipleObjects(MAXIMUM_WAIT_OBJECTS - 1, Handles, FALSE, min(((LqTimeMillisec)LQ_POLLCHECK_WAIT_WHEN_GR_MAXIMUM_WAIT_OBJECTS), CurWaitTime));
			if (((WaitRes >= WAIT_OBJECT_0) && (WaitRes < (WAIT_OBJECT_0 + MAXIMUM_WAIT_OBJECTS))) || (WaitRes != WAIT_TIMEOUT))
				break;
			if (CurWaitTime <= ((LqTimeMillisec)0))
				break;
		}
	}
	else {
		WaitForMultipleObjects(CountFds, Handles, FALSE, CurWaitTime);
	}
	WaitTime -= CurWaitTime2;
	for (size_t i = 0; i < CountFds; i++) {
		switch (Types[i]) {
		case LQ_POLL_TYPE_EVENT:
			switch (WaitForSingleObject(Handles[i], 0)) {
			case WAIT_OBJECT_0:
				Fds[i].revents = Fds[i].events & (LQ_POLLIN | LQ_POLLOUT);
				break;
			case WAIT_TIMEOUT:
				break;
			default:
				Fds[i].revents = LQ_POLLERR;
				break;
			}
			break;
		case LQ_POLL_TYPE_SOCKET:
			NetEvnts.lNetworkEvents = 0;
			WSAEnumNetworkEvents(Fds[i].fd, Handles[i], &NetEvnts);
			if (NetEvnts.lNetworkEvents != 0)
				Fds[i].revents = LqConnFlagBySysEvent(NetEvnts.lNetworkEvents);
			break;
		case LQ_POLL_TYPE_PIPE:
			Status = NtQueryInformationFile((HANDLE)Fds[i].fd, &StatusBlock, &PipeInfo, sizeof(PipeInfo), (FILE_INFORMATION_CLASS)24);
			if (Status != STATUS_SUCCESS) {
				Fds[i].revents |= LQ_POLLERR;
			}
			else {
				if ((Fds[i].events & LQ_POLLOUT) && (PipeInfo.WriteQuotaAvailable > 0))
					Fds[i].revents |= LQ_POLLOUT;
				if ((Fds[i].events & LQ_POLLIN) && (PipeInfo.ReadDataAvailable > 0))
					Fds[i].revents |= LQ_POLLIN;
				if ((Fds[i].events & LQ_POLLHUP) && (PipeInfo.NamedPipeState != 3))
					Fds[i].revents |= LQ_POLLHUP;
			}
			break;
		case LQ_POLL_TYPE_TERMINAL:
			if (Fds[i].events & LQ_POLLIN) {
				while (true) {
					if (!PeekConsoleInputW((HANDLE)Fds[i].fd, &ir, 1, &num_read)) {
						Fds[i].revents = LQ_POLLERR;
						break;
					}
					if (num_read <= 0)
						break;
					if (ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown) {
						Fds[i].revents = LQ_POLLIN;
						break;
					}
					else {
						ReadConsoleInputW((HANDLE)Fds[i].fd, &ir, 1, &num_read);
					}
				}
			}
			Fds[i].revents |= (Fds[i].events & LQ_POLLOUT);
			break;
		case LQ_POLL_TYPE_DRIVER:
			switch (((Fds[i].events & LQ_POLLHUP) && !(Fds[i].events & LQ_POLLIN)) ? WAIT_OBJECT_0 : WaitForSingleObject(Handles[i], 0)) {
			case WAIT_OBJECT_0:
				pli = NULL;
			lblAgain2:
				switch (NtReadFile((HANDLE)Fds[i].fd, Handles[i], NULL, NULL, &ReadStatusBlock, &LqPollCheckBuf, 0, pli, NULL)) {
				case STATUS_SUCCESS:
					if (Fds[i].events & LQ_POLLIN)
						Fds[i].revents |= LQ_POLLIN;
					else
						ResetEvent(Handles[i]);
					break;
				case STATUS_PENDING:
					if (!(Fds[i].events & LQ_POLLIN)) {
						CancelIo((HANDLE)Fds[i].fd);
						ResetEvent(Handles[i]);
					}
					break;
				case STATUS_PIPE_BROKEN:
				case STATUS_PIPE_CLOSING:
					if (Fds[i].events & LQ_POLLHUP)
						Fds[i].revents |= LQ_POLLHUP;
					ResetEvent(Handles[i]);
					break;
				case STATUS_INVALID_PARAMETER:
					if (pli == NULL) {
						pli = &li;
						NtQueryInformationFile((HANDLE)Fds[i].fd, &ReadStatusBlock, &li.QuadPart, sizeof(li.QuadPart), (FILE_INFORMATION_CLASS)14);
						goto lblAgain2;
					}
				default:
					Fds[i].revents |= LQEVNT_FLAG_ERR;
				}
				break;
			case WAIT_TIMEOUT:
				break;
			default:
				Fds[i].revents = LQ_POLLERR;
				break;
			}
			break;
		}
		if (Fds[i].revents != 0)
			CountEvents++;
	}
	if (CountEvents > 0)
		goto lblOut;
	if (WaitTime > ((LqTimeMillisec)0))
		goto lblAgainCheck;
lblOut:
	for (size_t i = 0; i < CountFds; i++) {
		if (Types[i] == LQ_POLL_TYPE_DRIVER)
			CancelIo((HANDLE)Fds[i].fd);
		if ((HANDLE)Fds[i].fd != Handles[i])
			CloseHandle(Handles[i]);
	}
	LqMemFree(Handles);
	return CountEvents;
}

short LqPollCheckSingle(int Fd, short Events, LqTimeMillisec TimeoutMillisec) {
	LqPoll Poll;
	Poll.fd = Fd;
	Poll.events = Events;
	Poll.revents = 0;
	if (LqPollCheck(&Poll, 1, TimeoutMillisec) == 1)
		return Poll.revents;
	return 0;
}

#define __METHOD_DECLS__
#include "LqAlloc.hpp"

