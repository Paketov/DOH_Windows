/*
* Lanq(Lan Quick)
* Solodov A. N. (hotSAN)
* 2016
*   LqFile... - File layer between os and server.
*/


#pragma once

#include <stdint.h>


#if defined(_WIN64) || defined(_WIN32)
# define LQPLATFORM_WINDOWS

#else
# define LQPLATFORM_POSIX


# ifdef __ANDROID__
#  define LQPLATFORM_ANDROID
#  define LQ_ASYNC_IO_NOT_HAVE
# endif

#endif

/* Architectuire word bits */
#if defined(_WIN64)
# define LQARCH_64
#elif defined(_WIN32)
# define LQARCH_32
#elif __WORDSIZE == 64
# define LQARCH_64
#elif __WORDSIZE == 32
# define LQARCH_64
#elif defined(__GNUC__)
# ifdef __x86_64__
#  define LQARCH_64
# else
#  define LQARCH_32
# endif
#else
# error "Not detect platform architecture"
#endif






typedef uint16_t                LqEvntFlag;

#define LQ_POLL_TYPE_EVENT 0
#define LQ_POLL_TYPE_PIPE 1
#define LQ_POLL_TYPE_SOCKET 2
#define LQ_POLL_TYPE_TERMINAL 3
#define LQ_POLL_TYPE_DRIVER 4

#define LQ_POLLIN    ((short)1)
#define LQ_POLLOUT   ((short)2)
#define LQ_POLLHUP   ((short)4)
#define LQ_POLLNVAL  ((short)8)
#define LQ_POLLERR   ((short)16)

#define LQEVNT_FLAG_HUP                         ((LqEvntFlag)4)          /*Connection lost or can been closed by client*/
#define LQEVNT_FLAG_RDHUP                       ((LqEvntFlag)8)          /*Connection lost or can been closed by client*/
#define LQEVNT_FLAG_END                         ((LqEvntFlag)16)         /*Want end session*/
#define LQEVNT_FLAG_ERR                         ((LqEvntFlag)32)         /*Have error in event descriptor*/


# ifndef LQ_POLLCHECK_WAIT_WHEN_GR_MAXIMUM_WAIT_OBJECTS
#  define LQ_POLLCHECK_WAIT_WHEN_GR_MAXIMUM_WAIT_OBJECTS ((LqTimeMillisec)10)
# endif
# ifndef LQ_POLLCHECK_WAIT_WHEN_HAVE_PIPE_OR_TERMINAL
#  define LQ_POLLCHECK_WAIT_WHEN_HAVE_PIPE_OR_TERMINAL ((LqTimeMillisec)30)
# endif

#define LqEvntSystemEventByConnFlag(EvntFlags)        \
    ((((EvntFlags) & LQ_POLLOUT)  ? FD_WRITE : 0)    |\
    (((EvntFlags) & LQ_POLLIN)    ? FD_READ : 0)     |\
    (((EvntFlags) & LQ_POLLIN)    ? FD_ACCEPT : 0)   |\
    (((EvntFlags) & LQ_POLLOUT)   ? FD_CONNECT : 0)  |\
    (((EvntFlags) & LQ_POLLHUP)   ? FD_CLOSE: 0))

#define LqConnFlagBySysEvent(EvntFlags)               \
    ((((EvntFlags) & FD_READ)     ? LQ_POLLIN : 0)   |\
    (((EvntFlags) & FD_WRITE)     ? LQ_POLLOUT : 0)  |\
    (((EvntFlags) & FD_ACCEPT)    ? LQ_POLLOUT : 0)  |\
    (((EvntFlags) & FD_CONNECT)   ? LQ_POLLIN : 0)   |\
    (((EvntFlags) & FD_CLOSE)     ? LQ_POLLHUP: 0))

typedef long long               LqTimeMillisec;

#pragma pack(push)
#pragma pack(1)

typedef struct LqPoll {
	int   fd;         /* file descriptor */
	short events;     /* requested events */
	short revents;    /* returned events */
} LqPoll;

#pragma pack(pop)

int LqDescrSetInherit(int Descriptor, int IsInherit);

int LqConnSwitchNonBlock(int Fd, int IsNonBlock);

bool LqDescrIsSocket(int Fd);

bool LqDescrIsTerminal(int Fd);

int LqEventCreate(int InheritFlag);

int LqEventSet(int FileEvent);

int LqEventReset(int FileEvent);

void LqThreadYield();

int LqPollCheck(LqPoll* Fds, size_t CountFds, LqTimeMillisec TimeoutMillisec);

short LqPollCheckSingle(int Fd, short Events, LqTimeMillisec TimeoutMillisec);