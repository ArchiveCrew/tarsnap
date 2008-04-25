#include "bsdtar_platform.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include "warnp.h"

#include "network_internal.h"

/**
 * XXX Portability
 * XXX These functions serve two purposes:
 * XXX 1. To avoid wasting bandwidth, by ensuring that multiple small writes
 * XXX over a socket are aggregated into a single TCP/IP packet.
 * XXX 2. To avoid severe performance issues which would otherwise result
 * XXX from nagling, by allowing data to be "pushed" out once there are no
 * XXX more writes queued.
 * XXX
 * XXX POSIX defines TCP_NODELAY for purpose #2, although it does not require
 * XXX that implementations obey it; BSD and Linux respectively define
 * XXX TCP_NOPUSH and TCP_CORK for purpose #1.
 */

/* Macro to simplify setting options. */
#define setopt(fd, opt, value, err0) do {				\
	int val;							\
									\
	val = value;							\
	if (setsockopt(fd, IPPROTO_TCP, opt, &val, sizeof(int))) {	\
		if ((errno != ETIMEDOUT) &&				\
		    (errno != ECONNRESET)) {				\
			warnp("setsockopt(%s, %d)", #opt, val);		\
			goto err0;					\
		}							\
	}								\
} while (0);

/**
 * network_cork(fd):
 * Clear the TCP_NODELAY socket option, and set TCP_CORK or TCP_NOPUSH if
 * either is defined.
 */
int
network_cork(int fd)
{

	/* Clear TCP_NODELAY. */
	setopt(fd, TCP_NODELAY, 0, err0);

	/* Set TCP_CORK or TCP_NOPUSH as appropriate. */
#ifdef TCP_CORK
	setopt(fd, TCP_CORK, 1, err0);
#else
#ifdef TCP_NOPUSH
	setopt(fd, TCP_NOPUSH, 1, err0);
#endif
#endif

	/* Success! */
	return (0);

err0:
	/* Failure! */
	return (-1);
}

/**
 * network_uncork(fd):
 * Set the TCP_NODELAY socket option, and clear TCP_CORK or TCP_NOPUSH if
 * either is defined.
 */
int
network_uncork(int fd)
{

	/* Set TCP_NODELAY. */
	setopt(fd, TCP_NODELAY, 1, err0);

	/* Clear TCP_CORK or TCP_NOPUSH as appropriate. */
#ifdef TCP_CORK
	setopt(fd, TCP_CORK, 0, err0);
#else
#ifdef TCP_NOPUSH
	setopt(fd, TCP_NOPUSH, 0, err0);
#endif
#endif

	/* Success! */
	return (0);

err0:
	/* Failure! */
	return (-1);
}
