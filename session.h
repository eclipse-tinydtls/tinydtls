/*******************************************************************************
 *
 * Copyright (c) 2011-2022 Olaf Bergmann (TZI) and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at 
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Olaf Bergmann  - initial API and implementation
 *
 *******************************************************************************/

#ifndef _DTLS_SESSION_H_
#define _DTLS_SESSION_H_

#include "tinydtls.h"
#include "global.h"

#ifdef WITH_CONTIKI
#include "ip/uip.h"
typedef struct {
  unsigned char size;     /**< size of session_t::addr */
  uip_ipaddr_t addr;      /**< session IP address */
  unsigned short port;    /**< transport layer port */
  int ifindex;            /**< network interface index */
} session_t;

 /* TODO: Add support for RIOT over sockets  */
#elif defined(WITH_RIOT_SOCK)

#include "net/ipv4/addr.h"
#include "net/ipv6/addr.h"
typedef struct {
  unsigned char size;       /**< size of session_t::addr */
  struct {
    unsigned short family;  /**< IP address family */
    unsigned short port;    /**< transport layer port */
    union {
#ifdef SOCK_HAS_IPV4
      ipv4_addr_t ipv4;     /**< IPv4 address */
#endif
#ifdef SOCK_HAS_IPV6
      ipv6_addr_t ipv6;     /**< IPv6 address */
#endif
    };
  } addr;                   /**< session IP address and port */
  int ifindex;              /**< network interface index */
} session_t;

#elif defined(WITH_LWIP_NO_SOCKET)

#include <lwip/ip_addr.h>
typedef struct {
  unsigned char size;     /**< size of session_t::addr */
  unsigned short port;    /**< transport layer port */
  ip_addr_t addr;         /**< session IP address */
  int ifindex;            /**< network interface index */
} session_t;

#undef INET_NTOP

#else /* ! WITH_CONTIKI && ! WITH_RIOT_SOCK && ! WITH_LWIP_NO_SOCKET */

#ifdef WITH_ZEPHYR
#include <zephyr/kernel.h>
#ifdef HAVE_NET_SOCKET_H
#include <zephyr/net/socket.h>
#endif /* HAVE_NET_SOCKET_H */

#elif defined(WITH_LWIP)
#include "lwip/sockets.h"
#undef write
#undef read
typedef unsigned char uint8_t;
#if ! LWIP_IPV4
/* members are in network byte order */
struct sockaddr_in {
  u8_t            sin_len;
  sa_family_t     sin_family;
  in_port_t       sin_port;
  struct in_addr  sin_addr;
#define SIN_ZERO_LEN 8
  char            sin_zero[SIN_ZERO_LEN];
};
#endif /* ! LWIP_IPV4 */
#if ! LWIP_IPV6
struct sockaddr_in6 {
  u8_t            sin6_len;      /* length of this structure    */
  sa_family_t     sin6_family;   /* AF_INET6                    */
  in_port_t       sin6_port;     /* Transport layer port #      */
  u32_t           sin6_flowinfo; /* IPv6 flow information       */
  struct in6_addr sin6_addr;     /* IPv6 address                */
  u32_t           sin6_scope_id; /* Set of interfaces for scope */
};
#endif /* ! LWIP_IPV6 */

#elif defined(IS_WINDOWS)
#include <winsock2.h>
#include <ws2tcpip.h>

#else /* ! WITH_ZEPHYR && ! WITH_LWIP && ! IS_WINDOWS */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* ! WITH_ZEPHYR  && ! WITH_LWIP */

typedef struct {
  socklen_t size;		/**< size of addr */
  union {
    struct sockaddr     sa;
    struct sockaddr_storage st;
    struct sockaddr_in  sin;
    struct sockaddr_in6 sin6;
  } addr;
  int ifindex;
} session_t;
#endif /* ! WITH_CONTIKI && ! WITH_RIOT_SOCK && ! WITH_LWIP_NO_LWIP_SOCKET */

/** 
 * Resets the given session_t object @p sess to its default
 * values.  In particular, the member rlen must be initialized to the
 * available size for storing addresses.
 * 
 * @param sess The session_t object to initialize.
 */
void dtls_session_init(session_t *sess);

#if !(defined (WITH_CONTIKI)) && !(defined (RIOT_VERSION)) && !(defined (WITH_LWIP_NO_SOCKET))
/**
 * Creates a new ::session_t for the given address.
 *
 * @param addr Address which should be stored in the ::session_t.
 * @param addrlen Length of the @p addr.
 * @return The new session or @c NULL on error.
 */
session_t* dtls_new_session(struct sockaddr *addr, socklen_t addrlen);

/**
 * Frees memory allocated for a session using ::dtls_new_session.
 *
 * @param sess Pointer to a session for which allocated memory should be
 *     freed.
 */
void dtls_free_session(session_t *sess);

/**
 * Extracts the address of the given ::session_t.
 *
 * @param sess Session to extract address for.
 * @param addrlen Pointer to memory location where the address
 *     length should be stored.
 * @return The address or @c NULL if @p sess was @c NULL.
 */
struct sockaddr* dtls_session_addr(session_t *sess, socklen_t *addrlen);
#endif /* ! WITH_CONTIKI && ! RIOT_VERSION && ! WITH_LWIP_NO_SOCKET */

/**
 * Compares the given session objects. This function returns @c 0
 * when @p a and @p b differ, @c 1 otherwise.
 */
int dtls_session_equals(const session_t *a, const session_t *b);

#endif /* _DTLS_SESSION_H_ */
