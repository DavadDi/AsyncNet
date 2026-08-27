//=====================================================================
//
// inetrtx.h - TCP proxy stream (SOCKS4/SOCKS5/HTTP CONNECT)
//
// Created by skywind on 2022/11/29
// Last Modified: 2022/12/19 21:58:59
//
//=====================================================================
#ifndef _INETRTX_H_
#define _INETRTX_H_

#include "inetbase.h"
#include "inetcode.h"
#include "inetkit.h"

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------
// proxy error codes (returned in stream->error on ASYNC_STREAM_EVT_ERROR)
//---------------------------------------------------------------------

#define ASYNC_PROXY_ERROR_ALLOC          (-21001)
#define ASYNC_PROXY_ERROR_PROTOCOL       (-21002)
#define ASYNC_PROXY_ERROR_AUTH           (-21003)
#define ASYNC_PROXY_ERROR_UNSUPPORTED    (-21004)

//---------------------------------------------------------------------
// proxy option constants (for async_stream_option)
//---------------------------------------------------------------------

#define ASYNC_STREAM_OPTION_PROXY_TIMEOUT   1

//---------------------------------------------------------------------
// LOG channel
//---------------------------------------------------------------------
#define ASYNC_LOOP_LOG_PROXY ASYNC_LOOP_LOG_NEXT(2)

//---------------------------------------------------------------------
// proxy type constants
//---------------------------------------------------------------------

// SOCKS4 proxy (supports SOCKS4a for domain name resolution)
#define ASYNC_STREAM_PROXY_SOCKS4    0

// SOCKS5 proxy (supports username/password authentication)
#define ASYNC_STREAM_PROXY_SOCKS5    1

// HTTP CONNECT proxy (supports Basic authentication)
#define ASYNC_STREAM_PROXY_HTTP      2

//---------------------------------------------------------------------
// create a proxy stream
//---------------------------------------------------------------------

// Create a proxy stream that tunnels a TCP connection through a proxy:
//   proxy_type: ASYNC_STREAM_PROXY_SOCKS4/5 or ASYNC_STREAM_PROXY_HTTP
//   proxy_addr: proxy server address (sockaddr)
//   proxy_addrlen: length of proxy_addr
//   username/password: for proxy authentication, can be NULL
//   target_host: target host name or IP address
//   target_port: target port number (1-65535)
//   callback: stream event callback (same signature as TCP stream)
// Returns: CAsyncStream object or NULL on error.
//
// Internally creates a TCP stream to connect to the proxy server,
// performs the proxy handshake, and then tunnels data to the target
// through the proxy. The returned stream behaves like a normal
// CAsyncStream once the handshake completes (ASYNC_STREAM_EVT_ESTAB).
CAsyncStream *async_stream_proxy_new(CAsyncLoop *loop, int proxy_type,
        const struct sockaddr *proxy_addr, int proxy_addrlen,
        const char *username, const char *password,
        const char *target_host, int target_port,
        void (*callback)(CAsyncStream *stream, int event, int args));

// Create a proxy stream from a URL string that describes the proxy server.
// proxy_url format: scheme://[user[:password]@]host[:port]
// Supported schemes: socks4, socks4a, socks5, socks5h, http, https
// Default ports: socks4/socks4a/socks5/socks5h = 1080, http/https = 8080
// The target_host/target_port specify the destination behind the proxy.
// Returns a CAsyncStream object or NULL on error.
CAsyncStream *async_stream_proxy_newex(CAsyncLoop *loop,
        const char *proxy_url, const char *target_host, int target_port,
        void (*callback)(CAsyncStream *stream, int event, int args));

// Parse a proxy URL into its components.
// proxy_url format: scheme://[user[:password]@]host[:port]
// Supported schemes: socks4, socks4a, socks5, socks5h, http, https
// On success, fills *proxy_type, *host, *port, *username, *password.
// On failure, all output string pointers are set to NULL.
// The caller must ikmem_free any non-NULL *host, *username, *password.
// Returns 0 on success, -1 on error.
int async_stream_proxy_parse(const char *url, int *proxy_type,
        char **host, int *port, char **username, char **password);

//---------------------------------------------------------------------
// query proxy-assigned bound address
//---------------------------------------------------------------------

// Get the bound address assigned by the proxy server during handshake.
// For SOCKS5, this is the BND.ADDR/BND.PORT from the CONNECT reply.
// For SOCKS4, this is the IP/PORT from the reply.
// For HTTP CONNECT, there is no bound address (returns -1).
// Returns 0 on success, -1 if no bound address is available or the
// stream is not a proxy stream. On success, addr and addrlen are
// filled with the sockaddr structure.
int async_stream_proxy_bind_addr(CAsyncStream *stream,
        struct sockaddr *addr, int *addrlen);


#ifdef __cplusplus
}
#endif

#endif
