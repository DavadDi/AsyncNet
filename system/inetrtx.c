//=====================================================================
//
// inetrtx.c - TCP proxy stream implementation (SOCKS4/SOCKS5/HTTP CONNECT)
//
// Created by skywind on 2022/11/29
// Last Modified: 2025/12/22 15:07:12
//
// This implements a CAsyncStream subtype that tunnels through a proxy.
// CAsyncProxy embeds CAsyncStream as its first field so that
// async_stream_upcast/async_stream_private can convert between the
// stream pointer and the private proxy struct. The proxy manages an
// underlying TCP stream (proxy->tcp) and intercepts its events to
// perform the proxy handshake before forwarding data to the user.
//
//=====================================================================
#include "inetrtx.h"
#include "imemdata.h"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#ifndef _WINSOCKAPI_
#include <winsock2.h>
#endif
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif


//---------------------------------------------------------------------
// constants and error codes
//---------------------------------------------------------------------

#define ASYNC_STREAM_NAME_PROXY    ASYNC_STREAM_NAME('P','R','X','Y')

// Maximum domain name length accepted for SOCKS5 (per RFC 1928)
#define PROXY_MAX_DOMAIN_LEN       255

// Maximum total SOCKS4a request packet size (stack buffer bound)
#define PROXY_SOCKS4_MAX_PACKET    600

// Maximum handshake response size (prevents unbounded buffer growth)
#define PROXY_HANDSHAKE_BUF_LIMIT  8192

// Default handshake timeout in milliseconds
#define PROXY_HANDSHAKE_TIMEOUT    15000


//---------------------------------------------------------------------
// state and stage enums
//---------------------------------------------------------------------

// Proxy connection state machine
enum {
    PROXY_STATE_INIT = 0,       // waiting for TCP connection to proxy
    PROXY_STATE_NEGOTIATING,    // TCP connected, performing handshake
    PROXY_STATE_READY,          // handshake done, tunneling data
    PROXY_STATE_FAILED          // handshake failed or connection lost
};

// SOCKS5 handshake sub-stages
enum {
    SOCKS5_STAGE_METHOD = 0,    // method selection negotiation
    SOCKS5_STAGE_AUTH,          // username/password sub-negotiation
    SOCKS5_STAGE_CONNECT        // CONNECT request/reply
};


//---------------------------------------------------------------------
// CAsyncProxy - private proxy stream data
//---------------------------------------------------------------------

// CAsyncProxy embeds CAsyncStream as the first field. The stream's
// virtual dispatch table (close/read/write/etc.) points to proxy-
// specific functions. async_stream_private(stream, CAsyncProxy) and
// async_stream_upcast(stream, CAsyncProxy, stream) convert between
// the two pointer types.
typedef struct _CAsyncProxy {
    CAsyncStream stream;           // embedded base stream (first field)
    CAsyncStream *tcp;             // underlying TCP stream to proxy server
    int proxy_type;                // ASYNC_STREAM_PROXY_SOCKS4/5/HTTP
    int state;                     // PROXY_STATE_INIT/NEGOTIATING/READY/FAILED
    int ready;                     // 1 once handshake completes successfully
    int dispatched_estab;          // 1 after ESTAB event dispatched to user
    int closing;                   // 1 to prevent double-close
    int in_dispatch;               // 1 while inside user callback
    int user_enabled;              // event mask the user requested
    struct IMSTREAM send_pending;  // data buffered before tunnel is ready
    struct IMSTREAM handshake_buf; // incoming bytes during handshake
    struct IMSTREAM recv_leftover; // leftover data after handshake completes
    CAsyncTimer timer;             // handshake timeout timer
    IUINT32 timeout_ms;            // handshake timeout in milliseconds
    CAsyncPostpone evt_post;       // deferred event delivery (READING)
    int notify_reading;            // 1 while a READING notify is queued
    int socks5_stage;              // SOCKS5 sub-stage during negotiation
    int socks5_offered_auth;       // 1 if we offered 0x02 (username/password)
    int target_type;               // 1: ipv4, 3: domain, 4: ipv6
    int target_port;               // target port number
    unsigned char target_ipv4[4];  // resolved ipv4 address
    unsigned char target_ipv6[16]; // resolved ipv6 address
    char *target_host;             // target hostname or IP string
    char *username;                // proxy auth username (nullable)
    char *password;                // proxy auth password (nullable)
    int bind_type;                 // bound address type: 0=none, 1=ipv4, 4=ipv6
    int bind_port;                 // bound port from proxy reply
    unsigned char bind_ipv4[4];    // bound ipv4 address from proxy reply
    unsigned char bind_ipv6[16];   // bound ipv6 address from proxy reply
} CAsyncProxy;


//---------------------------------------------------------------------
// forward declarations
//---------------------------------------------------------------------

static void async_proxy_close(CAsyncStream *stream);
static long async_proxy_read(CAsyncStream *stream, void *ptr, long size);
static long async_proxy_write(CAsyncStream *stream, const void *ptr, long size);
static long async_proxy_peek(CAsyncStream *stream, void *ptr, long size);
static void async_proxy_enable(CAsyncStream *stream, int event);
static void async_proxy_disable(CAsyncStream *stream, int event);
static long async_proxy_remain(const CAsyncStream *stream);
static long async_proxy_pending(const CAsyncStream *stream);
static void async_proxy_watermark(CAsyncStream *stream, long high, long low);
static long async_proxy_option(CAsyncStream *stream, int option, long value);

static void async_proxy_tcp_event(CAsyncStream *tcp, int event, int args);
static int async_proxy_on_established(CAsyncProxy *proxy);
static int async_proxy_collect_handshake(CAsyncProxy *proxy);
static int async_proxy_process_handshake(CAsyncProxy *proxy);
static int async_proxy_start_socks5(CAsyncProxy *proxy);
static int async_proxy_start_socks4(CAsyncProxy *proxy);
static int async_proxy_start_http(CAsyncProxy *proxy);
static int async_proxy_process_socks5(CAsyncProxy *proxy);
static int async_proxy_socks5_process_method(CAsyncProxy *proxy);
static int async_proxy_socks5_process_auth(CAsyncProxy *proxy);
static int async_proxy_socks5_process_connect(CAsyncProxy *proxy);
static int async_proxy_process_socks4(CAsyncProxy *proxy);
static int async_proxy_process_http(CAsyncProxy *proxy);
static int async_proxy_socks5_reply_length(struct IMSTREAM *buffer);
static int async_proxy_send_socks5_connect(CAsyncProxy *proxy);
static int async_proxy_send_socks5_auth(CAsyncProxy *proxy);
static int async_proxy_mark_ready(CAsyncProxy *proxy);
static int async_proxy_fail(CAsyncProxy *proxy, int error);
static long async_proxy_flush_pending(CAsyncProxy *proxy);
static void async_proxy_kick_output(CAsyncProxy *proxy);
static int async_proxy_dispatch(CAsyncProxy *proxy, int event, int args);
static void async_proxy_apply_user_enabled(CAsyncProxy *proxy);
static void async_proxy_apply_watermark(CAsyncProxy *proxy);
static int async_proxy_prepare_target(CAsyncProxy *proxy);
static ilong async_proxy_find_header_end(const char *buffer, ilong size);
static int async_proxy_parse_http_status(const char *buffer, ilong size);
static int async_proxy_host_needs_brackets(const char *host);
static int async_proxy_format_hostport(CAsyncProxy *proxy,
    char *buffer, size_t size);
static void async_proxy_notify_reading(CAsyncProxy *proxy);
static void async_proxy_post_cb(CAsyncLoop *loop, CAsyncPostpone *post);
static void async_proxy_destroy(CAsyncProxy *proxy);
static void async_proxy_timer_cb(CAsyncLoop *loop, CAsyncTimer *evt);
static int async_proxy_query_bind_addr(CAsyncStream *stream,
    struct sockaddr *addr, int *addrlen);


//---------------------------------------------------------------------
// proxy type name helper
//---------------------------------------------------------------------
static const char *proxy_type_str(int type)
{
    switch (type) {
    case ASYNC_STREAM_PROXY_SOCKS4: return "SOCKS4";
    case ASYNC_STREAM_PROXY_SOCKS5: return "SOCKS5";
    case ASYNC_STREAM_PROXY_HTTP:   return "HTTP";
    default:                        return "UNKNOWN";
    }
}


//---------------------------------------------------------------------
// handshake timeout timer callback
//---------------------------------------------------------------------

// Timer callback for handshake timeout. If the proxy is still
// negotiating when the timer fires, mark it as failed.
static void async_proxy_timer_cb(CAsyncLoop *loop, CAsyncTimer *evt)
{
    CAsyncProxy *proxy = (CAsyncProxy*)evt->user;
    (void)loop;
    if (proxy == NULL || proxy->tcp == NULL) {
        return;
    }
    if (proxy->state != PROXY_STATE_FAILED && proxy->ready == 0) {
        if (proxy->stream.loop &&
            (proxy->stream.loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
            async_loop_log(proxy->stream.loop, ASYNC_LOOP_LOG_PROXY,
                "[proxy] handshake timeout for %s target %s:%d",
                proxy_type_str(proxy->proxy_type),
                proxy->target_host ? proxy->target_host : "?",
                proxy->target_port);
        }
        async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL);
    }
}


//---------------------------------------------------------------------
// deferred event delivery
//---------------------------------------------------------------------

// Queue a READING notification to be delivered at the end of the current
// loop iteration instead of dispatching it right away. Needed because the
// notification can originate from async_proxy_enable(), i.e. from inside
// the user's own async_stream_enable() call: dispatching synchronously
// there would re-enter user code (and let it close the stream) while the
// caller is still holding the stream pointer. Same approach as
// async_ssl_notify() in inetssl.c.
// The flag makes it idempotent within one round.
static void async_proxy_notify_reading(CAsyncProxy *proxy)
{
    if (proxy->notify_reading) {
        return;
    }
    if (proxy->stream.loop == NULL) {
        return;
    }
    proxy->notify_reading = 1;
    if (async_post_is_active(&proxy->evt_post) == 0) {
        async_post_start(proxy->stream.loop, &proxy->evt_post);
    }
}


// Postpone callback: deliver the queued READING notification, re-checking
// every precondition because the situation may have changed since it was
// queued (stream closed, READ disabled again, data already drained).
static void async_proxy_post_cb(CAsyncLoop *loop, CAsyncPostpone *post)
{
    CAsyncProxy *proxy = (CAsyncProxy*)post->user;
    long remain;
    (void)loop;
    if (proxy == NULL) {
        return;
    }
    proxy->notify_reading = 0;
    if (proxy->closing || proxy->ready == 0) {
        return;
    }
    if ((proxy->user_enabled & ASYNC_EVENT_READ) == 0) {
        return;
    }
    remain = async_proxy_remain(&proxy->stream);
    if (remain <= 0) {
        return;
    }
    // dispatch may destroy the proxy; nothing is touched afterwards
    async_proxy_dispatch(proxy, ASYNC_STREAM_EVT_READING, (int)remain);
}


//---------------------------------------------------------------------
// destroy - release all proxy resources
//---------------------------------------------------------------------

// Called from async_proxy_close (via the stream's close vfunc).
// Disconnects the underlying TCP stream, frees all IMSTREAM buffers
// and heap-allocated strings, then frees the CAsyncProxy struct.
static void async_proxy_destroy(CAsyncProxy *proxy)
{
    if (proxy == NULL) {
        return;
    }
    // Prevent re-entry: clear user pointer BEFORE closing TCP to avoid
    // stray events reaching us during teardown.
    if (proxy->tcp) {
        proxy->tcp->user = NULL;
        proxy->tcp->callback = NULL;
        async_stream_close(proxy->tcp);
        proxy->tcp = NULL;
    }
    // Stop handshake timeout timer.
    if (proxy->stream.loop && async_timer_active(&proxy->timer)) {
        async_timer_stop(proxy->stream.loop, &proxy->timer);
    }
    // Stop the deferred notification postpone (safe even if proxy_new
    // failed before initializing it: async_post_is_active only reads the
    // active flag of the zeroed struct, same convention as the timer).
    if (proxy->stream.loop && async_post_is_active(&proxy->evt_post)) {
        async_post_stop(proxy->stream.loop, &proxy->evt_post);
    }
    proxy->notify_reading = 0;
    // Release IMSTREAM buffers (ims_destroy handles internal nodes).
    ims_destroy(&proxy->send_pending);
    ims_destroy(&proxy->handshake_buf);
    ims_destroy(&proxy->recv_leftover);
    // Free heap-allocated strings.
    ikmem_free(proxy->target_host); proxy->target_host = NULL;
    ikmem_free(proxy->username); proxy->username = NULL;
    ikmem_free(proxy->password); proxy->password = NULL;
    // Clear the embedded stream so stale pointers can't be used.
    proxy->stream.instance = NULL;
    async_stream_zero(&proxy->stream);
    ikmem_free(proxy);
}


//---------------------------------------------------------------------
// target address parsing
//---------------------------------------------------------------------

// Try to parse target_host as an IPv4 or IPv6 literal.
// Returns: 1 for IPv4, 4 for IPv6, 3 for domain name (not an IP).
static int async_proxy_try_parse_ip(const char *host, unsigned char ipv4[4],
    unsigned char ipv6[16])
{
    struct in_addr addr4;
    if (isockaddr_pton(AF_INET, host, &addr4) == 0) {
        memcpy(ipv4, &addr4, 4);
        return 1;
    }
#ifdef AF_INET6
    {
        struct in6_addr addr6;
        if (isockaddr_pton(AF_INET6, host, &addr6) == 0) {
            memcpy(ipv6, &addr6, 16);
            return 4;
        }
    }
#endif
    // Not an IP literal - treat as a domain name.
    return 3;
}

// Resolve target_host into target_type + target_ipv4/ipv6.
// Validates domain name length for SOCKS4/SOCKS5, and rejects
// IPv6 targets for SOCKS4 (which only supports IPv4).
static int async_proxy_prepare_target(CAsyncProxy *proxy)
{
    int t;
    if (proxy->target_host == NULL || proxy->target_host[0] == '\0') {
        return -1;
    }
    t = async_proxy_try_parse_ip(proxy->target_host,
        proxy->target_ipv4, proxy->target_ipv6);
    // SOCKS4 does not support IPv6 targets.
    if (t == 4 && proxy->proxy_type == ASYNC_STREAM_PROXY_SOCKS4) {
        return -1;
    }
    // SOCKS5 limits domain names to 255 bytes (RFC 1928).
    if (t == 3) {
        size_t len = strlen(proxy->target_host);
        if (len > PROXY_MAX_DOMAIN_LEN) {
            return -1;
        }
        // SOCKS4a domain names must fit within the request packet
        // (bounded by PROXY_SOCKS4_MAX_PACKET minus fixed overhead and userid).
        if (proxy->proxy_type == ASYNC_STREAM_PROXY_SOCKS4) {
            size_t userlen = proxy->username ? strlen(proxy->username) : 0;
            if (userlen > 255) {
                return -1;
            }
            // Fixed: VER(1)+CMD(1)+PORT(2)+IP(4)+USERID_NUL(1)+DOMAIN_NUL(1)=10
            if (9 + userlen + 1 + len + 1 > PROXY_SOCKS4_MAX_PACKET) {
                return -1;
            }
        }
    }
    proxy->target_type = t;
    return 0;
}


//---------------------------------------------------------------------
// event dispatch and state management
//---------------------------------------------------------------------

// Forward an event to the user's callback on the proxy stream.
// Sets in_dispatch around the callback so that async_proxy_close()
// can defer destroy when called reentrantly from within a callback.
// Returns 1 if the proxy was destroyed during the callback (caller
// must not access proxy afterward). Returns 0 otherwise.
static int async_proxy_dispatch(CAsyncProxy *proxy, int event, int args)
{
    CAsyncStream *stream = &proxy->stream;
    CAsyncLoop *loop = stream->loop;
    if (loop && (loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
        if (event == ASYNC_STREAM_EVT_ESTAB ||
            event == ASYNC_STREAM_EVT_ERROR ||
            event == ASYNC_STREAM_EVT_EOF) {
            async_loop_log(loop, ASYNC_LOOP_LOG_PROXY,
                "[proxy] dispatch %s event=0x%x args=%d",
                proxy_type_str(proxy->proxy_type), event, args);
        }
    }
    if (stream->callback) {
        proxy->in_dispatch = 1;
        stream->callback(stream, event, args);
        proxy->in_dispatch = 0;
        // If the user closed the stream inside the callback, the
        // deferred destroy is pending. Execute it now.
        if (proxy->closing) {
            async_proxy_destroy(proxy);
            return 1;
        }
    }
    return 0;
}

// Sync the underlying TCP stream's event mask to match what the
// user requested on the proxy stream. Only called when proxy->ready
// is set, so the tunnel is active and events should propagate.
// NOTE: the WRITE bit must not be dropped while output is still
// queued: async_tcp_write() only starts the write event when the
// stream has ASYNC_EVENT_WRITE enabled, so clearing it would leave
// the data stuck in sendbuf forever. This mirrors what
// async_filter_disable() in inetkit.c does.
static void async_proxy_apply_user_enabled(CAsyncProxy *proxy)
{
    if (proxy->tcp == NULL || proxy->ready == 0) {
        return;
    }
    // Enable any events the user wants but TCP doesn't have yet.
    if (proxy->user_enabled) {
        int enable_mask = proxy->user_enabled &
            (~proxy->tcp->enabled);
        if (enable_mask) {
            async_stream_enable(proxy->tcp, enable_mask);
        }
    }
    // Disable any events TCP has but the user doesn't want.
    {
        int disable_mask = proxy->tcp->enabled &
            (~proxy->user_enabled);
        if ((disable_mask & ASYNC_EVENT_WRITE) != 0) {
            if (proxy->send_pending.size > 0 ||
                async_stream_pending(proxy->tcp) > 0) {
                disable_mask &= ~ASYNC_EVENT_WRITE;
            }
        }
        if (disable_mask) {
            async_stream_disable(proxy->tcp, disable_mask);
        }
    }
    // Mirror TCP's actual enabled state back to the proxy stream.
    proxy->stream.enabled = proxy->tcp->enabled;
}

// Apply the proxy stream's watermark settings to the underlying
// TCP stream. Only effective when the tunnel is ready.
static void async_proxy_apply_watermark(CAsyncProxy *proxy)
{
    if (proxy->ready == 0 || proxy->tcp == NULL) {
        return;
    }
    async_stream_watermark(proxy->tcp,
        proxy->stream.hiwater, proxy->stream.lowater);
}


//---------------------------------------------------------------------
// host formatting for HTTP CONNECT
//---------------------------------------------------------------------

// Check if a host string contains colons (IPv6 literal) and
// therefore needs bracket notation in URLs.
static int async_proxy_host_needs_brackets(const char *host)
{
    size_t len;
    if (host == NULL) {
        return 0;
    }
    len = strlen(host);
    if (len == 0) {
        return 0;
    }
    // Already bracketed - no need to add more.
    if (host[0] == '[' && host[len - 1] == ']') {
        return 0;
    }
    return (strchr(host, ':') != NULL);
}

// Format host:port for HTTP CONNECT, adding brackets for IPv6.
// Returns the number of bytes written (excluding NUL), or -1 on
// truncation. The output is always NUL-terminated.
static int async_proxy_format_hostport(CAsyncProxy *proxy,
    char *buffer, size_t size)
{
    const char *host = proxy->target_host ? proxy->target_host : "";
    int n;
    if (async_proxy_host_needs_brackets(host)) {
        n = snprintf(buffer, size, "[%s]:%d", host, proxy->target_port);
    }
    else {
        n = snprintf(buffer, size, "%s:%d", host, proxy->target_port);
    }
    // snprintf returns the number of bytes that would have been written
    // if size were unlimited. Truncation means the buffer was too small.
    if (n < 0 || (size_t)n >= size) {
        return -1;
    }
    return n;
}


//---------------------------------------------------------------------
// pending data flush
//---------------------------------------------------------------------

// Try to send buffered data from send_pending through the TCP stream.
// Called when the tunnel becomes ready (mark_ready) and on WRITE events.
// Returns the total number of bytes successfully written to TCP.
static long async_proxy_flush_pending(CAsyncProxy *proxy)
{
    long total = 0;
    if (proxy->ready == 0 || proxy->tcp == NULL) {
        return 0;
    }
    while (proxy->send_pending.size > 0) {
        void *flat = NULL;
        ilong avail = ims_flat(&proxy->send_pending, &flat);
        long wrote;
        if (avail <= 0 || flat == NULL) {
            break;
        }
        wrote = async_stream_write(proxy->tcp, flat, (long)avail);
        if (wrote <= 0) {
            break;
        }
        ims_drop(&proxy->send_pending, wrote);
        total += wrote;
        if (wrote < avail) {
            // TCP send buffer is full; wait for next WRITE event.
            break;
        }
    }
    async_proxy_kick_output(proxy);
    return total;
}


// Keep the underlying TCP stream flushing while output is still
// queued. async_tcp_write() only starts the write event when the
// stream has ASYNC_EVENT_WRITE enabled, so a user who disabled WRITE
// (meaning "no WRITING notifications, please") would otherwise strand
// the data forever. Same rule as async_filter_drain() in inetkit.c.
static void async_proxy_kick_output(CAsyncProxy *proxy)
{
    if (proxy->tcp == NULL) {
        return;
    }
    if (proxy->send_pending.size == 0 &&
        async_stream_pending(proxy->tcp) <= 0) {
        return;
    }
    if ((proxy->tcp->enabled & ASYNC_EVENT_WRITE) == 0) {
        async_stream_enable(proxy->tcp, ASYNC_EVENT_WRITE);
    }
}


//---------------------------------------------------------------------
// mark_ready - transition to tunneling state
//---------------------------------------------------------------------

// Called after a successful proxy handshake. Moves any leftover bytes
// from handshake_buf into recv_leftover (they arrived before we finished
// the handshake and belong to the tunneled connection), syncs event
// masks and watermarks to the underlying TCP stream, flushes any
// data the user wrote before the tunnel was ready, then dispatches
// ESTAB and READING events to the user.
// Returns 1 if the proxy was destroyed during a dispatch callback,
// 0 if the proxy is still alive.
static int async_proxy_mark_ready(CAsyncProxy *proxy)
{
    ilong leftover;
    if (proxy->ready) {
        return 0;
    }
    // Stop handshake timeout timer.
    if (proxy->stream.loop && async_timer_active(&proxy->timer)) {
        async_timer_stop(proxy->stream.loop, &proxy->timer);
    }
    proxy->ready = 1;
    proxy->state = PROXY_STATE_READY;
    if (proxy->stream.loop &&
        (proxy->stream.loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
        async_loop_log(proxy->stream.loop, ASYNC_LOOP_LOG_PROXY,
            "[proxy] %s handshake complete, tunnel ready -> %s:%d",
            proxy_type_str(proxy->proxy_type),
            proxy->target_host ? proxy->target_host : "?",
            proxy->target_port);
    }
    proxy->stream.state = ASYNC_STREAM_ESTAB;
    proxy->stream.error = 0;
    // Any data that arrived after the handshake reply but before we
    // processed it is application data from the target server.
    leftover = ims_dsize(&proxy->handshake_buf);
    if (leftover > 0) {
        ims_move(&proxy->recv_leftover, &proxy->handshake_buf, leftover);
    }
    // Sync user-requested event mask and watermark to TCP stream.
    async_proxy_apply_user_enabled(proxy);
    async_proxy_apply_watermark(proxy);
    // Flush data the user wrote before the tunnel was ready.
    async_proxy_flush_pending(proxy);
    // Dispatch ESTAB event (only once per connection).
    if (!proxy->dispatched_estab) {
        proxy->dispatched_estab = 1;
        if (async_proxy_dispatch(proxy, ASYNC_STREAM_EVT_ESTAB, 0)) {
            return 1;
        }
    }
    // If leftover data arrived during handshake, notify the user.
    if (proxy->recv_leftover.size > 0) {
        if (async_proxy_dispatch(proxy, ASYNC_STREAM_EVT_READING,
                (int)proxy->recv_leftover.size)) {
            return 1;
        }
    }
    return 0;
}


//---------------------------------------------------------------------
// fail - transition to failed state
//---------------------------------------------------------------------

// Called on handshake errors or unexpected disconnection. Sets the
// proxy stream to CLOSED, clears all buffers, and dispatches an
// ERROR event to the user.
// Returns 1 if the proxy was destroyed during the dispatch callback,
// 0 if the proxy is still alive. Caller must not access proxy after
// a return value of 1.
static int async_proxy_fail(CAsyncProxy *proxy, int error)
{
    if (proxy->state == PROXY_STATE_FAILED) {
        return 0;
    }
    if (proxy->stream.loop &&
        (proxy->stream.loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
        async_loop_log(proxy->stream.loop, ASYNC_LOOP_LOG_PROXY,
            "[proxy] %s handshake failed for %s:%d error=%d",
            proxy_type_str(proxy->proxy_type),
            proxy->target_host ? proxy->target_host : "?",
            proxy->target_port, error);
    }
    // Stop handshake timeout timer.
    if (proxy->stream.loop && async_timer_active(&proxy->timer)) {
        async_timer_stop(proxy->stream.loop, &proxy->timer);
    }
    proxy->state = PROXY_STATE_FAILED;
    proxy->stream.state = ASYNC_STREAM_CLOSED;
    proxy->stream.error = error;
    proxy->stream.direction = 0;
    proxy->stream.eof = ASYNC_STREAM_BOTH;
    proxy->ready = 0;
    // Disable all events on the TCP stream to stop receiving data.
    if (proxy->tcp) {
        async_stream_disable(proxy->tcp,
            ASYNC_EVENT_READ | ASYNC_EVENT_WRITE);
    }
    ims_clear(&proxy->send_pending);
    ims_clear(&proxy->handshake_buf);
    ims_clear(&proxy->recv_leftover);
    return async_proxy_dispatch(proxy, ASYNC_STREAM_EVT_ERROR, error);
}


//---------------------------------------------------------------------
// handshake data collection
//---------------------------------------------------------------------

// Read all available bytes from the TCP stream into handshake_buf.
// Called on each READ event during the negotiation phase.
// Returns 1 if the proxy was destroyed (buffer overflow triggered fail),
// 0 if the proxy is still alive.
static int async_proxy_collect_handshake(CAsyncProxy *proxy)
{
    char buffer[512];
    long rc;
    if (proxy->tcp == NULL) {
        return 0;
    }
    while ((rc = async_stream_read(proxy->tcp, buffer,
        (long)sizeof(buffer))) > 0) {
        ims_write(&proxy->handshake_buf, buffer, rc);
        if (proxy->handshake_buf.size > PROXY_HANDSHAKE_BUF_LIMIT) {
            return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL);
        }
    }
    return 0;
}

// Process the handshake_buf based on proxy_type.
// Returns 1 if the proxy was destroyed, 0 if still alive.
static int async_proxy_process_handshake(CAsyncProxy *proxy)
{
    if (proxy->state != PROXY_STATE_NEGOTIATING) {
        return 0;
    }
    switch (proxy->proxy_type) {
    case ASYNC_STREAM_PROXY_SOCKS5:
        return async_proxy_process_socks5(proxy);
    case ASYNC_STREAM_PROXY_SOCKS4:
        return async_proxy_process_socks4(proxy);
    case ASYNC_STREAM_PROXY_HTTP:
        return async_proxy_process_http(proxy);
    default:
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_UNSUPPORTED);
    }
}


//---------------------------------------------------------------------
// SOCKS5 handshake
//---------------------------------------------------------------------

// Send the initial method selection message.
// If username is provided, offer methods {NO_AUTH(0x00), AUTH(0x02)}.
// Otherwise, offer only {NO_AUTH(0x00)}.
static int async_proxy_start_socks5(CAsyncProxy *proxy)
{
    unsigned char buffer[4];
    int len;
    if (proxy->username) {
        // Offer both NO_AUTH and USERNAME/PASSWORD. The server chooses
        // which to use. If it picks NO_AUTH, we skip authentication
        // (the caller provided credentials but the proxy doesn't require
        // them, which is legitimate for some proxy configurations).
        buffer[0] = 0x05;  // SOCKS version
        buffer[1] = 0x02;  // number of methods offered
        buffer[2] = 0x00;  // NO_AUTH
        buffer[3] = 0x02;  // USERNAME/PASSWORD
        len = 4;
        proxy->socks5_offered_auth = 1;
    }
    else {
        // No credentials - offer only NO_AUTH.
        buffer[0] = 0x05;
        buffer[1] = 0x01;  // number of methods offered
        buffer[2] = 0x00;  // NO_AUTH
        len = 3;
        proxy->socks5_offered_auth = 0;
    }
    proxy->socks5_stage = SOCKS5_STAGE_METHOD;
    return (async_stream_write(proxy->tcp, buffer, len) == len) ? 0 : -1;
}

// Send username/password sub-negotiation (RFC 1929).
static int async_proxy_send_socks5_auth(CAsyncProxy *proxy)
{
    size_t ulen = proxy->username ? strlen(proxy->username) : 0;
    size_t plen = proxy->password ? strlen(proxy->password) : 0;
    unsigned char buffer[514];  // 1+1+255+1+255 = max size
    size_t offset = 0;
    if (ulen > 255 || plen > 255) {
        return -1;
    }
    buffer[offset++] = 0x01;  // sub-negotiation version
    buffer[offset++] = (unsigned char)ulen;
    if (ulen) {
        memcpy(buffer + offset, proxy->username, ulen);
        offset += ulen;
    }
    buffer[offset++] = (unsigned char)plen;
    if (plen) {
        memcpy(buffer + offset, proxy->password, plen);
        offset += plen;
    }
    return (async_stream_write(proxy->tcp, buffer, (long)offset) ==
        (long)offset) ? 0 : -1;
}

// Send the SOCKS5 CONNECT request after method negotiation completes.
static int async_proxy_send_socks5_connect(CAsyncProxy *proxy)
{
    unsigned char buffer[512];
    size_t offset = 0;
    buffer[offset++] = 0x05;  // SOCKS version
    buffer[offset++] = 0x01;  // CONNECT command
    buffer[offset++] = 0x00;  // reserved
    buffer[offset++] = (unsigned char)proxy->target_type;
    if (proxy->target_type == 1) {
        // IPv4 address: 4 bytes
        memcpy(buffer + offset, proxy->target_ipv4, 4);
        offset += 4;
    }
    else if (proxy->target_type == 4) {
        // IPv6 address: 16 bytes
        memcpy(buffer + offset, proxy->target_ipv6, 16);
        offset += 16;
    }
    else {
        // Domain name: 1-byte length + name bytes
        size_t host_len = strlen(proxy->target_host);
        buffer[offset++] = (unsigned char)host_len;
        memcpy(buffer + offset, proxy->target_host, host_len);
        offset += host_len;
    }
    // Port number in network byte order (big-endian).
    buffer[offset++] = (unsigned char)((proxy->target_port >> 8) & 0xff);
    buffer[offset++] = (unsigned char)(proxy->target_port & 0xff);
    return (async_stream_write(proxy->tcp, buffer, (long)offset) ==
        (long)offset) ? 0 : -1;
}

// Determine the expected reply length for a SOCKS5 CONNECT response.
// The reply format is: VER(1) + REP(1) + RSV(1) + ATYP(1) + ADDR + PORT(2).
// Returns: total bytes needed, 0 if not enough data yet, -1 on error.
static int async_proxy_socks5_reply_length(struct IMSTREAM *buffer)
{
    unsigned char head[5];
    ilong size = ims_dsize(buffer);
    if (size < 5) {
        return 0;
    }
    ims_peek(buffer, head, 5);
    switch (head[3]) {  // ATYP field
    case 1:     // IPv4: 4 + 2 = 6 bytes after the 4-byte header
        return (size >= 10) ? 10 : 0;
    case 4:     // IPv6: 16 + 2 = 18 bytes after the 4-byte header
        return (size >= 22) ? 22 : 0;
    case 3:     // Domain: 1-byte len + name + 2 bytes after header
        {
            int len = head[4];
            int need = 7 + len;
            return (size >= need) ? need : 0;
        }
    default:
        return -1;
    }
}

// Process SOCKS5 METHOD selection stage.
// Returns: 0 = stage advanced (continue loop), 1 = need more data,
// -1 = error (fail already called), 2 = proxy destroyed.
static int async_proxy_socks5_process_method(CAsyncProxy *proxy)
{
    unsigned char reply[2];
    ilong size = ims_dsize(&proxy->handshake_buf);
    if (size < 2) {
        return 1;  // need more data
    }
    ims_read(&proxy->handshake_buf, reply, 2);
    if (reply[0] != 0x05) {
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL) ? 2 : -1;
    }
    if (reply[1] == 0xff) {
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_AUTH) ? 2 : -1;
    }
    if (proxy->stream.loop &&
        (proxy->stream.loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
        async_loop_log(proxy->stream.loop, ASYNC_LOOP_LOG_PROXY,
            "[proxy] SOCKS5 method selected: 0x%02x%s",
            reply[1],
            reply[1] == 0x00 ? " (NO_AUTH)" :
            reply[1] == 0x02 ? " (USERNAME/PASSWORD)" : "");
    }
    if (reply[1] == 0x02) {
        if (!proxy->socks5_offered_auth) {
            return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL) ? 2 : -1;
        }
        if (async_proxy_send_socks5_auth(proxy) != 0) {
            return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL) ? 2 : -1;
        }
        proxy->socks5_stage = SOCKS5_STAGE_AUTH;
        return 0;
    }
    if (reply[1] == 0x00) {
        if (async_proxy_send_socks5_connect(proxy) != 0) {
            return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL) ? 2 : -1;
        }
        proxy->socks5_stage = SOCKS5_STAGE_CONNECT;
        return 0;
    }
    // Unsupported authentication method (e.g. GSSAPI).
    return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_UNSUPPORTED) ? 2 : -1;
}

// Process SOCKS5 USERNAME/PASSWORD sub-negotiation stage.
// Returns: 0 = stage advanced (continue loop), 1 = need more data,
// -1 = error (fail already called), 2 = proxy destroyed.
static int async_proxy_socks5_process_auth(CAsyncProxy *proxy)
{
    unsigned char reply[2];
    ilong size = ims_dsize(&proxy->handshake_buf);
    if (size < 2) {
        return 1;  // need more data
    }
    ims_read(&proxy->handshake_buf, reply, 2);
    if (reply[0] != 0x01) {
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL) ? 2 : -1;
    }
    if (reply[1] != 0x00) {
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_AUTH) ? 2 : -1;
    }
    if (proxy->stream.loop &&
        (proxy->stream.loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
        async_loop_log(proxy->stream.loop, ASYNC_LOOP_LOG_PROXY,
            "[proxy] SOCKS5 auth succeeded, sending CONNECT request");
    }
    if (async_proxy_send_socks5_connect(proxy) != 0) {
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL) ? 2 : -1;
    }
    proxy->socks5_stage = SOCKS5_STAGE_CONNECT;
    return 0;
}

// Process SOCKS5 CONNECT request/reply stage.
// Returns: 0 = tunnel ready (mark_ready succeeded), 1 = need more data,
// -1 = error (fail already called), 2 = proxy destroyed.
static int async_proxy_socks5_process_connect(CAsyncProxy *proxy)
{
    unsigned char reply[300];
    int need = async_proxy_socks5_reply_length(&proxy->handshake_buf);
    if (need <= 0) {
        if (need < 0) {
            return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL) ? 2 : -1;
        }
        return 1;  // not enough data yet
    }
    if (need > (int)sizeof(reply)) {
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL) ? 2 : -1;
    }
    ims_read(&proxy->handshake_buf, reply, need);
    if (reply[0] != 0x05) {
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL) ? 2 : -1;
    }
    if (reply[1] != 0x00) {
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL) ? 2 : -1;
    }
    // Extract bound address from the reply:
    // VER(1) + REP(1) + RSV(1) + ATYP(1) + ADDR + PORT(2)
    {
        int atyp = reply[3];
        if (atyp == 1) {
            memcpy(proxy->bind_ipv4, reply + 4, 4);
            proxy->bind_port = (reply[8] << 8) | reply[9];
            proxy->bind_type = 1;
        }
        else if (atyp == 4) {
            memcpy(proxy->bind_ipv6, reply + 4, 16);
            proxy->bind_port = (reply[20] << 8) | reply[21];
            proxy->bind_type = 4;
        }
        else if (atyp == 3) {
            proxy->bind_type = 0;
        }
    }
    if (proxy->stream.loop &&
        (proxy->stream.loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
        char bind_str[64];
        if (proxy->bind_type == 1) {
            snprintf(bind_str, sizeof(bind_str), "%d.%d.%d.%d:%d",
                proxy->bind_ipv4[0], proxy->bind_ipv4[1],
                proxy->bind_ipv4[2], proxy->bind_ipv4[3],
                proxy->bind_port);
        }
        else if (proxy->bind_type == 4) {
            snprintf(bind_str, sizeof(bind_str), "[ipv6]:%d",
                proxy->bind_port);
        }
        else {
            snprintf(bind_str, sizeof(bind_str), "n/a");
        }
        async_loop_log(proxy->stream.loop, ASYNC_LOOP_LOG_PROXY,
            "[proxy] SOCKS5 connect reply: bound=%s", bind_str);
    }
    return async_proxy_mark_ready(proxy) ? 2 : 0;
}

// Process SOCKS5 handshake data in handshake_buf. Each stage consumes
// its expected bytes and advances to the next stage, or waits for
// more data if not enough is available yet.
// Returns 1 if the proxy was destroyed, 0 if still alive.
static int async_proxy_process_socks5(CAsyncProxy *proxy)
{
    int rc;
    while (proxy->state == PROXY_STATE_NEGOTIATING) {
        if (proxy->socks5_stage == SOCKS5_STAGE_METHOD) {
            rc = async_proxy_socks5_process_method(proxy);
        }
        else if (proxy->socks5_stage == SOCKS5_STAGE_AUTH) {
            rc = async_proxy_socks5_process_auth(proxy);
        }
        else if (proxy->socks5_stage == SOCKS5_STAGE_CONNECT) {
            rc = async_proxy_socks5_process_connect(proxy);
        }
        else {
            return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL);
        }
        // rc: 0 = stage advanced, continue; 1 = need more data, return;
        // -1 = error already handled, return; 2 = proxy destroyed, return 1.
        if (rc == 2) {
            return 1;
        }
        if (rc != 0) {
            return 0;
        }
    }
    return 0;
}


//---------------------------------------------------------------------
// SOCKS4/SOCKS4a handshake
//---------------------------------------------------------------------

// Build and send a SOCKS4 or SOCKS4a CONNECT request.
// SOCKS4a (target_type == 3) puts the domain name after the NULL-
// terminated userid, per the SOCKS4a extension convention.
static int async_proxy_start_socks4(CAsyncProxy *proxy)
{
    unsigned char buffer[PROXY_SOCKS4_MAX_PACKET];
    size_t offset = 0;
    const char *userid = proxy->username ? proxy->username : "";
    size_t userlen = strlen(userid);
    size_t host_len = 0;

    // Pre-calculate total packet size to avoid buffer overflow.
    // Format: VER(1) + CMD(1) + PORT(2) + IP(4) + USERID + NUL(1)
    //         + [DOMAIN + NUL(1)] (SOCKS4a only)
    if (userlen > 255) {
        return -1;
    }
    if (proxy->target_type == 3) {
        host_len = strlen(proxy->target_host);
    }
    // Fixed header: 9 bytes = VER(1)+CMD(1)+PORT(2)+IP(4)+NUL(1)
    if (9 + userlen + 1 + host_len + (host_len ? 1 : 0) >
        sizeof(buffer)) {
        return -1;  // packet too large for stack buffer
    }

    buffer[offset++] = 0x04;  // SOCKS4 version
    buffer[offset++] = 0x01;  // CONNECT command
    buffer[offset++] = (unsigned char)((proxy->target_port >> 8) & 0xff);
    buffer[offset++] = (unsigned char)(proxy->target_port & 0xff);
    if (proxy->target_type == 1) {
        // IPv4 address
        memcpy(buffer + offset, proxy->target_ipv4, 4);
        offset += 4;
    }
    else {
        // SOCKS4a: use 0.0.0.1 as the IP to signal domain resolution.
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x00;
        buffer[offset++] = 0x01;
    }
    if (userlen) {
        memcpy(buffer + offset, userid, userlen);
        offset += userlen;
    }
    buffer[offset++] = 0x00;  // NULL terminates userid
    if (proxy->target_type == 3) {
        // SOCKS4a: domain name after userid's NULL terminator.
        memcpy(buffer + offset, proxy->target_host, host_len);
        offset += host_len;
        buffer[offset++] = 0x00;  // NULL terminates domain name
    }
    return (async_stream_write(proxy->tcp, buffer, (long)offset) ==
        (long)offset) ? 0 : -1;
}

// Process the 8-byte SOCKS4 reply. Only byte[1] matters:
// 0x5a = request granted, anything else = rejected.
// Returns 1 if the proxy was destroyed, 0 if still alive.
static int async_proxy_process_socks4(CAsyncProxy *proxy)
{
    unsigned char reply[8];
    if (ims_dsize(&proxy->handshake_buf) < 8) {
        return 0;  // need more data, proxy still alive
    }
    ims_read(&proxy->handshake_buf, reply, 8);
    if (reply[1] != 0x5a) {
        if (proxy->stream.loop &&
            (proxy->stream.loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
            async_loop_log(proxy->stream.loop, ASYNC_LOOP_LOG_PROXY,
                "[proxy] SOCKS4 rejected: reply=0x%02x", reply[1]);
        }
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL);
    }
    // SOCKS4 reply: VN(1) + CD(1) + PORT(2) + IP(4)
    memcpy(proxy->bind_ipv4, reply + 4, 4);
    proxy->bind_port = (reply[2] << 8) | reply[3];
    proxy->bind_type = 1;
    if (proxy->stream.loop &&
        (proxy->stream.loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
        async_loop_log(proxy->stream.loop, ASYNC_LOOP_LOG_PROXY,
            "[proxy] SOCKS4 granted: bound=%d.%d.%d.%d:%d",
            proxy->bind_ipv4[0], proxy->bind_ipv4[1],
            proxy->bind_ipv4[2], proxy->bind_ipv4[3],
            proxy->bind_port);
    }
    return async_proxy_mark_ready(proxy);
}


//---------------------------------------------------------------------
// HTTP CONNECT handshake
//---------------------------------------------------------------------

// Find the end of HTTP headers (\r\n\r\n) in a buffer.
// Returns the offset of the first byte after the header block,
// or -1 if the header block is not yet complete.
static ilong async_proxy_find_header_end(const char *buffer, ilong size)
{
    ilong i;
    for (i = 0; i + 3 < size; ++i) {
        if (buffer[i] == '\r' && buffer[i + 1] == '\n' &&
            buffer[i + 2] == '\r' && buffer[i + 3] == '\n') {
            return i + 4;
        }
    }
    return -1;
}

// Parse the HTTP status code from a response header.
// Skips the HTTP version string, then reads the 3-digit code.
// Returns the status code (e.g. 200) or -1 on parse failure.
static int async_proxy_parse_http_status(const char *buffer, ilong size)
{
    ilong i = 0;
    int code = 0;
    // Skip "HTTP/1.x" version string.
    while (i < size && buffer[i] != ' ') {
        ++i;
    }
    while (i < size && buffer[i] == ' ') {
        ++i;
    }
    if (i + 2 >= size) {
        return -1;
    }
    if (!isdigit((unsigned char)buffer[i]) ||
        !isdigit((unsigned char)buffer[i + 1]) ||
        !isdigit((unsigned char)buffer[i + 2])) {
        return -1;
    }
    code = (buffer[i] - '0') * 100 +
        (buffer[i + 1] - '0') * 10 +
        (buffer[i + 2] - '0');
    return code;
}

// Build and send the HTTP CONNECT request to the proxy.
// Format: "CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n"
// Optional: "Proxy-Authorization: Basic <base64>\r\n"
static int async_proxy_start_http(CAsyncProxy *proxy)
{
    char hostport[512];
    char *auth_value = NULL;
    char *request = NULL;
    size_t capacity;
    int written;
    int rc = -1;  // default: failure
    int hp_len;

    hp_len = async_proxy_format_hostport(proxy, hostport, sizeof(hostport));
    if (hp_len < 0) {
        goto cleanup;
    }

    // Build Proxy-Authorization header if username is provided.
    if (proxy->username) {
        size_t user_len = strlen(proxy->username);
        size_t pass_len = proxy->password ? strlen(proxy->password) : 0;
        size_t raw_len = user_len + 1 + pass_len;
        char *raw = (char*)ikmem_malloc(raw_len);
        ilong enc;
        if (raw == NULL) {
            goto cleanup;
        }
        memcpy(raw, proxy->username, user_len);
        raw[user_len] = ':';
        if (pass_len) {
            memcpy(raw + user_len + 1, proxy->password, pass_len);
        }
        enc = ibase64_encode(raw, (ilong)raw_len, NULL);
        auth_value = (char*)ikmem_malloc((size_t)enc + 1);
        if (auth_value == NULL) {
            ikmem_free(raw);
            goto cleanup;
        }
        ibase64_encode(raw, (ilong)raw_len, auth_value);
        auth_value[enc] = '\0';
        ikmem_free(raw);
    }

    // Allocate and format the CONNECT request.
    capacity = strlen(hostport) * 2 + 256 +
        (auth_value ? strlen(auth_value) + 64 : 0);
    request = (char*)ikmem_malloc(capacity);
    if (request == NULL) {
        goto cleanup;
    }
    written = snprintf(request, capacity,
        "CONNECT %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Proxy-Connection: keep-alive\r\n",
        hostport, hostport);
    if (written < 0 || (size_t)written >= capacity) {
        goto cleanup;
    }
    if (auth_value) {
        int add = snprintf(request + written, capacity - written,
            "Proxy-Authorization: Basic %s\r\n", auth_value);
        if (add < 0 || (size_t)written + add >= capacity) {
            goto cleanup;
        }
        written += add;
    }
    // Final \r\n to end the headers.
    if (written + 2 >= (int)capacity) {
        goto cleanup;
    }
    request[written++] = '\r';
    request[written++] = '\n';
    request[written] = '\0';

    // Send the request through the TCP stream.
    if (async_stream_write(proxy->tcp, request, written) != written) {
        goto cleanup;
    }
    rc = 0;  // success

cleanup:
    ikmem_free(auth_value); auth_value = NULL;
    if (request) {
        ikmem_free(request);
    }
    return rc;
}

// Find the end of HTTP headers (\r\n\r\n) in an IMSTREAM buffer.
// Uses ims_peek to scan in chunks without allocating a contiguous buffer.
// Returns the offset of the first byte after the header block,
// or -1 if the header block is not yet complete.
static ilong async_proxy_find_header_end_stream(struct IMSTREAM *buffer)
{
    ilong total = ims_dsize(buffer);
    ilong scanned = 0;
    // ims_peek always reads from the head, so we peek increasingly
    // larger windows, checking the new portion each time.
    // Keep 3 bytes of overlap from the previous scan boundary to
    // catch \r\n\r\n spanning two chunks.
    while (scanned < total) {
        ilong peek_size = scanned + 512;
        if (peek_size > total) peek_size = total;
        char chunk[512 + 3];
        ilong overlap = (scanned > 3) ? 3 : scanned;
        ilong got = ims_peek(buffer, chunk, peek_size);
        if (got <= 0) break;
        // Search only the new portion (scanned - overlap .. peek_size)
        ilong search_start = scanned - overlap;
        if (search_start < 0) search_start = 0;
        ilong pos = async_proxy_find_header_end(chunk + search_start,
            got - search_start);
        if (pos >= 0) {
            return search_start + pos;
        }
        scanned = got;
    }
    return -1;
}

// Parse the HTTP status code from the first N bytes of an IMSTREAM buffer.
// Returns the status code (e.g. 200) or -1 on parse failure.
static int async_proxy_parse_http_status_stream(struct IMSTREAM *buffer, ilong size)
{
    char head[64];
    if (size > (ilong)sizeof(head)) {
        size = (ilong)sizeof(head);
    }
    if (ims_peek(buffer, head, size) < size) {
        return -1;
    }
    return async_proxy_parse_http_status(head, size);
}

// Process the HTTP CONNECT proxy response.
// Waits for the full header block (\r\n\r\n), then checks the
// status code. Only 2xx is accepted as a successful CONNECT.
// Returns 1 if the proxy was destroyed, 0 if still alive.
static int async_proxy_process_http(CAsyncProxy *proxy)
{
    ilong size = ims_dsize(&proxy->handshake_buf);
    ilong header;
    int status;
    int error_code;
    if (size <= 0) {
        return 0;
    }
    header = async_proxy_find_header_end_stream(&proxy->handshake_buf);
    if (header < 0) {
        return 0;
    }
    status = async_proxy_parse_http_status_stream(&proxy->handshake_buf, header);
    if (status < 0) {
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL);
    }
    // Map HTTP 407 (Proxy Authentication Required) to AUTH error.
    // Other non-2xx status codes are protocol errors.
    error_code = (status == 407) ?
        ASYNC_PROXY_ERROR_AUTH : ASYNC_PROXY_ERROR_PROTOCOL;
    if (status < 200 || status >= 300) {
        if (proxy->stream.loop &&
            (proxy->stream.loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
            async_loop_log(proxy->stream.loop, ASYNC_LOOP_LOG_PROXY,
                "[proxy] HTTP CONNECT failed: status=%d", status);
        }
        return async_proxy_fail(proxy, error_code);
    }
    if (proxy->stream.loop &&
        (proxy->stream.loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
        async_loop_log(proxy->stream.loop, ASYNC_LOOP_LOG_PROXY,
            "[proxy] HTTP CONNECT succeeded: status=%d", status);
    }
    // Drop the consumed header bytes from handshake_buf.
    ims_drop(&proxy->handshake_buf, header);
    return async_proxy_mark_ready(proxy);
}


//---------------------------------------------------------------------
// on_established - TCP connection to proxy server succeeded
//---------------------------------------------------------------------

// Called when the underlying TCP stream connects to the proxy server.
// Starts the proxy handshake based on proxy_type.
// Returns 1 if the proxy was destroyed, 0 if still alive.
static int async_proxy_on_established(CAsyncProxy *proxy)
{
    CAsyncLoop *loop = proxy->stream.loop;
    proxy->state = PROXY_STATE_NEGOTIATING;
    if (loop && (loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
        async_loop_log(loop, ASYNC_LOOP_LOG_PROXY,
            "[proxy] tcp connected, starting %s handshake -> %s:%d",
            proxy_type_str(proxy->proxy_type),
            proxy->target_host ? proxy->target_host : "?",
            proxy->target_port);
    }
    async_stream_enable(proxy->tcp, ASYNC_EVENT_READ);
    switch (proxy->proxy_type) {
    case ASYNC_STREAM_PROXY_SOCKS5:
        if (async_proxy_start_socks5(proxy) != 0) {
            return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL);
        }
        return 0;
    case ASYNC_STREAM_PROXY_SOCKS4:
        if (async_proxy_start_socks4(proxy) != 0) {
            return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL);
        }
        return 0;
    case ASYNC_STREAM_PROXY_HTTP:
        if (async_proxy_start_http(proxy) != 0) {
            return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_PROTOCOL);
        }
        return 0;
    default:
        return async_proxy_fail(proxy, ASYNC_PROXY_ERROR_UNSUPPORTED);
    }
}


//---------------------------------------------------------------------
// tcp event handler - intercepts events from the underlying stream
//---------------------------------------------------------------------

// This is set as the callback on the underlying TCP stream. It
// handles events differently depending on proxy->ready:
// - Before ready: ESTAB starts handshake, READ feeds handshake_buf,
//   EOF/ERROR triggers proxy failure.
// - After ready: all events are forwarded to the user's callback.
static void async_proxy_tcp_event(CAsyncStream *tcp, int event, int args)
{
    CAsyncProxy *proxy = (CAsyncProxy*)tcp->user;
    // Guard against use-after-free: if user was cleared during teardown,
    // or if tcp was detached, bail out immediately.
    if (proxy == NULL || proxy->tcp != tcp || proxy->closing) {
        return;
    }
    if (event & ASYNC_STREAM_EVT_ESTAB) {
        if (async_proxy_on_established(proxy)) {
            return;
        }
    }
    if (proxy->closing || proxy->state == PROXY_STATE_FAILED) {
        return;
    }
    if (event & ASYNC_STREAM_EVT_READING) {
        if (proxy->ready) {
            if (async_proxy_dispatch(proxy, ASYNC_STREAM_EVT_READING,
                    args)) {
                return;
            }
        }
        else if (proxy->state != PROXY_STATE_FAILED) {
            if (async_proxy_collect_handshake(proxy)) {
                return;
            }
            if (async_proxy_process_handshake(proxy)) {
                return;
            }
        }
    }
    if (proxy->closing || proxy->state == PROXY_STATE_FAILED) {
        return;
    }
    if (event & ASYNC_STREAM_EVT_WRITING) {
        async_proxy_flush_pending(proxy);
        // only report WRITING when the user asked for it
        if (proxy->ready && (proxy->user_enabled & ASYNC_EVENT_WRITE)) {
            if (async_proxy_dispatch(proxy, ASYNC_STREAM_EVT_WRITING,
                    args)) {
                return;
            }
        }
    }
    if (proxy->closing) {
        return;
    }
    if (event & ASYNC_STREAM_EVT_EOF) {
        if (proxy->ready) {
            async_proxy_dispatch(proxy, ASYNC_STREAM_EVT_EOF, args);
        }
        else {
            async_proxy_fail(proxy, tcp->error ? tcp->error : -1);
        }
        return;
    }
    if (proxy->closing) {
        return;
    }
    if (event & ASYNC_STREAM_EVT_ERROR) {
        async_proxy_fail(proxy, tcp->error ? tcp->error : -1);
    }
}


//---------------------------------------------------------------------
// stream virtual dispatch - CAsyncStream vfunc implementations
//---------------------------------------------------------------------

// Read data from the proxy stream. First drains recv_leftover (leftover
// from handshake), then reads from the underlying TCP stream.
static long async_proxy_read(CAsyncStream *stream, void *ptr, long size)
{
    CAsyncProxy *proxy = async_stream_upcast(stream, CAsyncProxy, stream);
    long total = 0;
    if (size <= 0 || ptr == NULL) {
        return 0;
    }
    // Drain recv_leftover first (data that arrived during handshake).
    if (proxy->recv_leftover.size > 0) {
        long take = (long)((proxy->recv_leftover.size < (iulong)size) ?
            proxy->recv_leftover.size : (iulong)size);
        long got = (long)ims_read(&proxy->recv_leftover, ptr, take);
        total += got;
        ptr = (char*)ptr + got;
        size -= got;
    }
    // Once tunnel is ready, read directly from the TCP stream.
    if (size > 0 && proxy->ready) {
        long hr = async_stream_pass_read(stream, ptr, size);
        if (hr > 0) {
            total += hr;
        }
    }
    return total;
}

// Write data to the proxy stream. If the tunnel is not yet ready,
// data is buffered in send_pending. Once ready, buffered data is
// flushed first, then new data is written directly to TCP.
// Returns the number of bytes accepted (buffered or sent).
static long async_proxy_write(CAsyncStream *stream, const void *ptr, long size)
{
    CAsyncProxy *proxy = async_stream_upcast(stream, CAsyncProxy, stream);
    if (size <= 0 || ptr == NULL) {
        return 0;
    }
    if (!proxy->ready) {
        // Tunnel not ready - buffer the data for later.
        ilong wrote = ims_write(&proxy->send_pending, ptr, size);
        return (wrote > 0) ? (long)wrote : 0;
    }
    if (proxy->send_pending.size > 0) {
        // Flush previously buffered data first.
        async_proxy_flush_pending(proxy);
        // If there's still pending data, append new data and try again.
        if (proxy->send_pending.size > 0) {
            ilong appended = ims_write(&proxy->send_pending, ptr, size);
            if (appended <= 0) {
                return 0;
            }
            async_proxy_flush_pending(proxy);
            return (long)appended;
        }
    }
    // No pending data - write directly to the TCP stream.
    {
        long wrote = async_stream_pass_write(stream, ptr, size);
        async_proxy_kick_output(proxy);
        return wrote;
    }
}

// Peek at data in the proxy stream without consuming it.
static long async_proxy_peek(CAsyncStream *stream, void *ptr, long size)
{
    CAsyncProxy *proxy = async_stream_upcast(stream, CAsyncProxy, stream);
    long copied = 0;
    if (size <= 0 || ptr == NULL) {
        return 0;
    }
    // Peek recv_leftover first.
    if (proxy->recv_leftover.size > 0) {
        long take = (long)((proxy->recv_leftover.size < (iulong)size) ?
            proxy->recv_leftover.size : (iulong)size);
        ims_peek(&proxy->recv_leftover, ptr, take);
        copied += take;
        ptr = (char*)ptr + take;
        size -= take;
    }
    // Then peek from the underlying TCP stream.
    if (size > 0 && proxy->ready) {
        long hr = async_stream_pass_peek(stream, ptr, size);
        if (hr > 0) {
            copied += hr;
        }
    }
    return copied;
}

// Enable events on the proxy stream. Records what the user wants
// and syncs to the underlying TCP stream when the tunnel is ready.
static void async_proxy_enable(CAsyncStream *stream, int event)
{
    CAsyncProxy *proxy = async_stream_upcast(stream, CAsyncProxy, stream);
    int fresh_read = 0;
    if (event & ASYNC_EVENT_READ) {
        if ((proxy->user_enabled & ASYNC_EVENT_READ) == 0) {
            fresh_read = 1;
        }
        proxy->user_enabled |= ASYNC_EVENT_READ;
    }
    if (event & ASYNC_EVENT_WRITE) {
        proxy->user_enabled |= ASYNC_EVENT_WRITE;
    }
    stream->enabled = proxy->user_enabled;
    async_proxy_apply_user_enabled(proxy);
    // READ just went from off to on: bytes may already be sitting in
    // recv_leftover or in the underlying TCP recv buffer. READING is a
    // level-triggered notification and will NOT be repeated for data that
    // arrived earlier (async_tcp_evt_read only dispatches when it actually
    // reads new bytes), so with the peer waiting for our next request the
    // classic backpressure pattern -- disable READ, process, enable READ --
    // would deadlock. Queue a notification instead, same as the
    // async_filter_enable() fresh_read branch in inetkit.c and the tail of
    // async_ssl_enable() in inetssl.c.
    if (fresh_read && proxy->ready && proxy->closing == 0) {
        if (async_proxy_remain(stream) > 0) {
            async_proxy_notify_reading(proxy);
        }
    }
}

// Disable events on the proxy stream.
static void async_proxy_disable(CAsyncStream *stream, int event)
{
    CAsyncProxy *proxy = async_stream_upcast(stream, CAsyncProxy, stream);
    if (event & ASYNC_EVENT_READ) {
        proxy->user_enabled &= ~ASYNC_EVENT_READ;
    }
    if (event & ASYNC_EVENT_WRITE) {
        proxy->user_enabled &= ~ASYNC_EVENT_WRITE;
    }
    stream->enabled = proxy->user_enabled;
    async_proxy_apply_user_enabled(proxy);
}

// Return total bytes available for reading (recv_leftover + TCP recv buffer).
static long async_proxy_remain(const CAsyncStream *stream)
{
    const CAsyncProxy *proxy = async_stream_private((CAsyncStream*)stream,
        CAsyncProxy);
    long total = (long)proxy->recv_leftover.size;
    if (proxy->ready && stream->underlying) {
        long rest = async_stream_pass_remain(stream);
        if (rest > 0) {
            total += rest;
        }
    }
    return total;
}

// Return total bytes pending in the send path (send_pending + TCP send buffer).
static long async_proxy_pending(const CAsyncStream *stream)
{
    const CAsyncProxy *proxy = async_stream_private((CAsyncStream*)stream,
        CAsyncProxy);
    long total = (long)proxy->send_pending.size;
    if (proxy->ready && stream->underlying) {
        long rest = async_stream_pass_pending(stream);
        if (rest > 0) {
            total += rest;
        }
    }
    return total;
}

// Apply watermark settings to the underlying TCP stream.
static void async_proxy_watermark(CAsyncStream *stream, long high, long low)
{
    CAsyncProxy *proxy = async_stream_upcast(stream, CAsyncProxy, stream);
    if (high >= 0) {
        stream->hiwater = high;
    }
    if (low >= 0) {
        stream->lowater = low;
    }
    async_proxy_apply_watermark(proxy);
}

// Pass option requests through to the underlying TCP stream.
// ASYNC_STREAM_OPTION_PROXY_TIMEOUT is handled locally: value is the
// timeout in milliseconds; 0 disables the handshake timer. Returns
// the previous timeout value, or -1 for unrecognized options.
static long async_proxy_option(CAsyncStream *stream, int option, long value)
{
    CAsyncProxy *proxy = async_stream_upcast(stream, CAsyncProxy, stream);
    if (option == ASYNC_STREAM_OPTION_PROXY_TIMEOUT) {
        IUINT32 old = proxy->timeout_ms;
        if (value >= 0) {
            proxy->timeout_ms = (IUINT32)value;
            // If timer is active and timeout changed, restart it.
            if (proxy->stream.loop && async_timer_active(&proxy->timer)) {
                async_timer_stop(proxy->stream.loop, &proxy->timer);
                if (proxy->timeout_ms > 0 && proxy->ready == 0) {
                    async_timer_start(proxy->stream.loop, &proxy->timer,
                        proxy->timeout_ms, 1);
                }
            }
        }
        return (long)old;
    }
    return async_stream_pass_option(stream, option, value);
}

// Close the proxy stream. Prevents double-close via the closing flag,
// then calls async_proxy_destroy to release all resources.
static void async_proxy_close(CAsyncStream *stream)
{
    CAsyncProxy *proxy = async_stream_upcast(stream, CAsyncProxy, stream);
    if (proxy->closing) {
        return;
    }
    proxy->closing = 1;
    // Defer destroy if called reentrantly from within a dispatch callback.
    // The dispatch wrapper will perform the actual destroy after the
    // callback returns. Otherwise destroy immediately.
    if (!proxy->in_dispatch) {
        async_proxy_destroy(proxy);
    }
}


//---------------------------------------------------------------------
// proxy URL parsing helpers
//---------------------------------------------------------------------

// Map a proxy URL scheme string to ASYNC_STREAM_PROXY_* type.
// Comparison is case-insensitive. Returns -1 for unrecognized schemes.
static int async_proxy_scheme_to_type(const char *scheme, int len)
{
    if (len == 6 && istrncasecmp(scheme, "socks4", 6) == 0) {
        return ASYNC_STREAM_PROXY_SOCKS4;
    }
    if (len == 7 && istrncasecmp(scheme, "socks4a", 7) == 0) {
        return ASYNC_STREAM_PROXY_SOCKS4;
    }
    if (len == 6 && istrncasecmp(scheme, "socks5", 6) == 0) {
        return ASYNC_STREAM_PROXY_SOCKS5;
    }
    if (len == 7 && istrncasecmp(scheme, "socks5h", 7) == 0) {
        return ASYNC_STREAM_PROXY_SOCKS5;
    }
    if (len == 4 && istrncasecmp(scheme, "http", 4) == 0) {
        return ASYNC_STREAM_PROXY_HTTP;
    }
    if (len == 5 && istrncasecmp(scheme, "https", 5) == 0) {
        return ASYNC_STREAM_PROXY_HTTP;
    }
    return -1;
}

// Return the default port for a proxy type.
static int async_proxy_default_port(int proxy_type)
{
    switch (proxy_type) {
    case ASYNC_STREAM_PROXY_SOCKS4:
    case ASYNC_STREAM_PROXY_SOCKS5:
        return 1080;
    case ASYNC_STREAM_PROXY_HTTP:
        return 8080;
    default:
        return 0;
    }
}

// Parse a proxy URL of the form:
//   scheme://[user[:password]@]host[:port]
// Supported schemes: socks4, socks4a, socks5, socks5h, http, https
// On success, fills *proxy_type, *host, *port, *username, *password.
// On failure, all output string pointers are set to NULL.
// The caller must ikmem_free any non-NULL *host, *username, *password.
// Returns 0 on success, -1 on error.
int async_stream_proxy_parse(const char *url, int *proxy_type,
    char **host, int *port, char **username, char **password)
{
    const char *scheme_end;
    const char *p;
    const char *auth_start;
    const char *auth_end;
    const char *host_start;
    const char *host_end;
    const char *port_start;
    char *lhost = NULL;
    char *luser = NULL;
    char *lpass = NULL;
    int scheme_len;
    int default_port;

    if (url == NULL || proxy_type == NULL || host == NULL ||
            port == NULL || username == NULL || password == NULL) {
        return -1;
    }
    *host = NULL;
    *username = NULL;
    *password = NULL;

    // Find "://" separator.
    scheme_end = strstr(url, "://");
    if (scheme_end == NULL || scheme_end == url) {
        goto fail;
    }
    scheme_len = (int)(scheme_end - url);
    *proxy_type = async_proxy_scheme_to_type(url, scheme_len);
    if (*proxy_type < 0) {
        goto fail;
    }
    default_port = async_proxy_default_port(*proxy_type);

    // Move past "://".
    p = scheme_end + 3;

    // Optional authentication: user[:password]@
    auth_start = p;
    auth_end = strchr(p, '@');
    if (auth_end != NULL) {
        const char *colon = strchr(auth_start, ':');
        int has_pass = (colon != NULL && colon < auth_end);
        if (has_pass) {
            luser = istrndup(auth_start, (ilong)(colon - auth_start));
            lpass = istrndup(colon + 1, (ilong)(auth_end - colon - 1));
        }
        else {
            luser = istrndup(auth_start, (ilong)(auth_end - auth_start));
            lpass = NULL;
        }
        if (luser == NULL || (has_pass && lpass == NULL)) {
            goto fail;
        }
        p = auth_end + 1;
    }

    // Parse host[:port].
    host_start = p;
    host_end = NULL;
    port_start = NULL;

    if (host_start[0] == '[') {
        // IPv6 bracket notation: [host]:port
        const char *bracket_end = strchr(host_start, ']');
        if (bracket_end == NULL) {
            goto fail;
        }
        host_start = host_start + 1;
        host_end = bracket_end;
        p = bracket_end + 1;
        if (*p == ':') {
            port_start = p + 1;
        }
        else if (*p != '\0') {
            goto fail;
        }
    }
    else {
        // IPv4 address or hostname; last ':' separates port.
        const char *colon = strrchr(host_start, ':');
        if (colon != NULL) {
            host_end = colon;
            port_start = colon + 1;
        }
        else {
            host_end = host_start + strlen(host_start);
        }
    }

    if (host_end <= host_start) {
        goto fail;
    }
    lhost = istrndup(host_start, (ilong)(host_end - host_start));
    if (lhost == NULL) {
        goto fail;
    }

    if (port_start != NULL && port_start[0] != '\0') {
        const char *endptr = NULL;
        long port_val = istrtol(port_start, &endptr, 10);
        if (endptr == port_start || *endptr != '\0' ||
                port_val <= 0 || port_val > 65535) {
            goto fail;
        }
        *port = (int)port_val;
    }
    else {
        *port = default_port;
    }

    *host = lhost;
    *username = luser;
    *password = lpass;
    return 0;

fail:
    ikmem_free(lhost);
    ikmem_free(luser);
    ikmem_free(lpass);
    return -1;
}

// Resolve a proxy host name and port into a sockaddr.
// Supports IPv4/IPv6 literals and DNS names via getaddrinfo.
// Returns 0 on success, -1 on error.
static int async_proxy_resolve_addr(const char *host, int port,
    struct sockaddr_storage *addr, int *addrlen)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char service[16];

    if (host == NULL || addr == NULL || addrlen == NULL) {
        return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(service, sizeof(service), "%d", port);

    if (getaddrinfo(host, service, &hints, &res) == 0 && res != NULL) {
        if (res->ai_addrlen > (int)sizeof(*addr)) {
            freeaddrinfo(res);
            return -1;
        }
        memcpy(addr, res->ai_addr, res->ai_addrlen);
        *addrlen = (int)res->ai_addrlen;
        freeaddrinfo(res);
        return 0;
    }

    // Fallback: try parsing host as an IP literal.
    {
        struct sockaddr_in sin4;
        memset(&sin4, 0, sizeof(sin4));
        if (isockaddr_pton(AF_INET, host, &sin4.sin_addr) == 0) {
            sin4.sin_family = AF_INET;
            sin4.sin_port = htons((unsigned short)port);
            memcpy(addr, &sin4, sizeof(sin4));
            *addrlen = sizeof(sin4);
            return 0;
        }
    }

#ifdef AF_INET6
    {
        struct sockaddr_in6 sin6;
        memset(&sin6, 0, sizeof(sin6));
        if (isockaddr_pton(AF_INET6, host, &sin6.sin6_addr) == 0) {
            sin6.sin6_family = AF_INET6;
            sin6.sin6_port = htons((unsigned short)port);
            memcpy(addr, &sin6, sizeof(sin6));
            *addrlen = sizeof(sin6);
            return 0;
        }
    }
#endif

    return -1;
}


//---------------------------------------------------------------------
// public interface - async_stream_proxy_new
//---------------------------------------------------------------------

// Create a proxy stream that tunnels a TCP connection through a proxy.
// Allocates a CAsyncProxy, sets up the underlying TCP connection to
// the proxy server, and configures the virtual dispatch table.
CAsyncStream *async_stream_proxy_new(CAsyncLoop *loop, int proxy_type,
    const struct sockaddr *proxy_addr, int proxy_addrlen,
    const char *username, const char *password,
    const char *target_host, int target_port,
    void (*callback)(CAsyncStream *stream, int event, int args))
{
    CAsyncProxy *proxy;
    CAsyncStream *stream;
    if (loop == NULL || proxy_addr == NULL || target_host == NULL) {
        return NULL;
    }
    if (proxy_type < 0 || proxy_type > 2) {
        return NULL;
    }
    if (target_port <= 0 || target_port > 65535) {
        return NULL;
    }
    // Allocate and zero-initialize the proxy struct.
    proxy = (CAsyncProxy*)ikmem_malloc(sizeof(CAsyncProxy));
    if (proxy == NULL) {
        return NULL;
    }
    memset(proxy, 0, sizeof(*proxy));
    proxy->proxy_type = proxy_type;
    proxy->target_port = target_port;
    proxy->target_host = istrdup(target_host);
    proxy->username = istrdupopt(username);
    proxy->password = istrdupopt(password);
    // Validate target_host was successfully duplicated.
    if (proxy->target_host == NULL) {
        async_proxy_destroy(proxy);
        return NULL;
    }
    // Initialize IMSTREAM buffers using the loop's memory node allocator.
    ims_init(&proxy->send_pending, &loop->memnode, 0, 0);
    ims_init(&proxy->handshake_buf, &loop->memnode, 0, 0);
    ims_init(&proxy->recv_leftover, &loop->memnode, 0, 0);
    // Parse and validate the target address.
    if (async_proxy_prepare_target(proxy) != 0) {
        async_proxy_destroy(proxy);
        return NULL;
    }
    // Create the underlying TCP stream to connect to the proxy server.
    proxy->tcp = async_stream_tcp_connect(loop, async_proxy_tcp_event,
        proxy_addr, proxy_addrlen);
    if (proxy->tcp == NULL) {
        async_proxy_destroy(proxy);
        return NULL;
    }
    // Link the TCP stream back to this proxy for event routing.
    proxy->tcp->user = proxy;
    // Set up the proxy stream's virtual dispatch table and metadata.
    stream = &proxy->stream;
    async_stream_zero(stream);
    stream->name = ASYNC_STREAM_NAME_PROXY;
    stream->loop = loop;
    stream->callback = callback;
    stream->direction = ASYNC_STREAM_BOTH;
    stream->state = ASYNC_STREAM_CONNECTING;
    // WRITE is enabled by default, same convention as the tcp / pair /
    // filter streams: it is what keeps the output path flushing.
    stream->enabled = ASYNC_EVENT_WRITE;
    proxy->user_enabled = ASYNC_EVENT_WRITE;
    stream->instance = proxy;
    stream->close = async_proxy_close;
    stream->read = async_proxy_read;
    stream->write = async_proxy_write;
    stream->peek = async_proxy_peek;
    stream->enable = async_proxy_enable;
    stream->disable = async_proxy_disable;
    stream->remain = async_proxy_remain;
    stream->pending = async_proxy_pending;
    stream->watermark = async_proxy_watermark;
    stream->option = async_proxy_option;
    // The proxy owns the TCP stream and will close it in destroy.
    stream->underlying = proxy->tcp;
    stream->underown = 1;
    // Initialize and start handshake timeout timer (one-shot).
    proxy->timeout_ms = PROXY_HANDSHAKE_TIMEOUT;
    async_timer_init(&proxy->timer, async_proxy_timer_cb);
    proxy->timer.user = proxy;
    async_timer_start(loop, &proxy->timer, proxy->timeout_ms, 1);
    // Initialize the postpone used for deferred READING notifications.
    async_post_init(&proxy->evt_post, async_proxy_post_cb);
    proxy->evt_post.user = proxy;
    // Enable READ on the TCP stream to receive handshake replies.
    async_stream_enable(proxy->tcp, ASYNC_EVENT_READ);
    if (loop && (loop->logmask & ASYNC_LOOP_LOG_PROXY)) {
        char addr_str[64];
        if (proxy_addr->sa_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in*)proxy_addr;
            char ip[48];
            isockaddr_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            snprintf(addr_str, sizeof(addr_str), "%s:%d", ip,
                (int)ntohs(sin->sin_port));
        }
#if defined(AF_INET6)
        else if (proxy_addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6*)proxy_addr;
            char ip[48];
            isockaddr_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
            snprintf(addr_str, sizeof(addr_str), "[%s]:%d", ip,
                (int)ntohs(sin6->sin6_port));
        }
#endif
        else {
            snprintf(addr_str, sizeof(addr_str), "unknown");
        }
        async_loop_log(loop, ASYNC_LOOP_LOG_PROXY,
            "[proxy] created %s stream: proxy=%s -> %s:%d",
            proxy_type_str(proxy_type), addr_str,
            target_host, target_port);
    }
    return stream;
}


//---------------------------------------------------------------------
// public interface - async_stream_proxy_newex
//---------------------------------------------------------------------

// Create a proxy stream from a URL string that describes the proxy server.
// proxy_url format: scheme://[user[:password]@]host[:port]
// Supported schemes: socks4, socks4a, socks5, socks5h, http, https
// Default ports: socks4/socks4a/socks5/socks5h = 1080, http/https = 8080
// The target_host/target_port specify the destination behind the proxy.
// Internally resolves the proxy host name synchronously and calls
// async_stream_proxy_new to perform the actual connection and handshake.
CAsyncStream *async_stream_proxy_newex(CAsyncLoop *loop,
    const char *proxy_url,
    const char *target_host, int target_port,
    void (*callback)(CAsyncStream *stream, int event, int args))
{
    int proxy_type;
    char *host = NULL;
    char *username = NULL;
    char *password = NULL;
    int port = 0;
    struct sockaddr_storage addr;
    int addrlen = 0;
    CAsyncStream *stream = NULL;

    if (loop == NULL || proxy_url == NULL || target_host == NULL) {
        return NULL;
    }
    if (target_port <= 0 || target_port > 65535) {
        return NULL;
    }

    if (async_stream_proxy_parse(proxy_url, &proxy_type,
            &host, &port, &username, &password) != 0) {
        goto cleanup;
    }

    if (async_proxy_resolve_addr(host, port, &addr, &addrlen) != 0) {
        goto cleanup;
    }

    stream = async_stream_proxy_new(loop, proxy_type,
        (const struct sockaddr *)&addr, addrlen,
        username, password, target_host, target_port, callback);

cleanup:
    ikmem_free(host);
    ikmem_free(username);
    ikmem_free(password);
    return stream;
}


//---------------------------------------------------------------------
// query bound address - retrieve the proxy-assigned bind address
//---------------------------------------------------------------------

// Get the bound address assigned by the proxy server during handshake.
// For SOCKS5, this is the BND.ADDR/BND.PORT from the CONNECT reply.
// For SOCKS4, this is the IP/PORT from the reply.
// Returns 0 on success, -1 if no bound address is available.
// On success, addr and addrlen are filled with the sockaddr.
static int async_proxy_query_bind_addr(CAsyncStream *stream,
    struct sockaddr *addr, int *addrlen)
{
    CAsyncProxy *proxy = async_stream_upcast(stream, CAsyncProxy, stream);
    if (proxy == NULL || addr == NULL || addrlen == NULL) {
        return -1;
    }
    if (proxy->bind_type == 1) {
        // IPv4 bound address
        struct sockaddr_in *sin = (struct sockaddr_in*)addr;
        if (*addrlen < (int)sizeof(struct sockaddr_in)) {
            return -1;
        }
        memset(sin, 0, sizeof(*sin));
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr, proxy->bind_ipv4, 4);
        sin->sin_port = htons((unsigned short)proxy->bind_port);
        *addrlen = (int)sizeof(struct sockaddr_in);
        return 0;
    }
    if (proxy->bind_type == 4) {
        // IPv6 bound address
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)addr;
        if (*addrlen < (int)sizeof(struct sockaddr_in6)) {
            return -1;
        }
        memset(sin6, 0, sizeof(*sin6));
        sin6->sin6_family = AF_INET6;
        memcpy(&sin6->sin6_addr, proxy->bind_ipv6, 16);
        sin6->sin6_port = htons((unsigned short)proxy->bind_port);
        *addrlen = (int)sizeof(struct sockaddr_in6);
        return 0;
    }
    return -1;
}


//---------------------------------------------------------------------
// public interface - async_stream_proxy_bind_addr
//---------------------------------------------------------------------

int async_stream_proxy_bind_addr(CAsyncStream *stream,
    struct sockaddr *addr, int *addrlen)
{
    if (stream == NULL || stream->name != ASYNC_STREAM_NAME_PROXY) {
        return -1;
    }
    return async_proxy_query_bind_addr(stream, addr, addrlen);
}
