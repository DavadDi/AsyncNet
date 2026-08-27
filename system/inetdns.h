//=====================================================================
//
// inetdns.h - Async DNS resolver for CAsyncLoop
//
// Created by skywind on 2026/04/24
// Last Modified: 2026/04/24
//
//=====================================================================
#ifndef _INETDNS_H_
#define _INETDNS_H_

#include "inetkit.h"

// Threading contract: every API in this header must be called from the
// thread that runs the owning CAsyncLoop. There is no internal locking.
//
// Anti-spoofing threat model: replies are accepted only when they match
// (1) the source address of the queried nameserver, (2) the 16-bit
// random transaction id and (3) the 0x20 case-randomized question echo.
// The id/0x20 bits come from a non-cryptographic xorshift32 PRNG. The
// UDP source port is kernel-assigned when the per-family socket is
// created (bind with port 0) and then never changes for the socket's
// lifetime -- a deliberate design choice and a KNOWN LIMITATION:
// per-query source port rotation (RFC 5452) is not implemented, so an
// observer who learns the port once reduces the remaining entropy to
// the id/0x20 bits. This defends against off-path blind spoofing but
// NOT against an attacker who can observe queries (on-path) or against
// a malicious/compromised recursive server. Answer-section owner names
// are not yet validated against the query name (roadmap, together with
// CNAME chain following); there is no downgrade-retry for servers that
// reject EDNS0 or normalize the 0x20 case pattern.

#ifdef __cplusplus
extern "C" {
#endif


//---------------------------------------------------------------------
// DNS protocol constants
//---------------------------------------------------------------------

#define IDNS_TYPE_A       1
#define IDNS_TYPE_NS      2
#define IDNS_TYPE_CNAME   5
#define IDNS_TYPE_SOA     6
#define IDNS_TYPE_PTR     12
#define IDNS_TYPE_MX      15
#define IDNS_TYPE_TXT     16
#define IDNS_TYPE_AAAA    28

#define IDNS_CLASS_INET   1

#define IDNS_FLAG_QR      0x8000U
#define IDNS_FLAG_AA      0x0400U
#define IDNS_FLAG_TC      0x0200U
#define IDNS_FLAG_RD      0x0100U
#define IDNS_FLAG_RA      0x0080U
#define IDNS_FLAG_RCODE   0x000FU


//---------------------------------------------------------------------
// DNS error codes
//---------------------------------------------------------------------

#define IDNS_ERR_NONE         0
#define IDNS_ERR_FORMAT       1
#define IDNS_ERR_SERVERFAILED 2
#define IDNS_ERR_NOTEXIST     3
#define IDNS_ERR_NOTIMPL      4
#define IDNS_ERR_REFUSED      5
#define IDNS_ERR_TRUNCATED    65
#define IDNS_ERR_UNKNOWN      66
#define IDNS_ERR_TIMEOUT      67
#define IDNS_ERR_SHUTDOWN     68
#define IDNS_ERR_CANCEL       69
#define IDNS_ERR_NODATA       70
#define IDNS_ERR_NOSERVER     71   // queued request expired with no nameserver configured


//---------------------------------------------------------------------
// LOG channel
//---------------------------------------------------------------------
#define ASYNC_LOOP_LOG_DNS ASYNC_LOOP_LOG_NEXT(1)


//---------------------------------------------------------------------
// DNS query/config flags
//---------------------------------------------------------------------

#define IDNS_QUERY_NO_SEARCH  0x01

#define IDNS_OPTION_SEARCH         0x01
#define IDNS_OPTION_NAMESERVERS    0x02
#define IDNS_OPTION_MISC           0x04
#define IDNS_OPTION_HOSTSFILE      0x08
#define IDNS_OPTIONS_ALL           (IDNS_OPTION_SEARCH | IDNS_OPTION_NAMESERVERS | IDNS_OPTION_MISC | IDNS_OPTION_HOSTSFILE)

// opt-in: when the system yields no nameserver at all, fall back to
// public DNS (8.8.8.8/8.8.4.4). Routes queries to a third party, so it
// is NOT part of IDNS_OPTIONS_ALL and defaults to off; passing this
// flag to async_dns_new is the supported way to enable it (it takes
// effect before the config load, unlike set_option afterwards)
#define IDNS_OPTION_PUBLIC_FALLBACK 0x10

#define IDNS_BUFFER_SIZE    1500
#define IDNS_MAX_ADDRS_V4   32
#define IDNS_MAX_ADDRS_V6   32

#define IDNS_TTL_LIMIT      86400    // positive cache TTL cap (seconds)
#define IDNS_NEG_TTL_LIMIT  3600     // negative cache TTL cap (seconds)
#define IDNS_CACHE_LIMIT    4096     // default max cache entries
#define IDNS_EDNS_PAYLOAD   1232     // EDNS0 advertised UDP payload size:
                                     // the DNS Flag Day 2020 value, safe
                                     // against IPv6 fragmentation (larger
                                     // replies get TC even though the
                                     // receive buffer could hold 1500)
#define IDNS_PROBE_SLOTS    8        // max concurrent health probes
#define IDNS_WAITING_LIMIT  4096     // default waiting-queue admission cap

// request states
#define IDNS_STATE_QUERY    0    // in-flight or waiting network query
#define IDNS_STATE_PENDING  1    // hosts/cache hit queued for deferred dispatch


//---------------------------------------------------------------------
// Forward declarations
//---------------------------------------------------------------------

struct CAsyncDNS;
struct CAsyncDnsServer;
struct CAsyncDnsRequest;
struct CAsyncDnsCacheEntry;

typedef struct CAsyncDNS CAsyncDNS;
typedef struct CAsyncDnsServer CAsyncDnsServer;
typedef struct CAsyncDnsRequest CAsyncDnsRequest;
typedef struct CAsyncDnsCacheEntry CAsyncDnsCacheEntry;


//---------------------------------------------------------------------
// Callback type
//---------------------------------------------------------------------

typedef void (*async_dns_callback)(CAsyncDNS *dns, int result, int type,
    int count, IUINT32 ttl, void *addresses, void *user);


//---------------------------------------------------------------------
// CAsyncDnsServer - DNS nameserver
//---------------------------------------------------------------------

struct CAsyncDnsServer {
    struct sockaddr_storage address;
    int addrlen;
    int state;                      // 0: down, 1: up
    int failed_times;               // consecutive sendto failures (marks the
                                    // server down at max_timeout_count, e.g.
                                    // an IPv6 server without an IPv6 route;
                                    // cleared by a successful send or any
                                    // response from the server)
    int timedout;                   // consecutive timeout counter
    int requests_inflight;          // inflight requests on this server
    IUINT32 probe_delay;            // current probe interval (ms), exponential backoff
    CAsyncTimer probe_timer;        // health probe timer
    CAsyncDnsServer *next;          // circular linked list
    CAsyncDnsServer *prev;
    CAsyncDNS *dns;                 // owning CAsyncDNS
};


//---------------------------------------------------------------------
// CAsyncDnsRequest - DNS request (internal transaction)
//---------------------------------------------------------------------

struct CAsyncDnsRequest {
    IUINT16 trans_id;               // transaction ID
    IUINT8 request_type;            // IDNS_TYPE_A / IDNS_TYPE_AAAA / IDNS_TYPE_PTR
    IUINT8 *request_data;           // built DNS query packet (ikmem_malloc'd)
    IUINT32 request_len;            // packet length
    int state;                      // IDNS_STATE_QUERY / IDNS_STATE_PENDING
    int retries;                    // retry count (server timeouts only)
    int send_failed;                // last arm was a fast retry after sendto failed
    int send_fails;                 // consecutive local send failures
    int resubmitted;                // callback took ownership (search chaining)
    int search_nodata;              // some search candidate answered NODATA

    CAsyncDnsServer *ns;            // target nameserver

    async_dns_callback callback;        // user callback
    void *user;                     // user pointer

    CAsyncTimer timeout_timer;      // request timeout timer

    CAsyncDNS *dns;                 // owning CAsyncDNS
    CAsyncDnsRequest *next;         // linked list (waiting queue)
    CAsyncDnsRequest *prev;

    // search domain state
    char *search_name;              // base short name (allocated copy)
    int search_index;               // current candidate index
    int search_count;               // total number of candidates
    int search_mode;                // 0=original first, 1=search domains first
    int search_flags;               // original query flags
    async_dns_callback search_callback; // user's original callback
    void *search_user;              // user's original user data

    // deferred hit result (state == IDNS_STATE_PENDING)
    int pending_result;             // IDNS_ERR_* to dispatch
    int pending_count;              // address count (0 = negative result)
    IUINT32 pending_ttl;            // remaining TTL in seconds
    union {
        IUINT32 v4[IDNS_MAX_ADDRS_V4];      // A record addresses
        IUINT8 v6[IDNS_MAX_ADDRS_V6][16];   // AAAA record addresses
        char ptr[256];                      // PTR hostname
    } pending_data;                 // inline copy of the hit result
};


//---------------------------------------------------------------------
// CAsyncDnsCacheEntry - DNS cache entry
//---------------------------------------------------------------------

struct CAsyncDnsCacheEntry {
    IUINT8 type;                    // IDNS_TYPE_A / IDNS_TYPE_AAAA / IDNS_TYPE_PTR
    IUINT32 ttl;                    // original TTL in seconds (diagnostics/logs
                                    // only; expiry is driven by expire_time)
    IUINT32 expire_time;            // expiry time (loop->current + ttl*1000)
    IUINT32 last_hit;               // last access time (loop->current, ms)
    IUINT32 count;                  // address count (0 = negative cache entry)
    IUINT32 result;                 // error code for negative cache (IDNS_ERR_NOTEXIST / IDNS_ERR_NODATA)
    void *addresses;                // address data (ikmem_malloc'd, NULL if negative)
};


//---------------------------------------------------------------------
// CAsyncDNS - Async DNS resolver
//---------------------------------------------------------------------

struct CAsyncDNS {
    CAsyncLoop *loop;               // associated event loop

    // nameserver management
    CAsyncDnsServer *server_head;   // circular linked list head
    int num_servers;                // total nameserver count
    int num_good_servers;           // healthy nameserver count
    CAsyncDnsServer *server_current; // last used server (round-robin)

    // request management
    struct ib_hash_map req_hash;    // trans_id (uint key) -> CAsyncDnsRequest*
    CAsyncDnsRequest *req_waiting;  // waiting queue head (doubly-linked)
    CAsyncDnsRequest *req_waiting_tail; // waiting queue tail (FIFO)
    int num_inflight;               // inflight request count
    int num_waiting;                // waiting queue count
    int max_inflight;               // max concurrent requests (default 64)
    int max_waiting;                // admission gate for outstanding work
                                    // (default IDNS_WAITING_LIMIT): new
                                    // resolves are rejected (NULL) when the
                                    // waiting queue -- or the deferred-hit
                                    // pending queue -- reaches this size.
                                    // A gate, not a hard cap: parked
                                    // retries/resubmissions bypass it, so
                                    // num_waiting may briefly exceed it by
                                    // up to max_inflight

    // UDP I/O
    CAsyncUdp *udp;                 // IPv4 UDP socket (user -> dns)
    CAsyncUdp *udp6;                // IPv6 UDP socket (user -> dns)
    IUINT32 rng_state;              // xorshift32 state (trans_id / 0x20)

    // config
    IUINT32 timeout_ms;             // request timeout (default 5000ms)
    int max_retries;                // max retry count (default 3)
    int max_timeout_count;          // consecutive timeouts to mark server down (default 3)
    int randomize_case;             // 0x20 case randomization (default 1)
    int public_fallback;            // allow built-in public DNS fallback
                                    // (default 0: never send queries to
                                    // 8.8.8.8 unless explicitly enabled by
                                    // IDNS_OPTION_PUBLIC_FALLBACK or option)
    int rotate;                     // 1 = round-robin across servers,
                                    // 0 = stick to the first healthy one
                                    // (default 0, matching glibc/c-ares)

    // hosts cache
    struct ib_hash_map hosts_v4;    // hostname (cstr key) -> hosts value
    struct ib_hash_map hosts_v6;    // hostname (cstr key) -> hosts value

    // DNS result cache
    struct ib_hash_map cache;       // "name:type" (cstr key) -> CAsyncDnsCacheEntry*
    int max_cache;                  // max cache entries (default IDNS_CACHE_LIMIT)

    // health probe tracking
    IUINT16 probe_ids[IDNS_PROBE_SLOTS];    // probe transaction IDs
    CAsyncDnsServer *probe_server[IDNS_PROBE_SLOTS]; // probe target servers
    int probe_count;                // active probe count

    // search domains
    char **search_domains;          // array of allocated domain strings
    int search_count;               // number of search domains
    int search_capacity;            // allocated capacity
    int search_ndots;               // ndots threshold (default 1)

    // deferred hit dispatch (hosts/cache hits)
    CAsyncDnsRequest *pending_head; // pending hit queue head (FIFO)
    CAsyncDnsRequest *pending_tail; // pending hit queue tail
    int num_pending;                // pending hit count
    CAsyncPostpone pending_post;    // end-of-iteration dispatcher
    CAsyncTimer pending_timer;      // overflow continuation (anti-spin)

    // state flags
    int suspended;                  // set after clear_nameservers
    int shutting_down;              // set during async_dns_delete
    int busy;                       // callback dispatch ref count
    int pending_delete;             // deferred delete requested while busy
    int pending_fail_requests;      // fail_requests arg for deferred delete
    int deleting;                   // actual destruction in progress (re-entry guard)
};


//---------------------------------------------------------------------
// Lifecycle
//---------------------------------------------------------------------

// Create CAsyncDNS. flags: IDNS_OPTIONS_ALL etc.
// Automatically loads system config based on flags.
CAsyncDNS *async_dns_new(CAsyncLoop *loop, int flags);

// Destroy CAsyncDNS. fail_requests: non-zero -> outstanding requests
// receive a final IDNS_ERR_SHUTDOWN callback; zero -> their callbacks
// are silently dropped (never invoked).
void async_dns_delete(CAsyncDNS *dns, int fail_requests);


//---------------------------------------------------------------------
// Nameserver configuration
//---------------------------------------------------------------------

// Add nameserver by IP string (supports "8.8.8.8", "8.8.8.8:53", IPv6)
int async_dns_nameserver_add(CAsyncDNS *dns, const char *ip);

// Get nameserver count
int async_dns_count_nameservers(const CAsyncDNS *dns);

// Clear all nameservers and suspend pending requests
int async_dns_clear_nameservers(CAsyncDNS *dns);

// Resume after clear_nameservers
int async_dns_resume(CAsyncDNS *dns);


//---------------------------------------------------------------------
// Search domains
//---------------------------------------------------------------------

// Add a search domain. Duplicates are ignored.
int async_dns_search_add(CAsyncDNS *dns, const char *domain);

// Clear all search domains.
int async_dns_search_clear(CAsyncDNS *dns);

// Get number of search domains.
int async_dns_search_count(const CAsyncDNS *dns);

// Get search domain at index (0-based). Returns NULL if out of range.
const char *async_dns_search_get(const CAsyncDNS *dns, int index);

// Set ndots threshold (default 1). Names with fewer dots than ndots
// will be tried with search domains first.
int async_dns_search_set_ndots(CAsyncDNS *dns, int ndots);

// Get current ndots threshold.
int async_dns_search_get_ndots(const CAsyncDNS *dns);


//---------------------------------------------------------------------
// DNS queries
//---------------------------------------------------------------------

// Resolve A record (IPv4). Returns request handle, or NULL on error
// (invalid args, a malformed/oversized hostname -- beyond the 255-byte
// protocol limit -- shutting down, out of memory, or the waiting/
// pending queue is full -- backpressure): NULL means the callback will
// never fire. The callback is never invoked from inside this call:
// hosts/cache hits are dispatched at the end of the current loop
// iteration (CAsyncPostpone); results queued from within a callback are
// deferred to the next iteration (no same-iteration spin).
// LOOKUP ORDER: a hosts/cache entry for the LITERAL name always wins
// over the whole search ladder (deliberate deviation from the strict
// glibc per-candidate order: a short name put into hosts takes effect
// immediately); only when the literal name misses does the ladder
// consult hosts -> cache -> network per candidate.
// HANDLE LIFETIME: the handle is valid only until its callback fires;
// the request is freed right after the callback returns. Do not store
// the handle past the callback, and never cancel a completed request
// (use-after-free). Hosts hits report a fixed ttl of 3600 (hosts
// entries are static); cache hits report the remaining TTL.
// addresses in callback: IUINT32 array, ephemeral (copy immediately).
CAsyncDnsRequest *async_dns_resolve_ipv4(CAsyncDNS *dns, const char *name,
    int flags, async_dns_callback callback, void *user);

// Resolve AAAA record (IPv6). addresses: 16-byte array, ephemeral.
// Same deferred-callback contract as async_dns_resolve_ipv4.
CAsyncDnsRequest *async_dns_resolve_ipv6(CAsyncDNS *dns, const char *name,
    int flags, async_dns_callback callback, void *user);

// Reverse resolve IPv4. addresses: char* hostname string, ephemeral.
CAsyncDnsRequest *async_dns_resolve_reverse(CAsyncDNS *dns,
    const struct in_addr *addr, int flags,
    async_dns_callback callback, void *user);

// Reverse resolve IPv6. addresses: char* hostname string, ephemeral.
CAsyncDnsRequest *async_dns_resolve_reverse_ipv6(CAsyncDNS *dns,
    const struct in6_addr *addr, int flags,
    async_dns_callback callback, void *user);

// Cancel a pending request (network query or a queued hosts/cache hit
// awaiting deferred dispatch). Callback receives IDNS_ERR_CANCEL.
// Only valid for requests whose callback has NOT fired yet: the handle
// is freed when the callback fires, cancelling it afterwards is
// use-after-free (see the handle lifetime note above).
void async_dns_cancel_request(CAsyncDNS *dns, CAsyncDnsRequest *req);


//---------------------------------------------------------------------
// Configuration options
//---------------------------------------------------------------------

// Set option. Supported options (value is a decimal string):
//   timeout         - request timeout in SECONDS (clamped to 1..600)
//   max-timeouts    - consecutive timeouts to mark a server down
//   max-inflight    - max concurrent network queries
//   max-waiting     - waiting-queue admission cap (>= 16)
//   attempts        - max retries per request (1..10)
//   randomize-case  - 0x20 case randomization on/off (1/0)
//   max-cache       - max DNS cache entries (>= 16)
//   ndots           - search domain ndots threshold (0..64)
//   rotate          - round-robin nameservers (1) or stick to the
//                     first healthy one (0, default)
//   public-fallback - allow the built-in 8.8.8.8/8.8.4.4 fallback when
//                     the system config yields no nameserver (default
//                     0). Prefer the IDNS_OPTION_PUBLIC_FALLBACK flag
//                     to async_dns_new: it takes effect before the
//                     initial config load, so it works together with
//                     IDNS_OPTION_NAMESERVERS/IDNS_OPTIONS_ALL. The
//                     option form only affects later calls to
//                     async_dns_config_windows_nameservers (on POSIX
//                     the fallback runs inside async_dns_new only,
//                     so the flag is the sole way to enable it there).
int async_dns_set_option(CAsyncDNS *dns, const char *option, const char *value);


//---------------------------------------------------------------------
// Configuration loading
//---------------------------------------------------------------------

// Parse resolv.conf (Linux/macOS). filename: NULL -> /etc/resolv.conf
int async_dns_resolv_conf_parse(CAsyncDNS *dns, int flags, const char *filename);

// Load hosts file. filename: NULL -> system default hosts file
int async_dns_load_hosts(CAsyncDNS *dns, const char *filename);

// Parse a single hosts line: "192.168.1.1  host1 host2"
int async_dns_hosts_add_line(CAsyncDNS *dns, const char *line);

// Add custom hosts mapping: hostname -> IPv4 address
int async_dns_hosts_add_ipv4(CAsyncDNS *dns, const char *hostname,
    const struct in_addr *addr);

// Add custom hosts mapping: hostname -> IPv6 address
int async_dns_hosts_add_ipv6(CAsyncDNS *dns, const char *hostname,
    const struct in6_addr *addr);

// Remove a specific IPv4 mapping from hosts cache.
// Returns 0 if the pair was found and removed, -1 if not found or on error.
int async_dns_hosts_remove_ipv4(CAsyncDNS *dns, const char *hostname,
    const struct in_addr *addr);

// Remove a specific IPv6 mapping from hosts cache.
// Returns 0 if the pair was found and removed, -1 if not found or on error.
int async_dns_hosts_remove_ipv6(CAsyncDNS *dns, const char *hostname,
    const struct in6_addr *addr);

// Clear all hosts cache (file-loaded and custom)
void async_dns_hosts_clear(CAsyncDNS *dns);

// Windows: load nameservers from the registry (Tcpip/Tcpip6 Parameters
// and per-interface keys). When nothing is found it only logs by
// default; the 8.8.8.8/8.8.4.4 fallback must be opted in via the
// IDNS_OPTION_PUBLIC_FALLBACK flag or option "public-fallback".
int async_dns_config_windows_nameservers(CAsyncDNS *dns);

// Windows: load DNS search suffixes from system config
int async_dns_config_windows_search(CAsyncDNS *dns);


//---------------------------------------------------------------------
// DNS cache
//---------------------------------------------------------------------

// Flush all DNS cache entries
void async_dns_cache_flush(CAsyncDNS *dns);

// Remove cache entry for specific name and type
void async_dns_cache_remove(CAsyncDNS *dns, const char *name, int type);


//---------------------------------------------------------------------
// Utility
//---------------------------------------------------------------------

// Convert DNS error code to human-readable string
const char *async_dns_err_to_string(int err);


//---------------------------------------------------------------------
// Test-internal API (compiled when IDNS_TEST_INTERNAL is defined)
//---------------------------------------------------------------------

#ifdef IDNS_TEST_INTERNAL

/* expose internal functions for unit testing */
int dns_test_name_encode(const char *name, int name_len,
    IUINT8 *buf, int bufsize, int randomize);
int dns_test_name_decode(const IUINT8 *packet, int length,
    int *idx, char *name_out, int name_out_len);
int dns_test_request_build(IUINT16 trans_id, IUINT16 qtype,
    const char *name, int name_len, int randomize,
    IUINT8 *buf, int bufsize);
CAsyncDnsServer *dns_test_server_pick(CAsyncDNS *dns);

#endif


#ifdef __cplusplus
}
#endif

#endif /* _INETDNS_H_ */
