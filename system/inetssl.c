//=====================================================================
//
// inetssl.c - SSL/TLS stream filter for CAsyncStream
//
// Created by skywind on 2026/04/21
// Last Modified: 2026/04/23
//
//=====================================================================
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "imemdata.h"
#include "inetbase.h"
#include "inetevt.h"
#include "inetkit.h"
#include "inetssl.h"

// Real implementation requires OpenSSL, enabled by defining IHAVE_OPENSSL.
// Without it, this file compiles into stubs (see the bottom of this file)
// so the whole library builds fine in environments lacking OpenSSL.
#ifdef IHAVE_OPENSSL

#ifdef _WIN32
#ifndef _WINSOCKAPI_
#include <winsock2.h>
#endif
#include <ws2tcpip.h>
#ifndef IHAVE_NOT_WINCRYPT
#include <wincrypt.h>
#endif
#else
#include <arpa/inet.h>
#include <sys/stat.h>
#endif

#include <stdlib.h>

#if defined(__APPLE__) && defined(IHAVE_SECURITY_FRAMEWORK)
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#endif

/* OpenSSL headers */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>


//=====================================================================
// Custom BIO for CAsyncStream (Filter Mode)
//=====================================================================

/* BIO type number - use BIO_get_new_index() when available (1.1.0+) */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
static int bio_type_async_stream_idx = -1;
#define BIO_TYPE_ASYNC_STREAM_INIT() \
	bio_type_async_stream_idx = BIO_get_new_index()
#define BIO_TYPE_ASYNC_STREAM_VAL() \
	(bio_type_async_stream_idx >= 0 ? bio_type_async_stream_idx : 128)
#else
#define BIO_TYPE_ASYNC_STREAM_INIT()  ((void)0)
#define BIO_TYPE_ASYNC_STREAM_VAL()   128
#endif

/* Method table - allocated once and shared across all BIO instances */
static BIO_METHOD *bio_method_async_stream = NULL;
static int ssl_init_control = 0;

static void ssl_init_once(void);
static void ssl_cleanup(void);


//---------------------------------------------------------------------
// bio_stream_read: SSL needs ciphertext, read from underlying stream
//---------------------------------------------------------------------
static int bio_stream_read(BIO *b, char *out, int outlen)
{
	CAsyncStream *underlying;
	long hr;

	BIO_clear_retry_flags(b);
	underlying = (CAsyncStream*)BIO_get_data(b);

	if (out == NULL || outlen <= 0 || underlying == NULL) {
		return 0;
	}

	hr = _async_stream_read(underlying, out, outlen);

	if (hr < 0) {
		/* real I/O error - do not set retry, OpenSSL should treat as fatal */
		return -1;
	}
	if (hr == 0) {
		if (underlying->eof & ASYNC_STREAM_INPUT) {
			/* EOF: no more data, tell OpenSSL the stream ended */
			return 0;
		}
		/* would-block: data not available yet, ask OpenSSL to retry later */
		BIO_set_retry_read(b);
		return -1;
	}

	return (int)hr;
}


//---------------------------------------------------------------------
// bio_stream_write: SSL outputs ciphertext, write to underlying stream
//---------------------------------------------------------------------
static int bio_stream_write(BIO *b, const char *in, int inlen)
{
	CAsyncStream *underlying;
	long hr;

	BIO_clear_retry_flags(b);
	underlying = (CAsyncStream*)BIO_get_data(b);

	if (in == NULL || inlen <= 0 || underlying == NULL) {
		return 0;
	}

	hr = _async_stream_write(underlying, in, inlen);

	if (hr < 0) {
		/* real I/O error */
		return -1;
	}
	if (hr == 0) {
		if (underlying->eof & ASYNC_STREAM_OUTPUT) {
			/* EOF: write side closed */
			return 0;
		}
		/* would-block: buffer full, retry later */
		BIO_set_retry_write(b);
		return -1;
	}

	return (int)hr;
}


//---------------------------------------------------------------------
// bio_stream_puts: implemented via write
//---------------------------------------------------------------------
static int bio_stream_puts(BIO *b, const char *str)
{
	if (str == NULL) return 0;
	return bio_stream_write(b, str, (int)strlen(str));
}


//---------------------------------------------------------------------
// bio_stream_ctrl: query buffer state
//---------------------------------------------------------------------
static long bio_stream_ctrl(BIO *b, int cmd, long num, void *ptr_unused)
{
	CAsyncStream *underlying;
	(void)ptr_unused;

	underlying = (CAsyncStream*)BIO_get_data(b);

	switch (cmd) {
	case BIO_CTRL_PENDING:
		if (underlying && underlying->remain) {
			/* return actual byte count, not boolean */
			return (long)_async_stream_remain(underlying);
		}
		return 0;
	case BIO_CTRL_WPENDING:
		if (underlying && underlying->pending) {
			/* return actual byte count, not boolean */
			return (long)_async_stream_pending(underlying);
		}
		return 0;
	case BIO_CTRL_GET_CLOSE:
		return BIO_get_shutdown(b);
	case BIO_CTRL_SET_CLOSE:
		BIO_set_shutdown(b, (int)num);
		return 1;
	case BIO_CTRL_DUP:
		return 1;
	case BIO_CTRL_FLUSH:
		return 1;
	default:
		return 0;
	}
}


//---------------------------------------------------------------------
// bio_stream_create: BIO initialization callback
//---------------------------------------------------------------------
static int bio_stream_create(BIO *b)
{
	BIO_set_shutdown(b, 0);
	BIO_set_init(b, 1);
	BIO_set_data(b, NULL);
	return 1;
}


//---------------------------------------------------------------------
// bio_stream_destroy: BIO cleanup callback
//---------------------------------------------------------------------
static int bio_stream_destroy(BIO *b)
{
	if (b == NULL) return 0;
	BIO_set_data(b, NULL);
	BIO_set_init(b, 0);
	return 1;
}


//---------------------------------------------------------------------
// Create the shared BIO_METHOD table for our custom BIO type
//---------------------------------------------------------------------
static BIO_METHOD *bio_method_async_stream_new(void)
{
	BIO_METHOD *method;
	int bio_type;

	BIO_TYPE_ASYNC_STREAM_INIT();
	bio_type = BIO_TYPE_ASYNC_STREAM_VAL();

	method = BIO_meth_new(bio_type, "async_stream");
	if (method == NULL) return NULL;

	BIO_meth_set_write(method, bio_stream_write);
	BIO_meth_set_read(method, bio_stream_read);
	BIO_meth_set_puts(method, bio_stream_puts);
	BIO_meth_set_ctrl(method, bio_stream_ctrl);
	BIO_meth_set_create(method, bio_stream_create);
	BIO_meth_set_destroy(method, bio_stream_destroy);

	return method;
}


//---------------------------------------------------------------------
// Create a BIO wrapping a CAsyncStream (for filter mode)
//---------------------------------------------------------------------
static BIO *bio_new_async_stream(CAsyncStream *underlying)
{
	BIO *b;

	assert(bio_method_async_stream != NULL);

	b = BIO_new(bio_method_async_stream);
	if (b == NULL) return NULL;

	BIO_set_data(b, underlying);
	BIO_set_init(b, 1);
	BIO_set_shutdown(b, 0);

	return b;
}


//=====================================================================
// CAsyncSSL - Internal helpers
//=====================================================================
static void async_ssl_close(CAsyncStream *stream);
static void async_ssl_destroy(CAsyncSSL *ssl_obj);
static long async_ssl_read(CAsyncStream *stream, void *ptr, long size);
static long async_ssl_write(CAsyncStream *stream, const void *ptr, long size);
static long async_ssl_peek(CAsyncStream *stream, void *ptr, long size);
static void async_ssl_enable(CAsyncStream *stream, int event);
static void async_ssl_disable(CAsyncStream *stream, int event);
static long async_ssl_remain(const CAsyncStream *stream);
static long async_ssl_pending(const CAsyncStream *stream);
static void async_ssl_watermark(CAsyncStream *stream, long high, long low);
static long async_ssl_option(CAsyncStream *stream, int option, long value);

static void async_ssl_underlying_event(CAsyncStream *underlying,
		int event, int args);
static void async_ssl_postpone(CAsyncLoop *loop, CAsyncPostpone *postpone);
static int async_ssl_dispatch(CAsyncSSL *ssl_obj, int event, int args);
static void async_ssl_notify(CAsyncSSL *ssl_obj, int event, int args);

static void async_ssl_apply_client_config(CAsyncSSL *ssl_obj, SSL *ssl_ptr);
static int async_ssl_do_handshake(CAsyncSSL *ssl_obj);
static void async_ssl_consider_reading(CAsyncSSL *ssl_obj);
static void async_ssl_consider_writing(CAsyncSSL *ssl_obj);

static void async_ssl_put_error(CAsyncSSL *ssl_obj, unsigned long err);
static void async_ssl_conn_closed(CAsyncSSL *ssl_obj, int errcode);
static void async_ssl_enter_dead(CAsyncSSL *ssl_obj);
static void async_ssl_filter_new_cleanup(CAsyncSSL *ssl_obj,
		int bio_owned, BIO *bio);

static int async_ssl_do_shutdown(CAsyncSSL *ssl_obj);


//---------------------------------------------------------------------
// Helper: upcast CAsyncStream* to CAsyncSSL*
//---------------------------------------------------------------------
#define SSL_UPCAST(stream) \
	((CAsyncSSL*)async_stream_upcast(stream, CAsyncSSL, stream))

#define SSL_PRIVATE(stream) \
	((CAsyncSSL*)async_stream_private(stream, CAsyncSSL))


//---------------------------------------------------------------------
// Save OpenSSL error
//---------------------------------------------------------------------
static void async_ssl_put_error(CAsyncSSL *ssl_obj, unsigned long err)
{
	if (err == 0) return;
	if (ssl_obj->n_errors < 3) {
		ssl_obj->errors[ssl_obj->n_errors] = err;
		ssl_obj->n_errors++;
	}
}


//---------------------------------------------------------------------
// Dispatch event to user callback
// busy is a reference count: nested dispatch calls increment it,
// so destroy only happens when the outermost caller unwinds and
// busy reaches 0 with closing set.
// Returns:  1 = ssl_obj destroyed (caller must not touch it)
//          -1 = closing set but still alive (caller should stop)
//           0 = normal, still alive
//---------------------------------------------------------------------
static int async_ssl_dispatch(CAsyncSSL *ssl_obj, int event, int args)
{
	CAsyncStream *stream = &ssl_obj->stream;
	CAsyncLoop *loop = stream->loop;
	if (loop && (loop->logmask & ASYNC_LOOP_LOG_SSL)) {
		char name[5];
		async_stream_name(stream, name);
		async_loop_log(loop, ASYNC_LOOP_LOG_SSL,
			"[ssl] %s dispatch event=0x%x args=%d",
			name, event, args);
	}
	ssl_obj->busy++;
	if (stream->callback) {
		stream->callback(stream, event, args);
	}
	ssl_obj->busy--;
	if (ssl_obj->closing && ssl_obj->busy == 0) {
		async_ssl_destroy(ssl_obj);
		return 1;
	}
	return ssl_obj->closing ? -1 : 0;
}


//---------------------------------------------------------------------
// Notify via postpone queue (deferred event delivery)
//---------------------------------------------------------------------
static void async_ssl_notify(CAsyncSSL *ssl_obj, int event, int args)
{
	CAsyncStream *stream = &ssl_obj->stream;
	char notify[8];
	iencode32i_lsb(notify + 0, event);
	iencode32i_lsb(notify + 4, args);
	ims_write(&ssl_obj->notify, notify, 8);
	if (async_post_is_active(&ssl_obj->evt_post) == 0) {
		async_post_start(stream->loop, &ssl_obj->evt_post);
	}
}


//---------------------------------------------------------------------
// Postpone callback: process pending notifications
//---------------------------------------------------------------------
static void async_ssl_postpone(CAsyncLoop *loop_unused, CAsyncPostpone *postpone)
{
	(void)loop_unused;
	CAsyncStream *stream = (CAsyncStream*)postpone->user;
	CAsyncSSL *ssl_obj = SSL_UPCAST(stream);
	char notify[8];

	ssl_obj->busy++;

	while ((long)ssl_obj->notify.size >= 8) {
		IINT32 event, args;
		ims_read(&ssl_obj->notify, notify, 8);
		idecode32i_lsb(notify + 0, &event);
		idecode32i_lsb(notify + 4, &args);
		if (ssl_obj->closing) break;
		if (async_ssl_dispatch(ssl_obj, (int)event, (int)args)) {
			/* destroyed or closing - stop processing */
			break;
		}
	}

	/* graceful shutdown completed and EOF delivered - start closing
	   automatically so fd/SSL are released without requiring a manual
	   async_stream_close(). Owners that hold a pointer to this stream
	   (e.g. a stream using it as its underlying) cannot observe such a
	   self-release and must opt out via OPT_SSL_NO_AUTO_CLOSE. */
	if (ssl_obj->shutdown_complete &&
		ssl_obj->ssl_state == ASYNC_STREAM_SSL_DEAD &&
		!ssl_obj->no_auto_close &&
		!ssl_obj->closing) {
		ssl_obj->closing = 1;
	}

	ssl_obj->busy--;
	if (ssl_obj->closing && ssl_obj->busy == 0) {
		async_ssl_destroy(ssl_obj);
	}
}


//---------------------------------------------------------------------
// Underlying stream event callback (hijacked)
//---------------------------------------------------------------------
static void async_ssl_underlying_event(CAsyncStream *underlying,
		int event, int args)
{
	CAsyncSSL *ssl_obj = (CAsyncSSL*)underlying->user;

	if (ssl_obj == NULL) {
		return;
	}

	if (ssl_obj->closing || ssl_obj->ssl_state == ASYNC_STREAM_SSL_DEAD) {
		return;
	}

	ssl_obj->busy++;

	if (event & ASYNC_STREAM_EVT_ESTAB) {
		/* underlying TCP just connected - start SSL handshake */
		if (ssl_obj->ssl_state != ASYNC_STREAM_SSL_OPEN) {
			async_ssl_do_handshake(ssl_obj);
		}
	}

	if (ssl_obj->closing) goto out;

	if (event & ASYNC_STREAM_EVT_EOF) {
		/* underlying stream EOF */
		if (ssl_obj->ssl_state == ASYNC_STREAM_SSL_OPEN ||
			ssl_obj->ssl_state == ASYNC_STREAM_SSL_SHUTTING) {
			if (ssl_obj->allow_dirty_shutdown) {
				ssl_obj->stream.eof |= ASYNC_STREAM_INPUT;
				async_ssl_enter_dead(ssl_obj);
				async_ssl_notify(ssl_obj,
					ASYNC_STREAM_EVT_EOF, 0);
			} else {
				async_ssl_conn_closed(ssl_obj, SSL_ERROR_SYSCALL);
			}
		} else {
			/* handshake not complete - report error */
			async_ssl_dispatch(ssl_obj, ASYNC_STREAM_EVT_ERROR, -1);
		}
		goto out;
	}

	if (ssl_obj->closing) goto out;

	if (event & ASYNC_STREAM_EVT_ERROR) {
		async_ssl_dispatch(ssl_obj, ASYNC_STREAM_EVT_ERROR, args);
		goto out;
	}

	if (ssl_obj->closing) goto out;

	if (event & ASYNC_STREAM_EVT_READING) {
		if (ssl_obj->ssl_state == ASYNC_STREAM_SSL_OPEN) {
			async_ssl_consider_reading(ssl_obj);
		} else if (ssl_obj->ssl_state == ASYNC_STREAM_SSL_SHUTTING) {
			/* drive shutdown state machine */
			async_ssl_do_shutdown(ssl_obj);
		} else {
			/* handshake in progress */
			async_ssl_do_handshake(ssl_obj);
		}
	}

	if (ssl_obj->closing) goto out;

	if (event & ASYNC_STREAM_EVT_WRITING) {
		if (ssl_obj->ssl_state == ASYNC_STREAM_SSL_OPEN) {
			async_ssl_consider_writing(ssl_obj);
		} else if (ssl_obj->ssl_state == ASYNC_STREAM_SSL_SHUTTING) {
			/* drive shutdown state machine */
			async_ssl_do_shutdown(ssl_obj);
		} else {
			/* handshake in progress */
			async_ssl_do_handshake(ssl_obj);
		}
	}

out:
	ssl_obj->busy--;
	if (ssl_obj->closing && ssl_obj->busy == 0) {
		async_ssl_destroy(ssl_obj);
	}
}


//=====================================================================
// SSL handshake
//=====================================================================

static int async_ssl_do_handshake(CAsyncSSL *ssl_obj)
{
	SSL *ssl = (SSL*)ssl_obj->ssl;
	CAsyncStream *stream = &ssl_obj->stream;
	CAsyncLoop *loop = stream->loop;
	int ret, err;

	/* apply client-side config (SNI, ALPN, hostname verify) before
	   first handshake attempt, so user can set them after filter_new */
	if (ssl_obj->ssl_state == ASYNC_STREAM_SSL_CONNECTING &&
		ssl_obj->config_applied == 0) {
		async_ssl_apply_client_config(ssl_obj, ssl);
		ssl_obj->config_applied = 1;
	}
	ERR_clear_error();
	ret = SSL_do_handshake(ssl);
	err = SSL_get_error(ssl, ret);

	if (ret == 1) {
		/* handshake complete */
		ssl_obj->ssl_state = ASYNC_STREAM_SSL_OPEN;

		/* cache negotiated ALPN protocol */
		{
			const unsigned char *proto;
			unsigned int proto_len;
			SSL_get0_alpn_selected(ssl, &proto, &proto_len);
			if (proto != NULL && proto_len > 0) {
				if (ssl_obj->alpn_selected) {
					ikmem_free(ssl_obj->alpn_selected);
				}
				ssl_obj->alpn_selected = (char*)ikmem_malloc(proto_len + 1);
				if (ssl_obj->alpn_selected) {
					memcpy(ssl_obj->alpn_selected, proto, proto_len);
					ssl_obj->alpn_selected[proto_len] = 0;
				}
			}
		}
		stream->state = ASYNC_STREAM_ESTAB;

		if (loop && (loop->logmask & ASYNC_LOOP_LOG_SSL)) {
			async_loop_log(loop, ASYNC_LOOP_LOG_SSL,
				"[ssl] handshake complete");
		}

		/* apply user's enable/disable preferences */
		if (ssl_obj->user_enabled & ASYNC_EVENT_READ) {
			async_stream_enable(ssl_obj->underlying, ASYNC_EVENT_READ);
		}
		if (ssl_obj->user_enabled & ASYNC_EVENT_WRITE) {
			async_stream_enable(ssl_obj->underlying, ASYNC_EVENT_WRITE);
		}

		/* notify ESTAB before queuing any READING events, so the user
		   sees the connection-ready event before application data */
		async_ssl_notify(ssl_obj, ASYNC_STREAM_EVT_ESTAB, 0);

		if (ssl_obj->closing) return -1;

		/* try to read any data that arrived during handshake */
		async_ssl_consider_reading(ssl_obj);

		if (ssl_obj->closing) return -1;
		return 1;
	}

	if (err == SSL_ERROR_WANT_READ) {
		/* need more data from underlying */
		async_stream_enable(ssl_obj->underlying, ASYNC_EVENT_READ);
		if (ssl_obj->write_blocked_on_read) {
			/* also need to enable write for blocked write ops */
			async_stream_enable(ssl_obj->underlying, ASYNC_EVENT_WRITE);
		}
		return 0;
	}

	if (err == SSL_ERROR_WANT_WRITE) {
		/* need to write more data to underlying */
		async_stream_enable(ssl_obj->underlying, ASYNC_EVENT_WRITE);
		if (ssl_obj->read_blocked_on_write) {
			/* also need to enable read for blocked read ops */
			async_stream_enable(ssl_obj->underlying, ASYNC_EVENT_READ);
		}
		return 0;
	}

	/* handshake failed */
	{
		unsigned long openssl_err = ERR_get_error();
		async_ssl_put_error(ssl_obj, openssl_err);
	}

	if (loop && (loop->logmask & ASYNC_LOOP_LOG_SSL)) {
		async_loop_log(loop, ASYNC_LOOP_LOG_SSL,
			"[ssl] handshake failed: err=%d ret=%d", err, ret);
	}

	async_ssl_dispatch(ssl_obj, ASYNC_STREAM_EVT_ERROR, err);
	return -1;
}


//=====================================================================
// SSL shutdown (close_notify)
//=====================================================================

//---------------------------------------------------------------------
// do_shutdown: drive the SSL_shutdown state machine
// Returns:  1 = shutdown complete (close_notify sent and received)
//           0 = shutdown in progress (need more I/O)
//          -1 = error
//---------------------------------------------------------------------
static int async_ssl_do_shutdown(CAsyncSSL *ssl_obj)
{
	SSL *ssl = (SSL*)ssl_obj->ssl;
	CAsyncStream *stream = &ssl_obj->stream;
	CAsyncLoop *loop = stream->loop;
	int ret, err;

	ERR_clear_error();
	ret = SSL_shutdown(ssl);
	err = SSL_get_error(ssl, ret);

	if (ret == 1) {
		/* shutdown complete: both close_notify sent and received */
		stream->eof |= ASYNC_STREAM_INPUT;
		async_ssl_enter_dead(ssl_obj);
		ssl_obj->shutdown_complete = 1;
		if (loop && (loop->logmask & ASYNC_LOOP_LOG_SSL)) {
			async_loop_log(loop, ASYNC_LOOP_LOG_SSL,
				"[ssl] shutdown complete (close_notify exchanged)");
		}
		async_ssl_notify(ssl_obj, ASYNC_STREAM_EVT_EOF, 0);
		return 1;
	}

	if (ret == 0) {
		/* close_notify sent, waiting for peer's response */
		/* enable both read and write to drive the shutdown */
		async_stream_enable(ssl_obj->underlying, ASYNC_EVENT_READ);
		async_stream_enable(ssl_obj->underlying, ASYNC_EVENT_WRITE);
		return 0;
	}

	/* ret < 0: error or would-block */
	if (err == SSL_ERROR_WANT_READ) {
		async_stream_enable(ssl_obj->underlying, ASYNC_EVENT_READ);
		return 0;
	}
	if (err == SSL_ERROR_WANT_WRITE) {
		async_stream_enable(ssl_obj->underlying, ASYNC_EVENT_WRITE);
		return 0;
	}

	/* fatal error during shutdown - force close */
	if (loop && (loop->logmask & ASYNC_LOOP_LOG_SSL)) {
		async_loop_log(loop, ASYNC_LOOP_LOG_SSL,
			"[ssl] shutdown error: err=%d, forcing close", err);
	}
	ssl_obj->ssl_state = ASYNC_STREAM_SSL_DEAD;
	stream->error = err;
	stream->direction = 0;
	async_ssl_notify(ssl_obj, ASYNC_STREAM_EVT_ERROR, err);
	return -1;
}


//=====================================================================
// Data phase: consider_reading / consider_writing
//=====================================================================

/* operation result flags */
#define OP_MADE_PROGRESS  1
#define OP_BLOCKED        2
#define OP_EOF            4
#define OP_ERROR          8


//---------------------------------------------------------------------
// do_read: call SSL_read and put decrypted data into recvbuf
//---------------------------------------------------------------------
static int async_ssl_do_read(CAsyncSSL *ssl_obj, long max_read)
{
	SSL *ssl = (SSL*)ssl_obj->ssl;
	CAsyncStream *stream = &ssl_obj->stream;
	CAsyncLoop *loop = stream->loop;
	char *buffer;
	long total = 0;
	int result = 0;

	buffer = loop->cache;

	while (max_read > 0) {
		long canread;
		int ret, err;

		if (stream->hiwater > 0) {
			long limit = stream->hiwater - (long)ssl_obj->recvbuf.size;
			if (limit <= 0) {
				/* high watermark reached */
				if (async_stream_remain(ssl_obj->underlying) > 0) {
					/* underlying still has data, but we can't accept more */
					async_stream_disable(ssl_obj->underlying,
						ASYNC_EVENT_READ);
				}
				result |= OP_BLOCKED;
				break;
			}
			canread = (max_read < limit) ? max_read : limit;
		} else {
			canread = max_read;
		}

		if (canread > ASYNC_LOOP_BUFFER_SIZE) {
			canread = ASYNC_LOOP_BUFFER_SIZE;
		}
		if (canread <= 0) break;

		ERR_clear_error();
		ret = SSL_read(ssl, buffer, (int)canread);
		err = SSL_get_error(ssl, ret);

		if (ret > 0) {
			/* successful read */
			ims_write(&ssl_obj->recvbuf, buffer, ret);
			total += ret;
			max_read -= ret;
			result |= OP_MADE_PROGRESS;

			/* check SSL_pending for buffered data */
			if (SSL_pending(ssl) > 0) {
				max_read = (SSL_pending(ssl) > max_read) ?
					SSL_pending(ssl) : max_read;
			}

			if (ret < canread) {
				/* short read, probably no more data right now */
				break;
			}
		}
		else {
			/* error or would-block */
			switch (err) {
			case SSL_ERROR_WANT_READ:
				/* normal: need more ciphertext from underlying */
				break;
			case SSL_ERROR_WANT_WRITE:
				/* renegotiation: read blocked on write */
				if (!ssl_obj->read_blocked_on_write) {
					ssl_obj->read_blocked_on_write = 1;
					ssl_obj->write_blocked_on_read = 0;
					async_stream_enable(ssl_obj->underlying,
						ASYNC_EVENT_WRITE);
				}
				break;
			case SSL_ERROR_ZERO_RETURN:
				/* clean shutdown: peer sent close_notify */
				result |= OP_EOF;
				break;
			case SSL_ERROR_SYSCALL:
				/* system error - check for dirty shutdown */
				if (ret == 0 || (ret == -1 && ERR_peek_error() == 0)) {
					/* dirty shutdown: TCP closed without close_notify */
					result |= OP_EOF;
				} else {
					result |= OP_ERROR;
				}
				break;
			default:
				/* SSL_ERROR_SSL, etc */
				async_ssl_put_error(ssl_obj, ERR_get_error());
				result |= OP_ERROR;
				break;
			}
			result |= OP_BLOCKED;
			break;
		}
	}

	if (total > 0) {
		async_ssl_notify(ssl_obj, ASYNC_STREAM_EVT_READING, total);
	}

	return result;
}


//---------------------------------------------------------------------
// do_write: take data from sendbuf and call SSL_write
//---------------------------------------------------------------------
static int async_ssl_do_write(CAsyncSSL *ssl_obj)
{
	SSL *ssl = (SSL*)ssl_obj->ssl;
	long total = 0;
	int result = 0;

	while (ssl_obj->sendbuf.size > 0) {
		void *ptr = NULL;
		long size;
		int ret, err;
		long to_write;

		size = (long)ims_flat(&ssl_obj->sendbuf, &ptr);
		if (size <= 0) break;

		/* use last_write for retry after WANT_WRITE */
		if (ssl_obj->last_write > 0) {
			to_write = ssl_obj->last_write;
			ssl_obj->last_write = 0;
		} else {
			to_write = size;
		}

		if (to_write > size) {
			to_write = size;
		}

		ERR_clear_error();
		ret = SSL_write(ssl, ptr, (int)to_write);
		err = SSL_get_error(ssl, ret);

		if (ret > 0) {
			ims_drop(&ssl_obj->sendbuf, ret);
			total += ret;
			result |= OP_MADE_PROGRESS;
		}
		else {
			switch (err) {
			case SSL_ERROR_WANT_READ:
				/* renegotiation: write blocked on read */
				if (!ssl_obj->write_blocked_on_read) {
					ssl_obj->write_blocked_on_read = 1;
					ssl_obj->read_blocked_on_write = 0;
					ssl_obj->last_write = to_write;
					async_stream_enable(ssl_obj->underlying,
						ASYNC_EVENT_READ);
				} else {
					ssl_obj->last_write = to_write;
				}
				break;
			case SSL_ERROR_WANT_WRITE:
				/* normal: underlying write buffer full */
				ssl_obj->last_write = to_write;
				break;
			case SSL_ERROR_ZERO_RETURN:
				result |= OP_EOF;
				break;
			case SSL_ERROR_SYSCALL:
				if (ret == 0 || (ret == -1 && ERR_peek_error() == 0)) {
					result |= OP_EOF;
				} else {
					result |= OP_ERROR;
				}
				break;
			default:
				async_ssl_put_error(ssl_obj, ERR_get_error());
				result |= OP_ERROR;
				break;
			}
			result |= OP_BLOCKED;
			break;
		}
	}

	if (total > 0) {
		async_ssl_notify(ssl_obj, ASYNC_STREAM_EVT_WRITING, total);
	}

	/* Do NOT disable the underlying WRITE event here when the SSL sendbuf
	   drains. Two reasons:

	   1) It is redundant. The TCP layer already stops evt_write when its
	      own sendbuf drains (async_tcp_evt_write), so leaving WRITE armed
	      does not cause busy-looping or spurious WRITING events: the poll
	      mask is driven by watcher active state, not stream->enabled.

	   2) Clearing the underlying stream's WRITE-enable flag here is
	      actively harmful: the next async_tcp_write() refuses to start
	      evt_write unless WRITE is enabled, so a subsequent write would
	      strand its ciphertext in the TCP sendbuf. Worse, on the Windows
	      select ipoll backend the ipoll_set() that drops WRITE from the
	      fd's mask races with the fd's READ readiness and can silently
	      stop evt_read from waking on the peer's subsequent data - the
	      response (or the rest of the handshake) then never arrives and
	      the loop stalls until the safety timer. Removing this disable
	      cuts the stall rate roughly in half on Windows. */
	return result;
}


//---------------------------------------------------------------------
// consider_reading: called when underlying has data or write unblocked
//---------------------------------------------------------------------
static void async_ssl_consider_reading(CAsyncSSL *ssl_obj)
{
	/* handle write ops blocked on read (renegotiation) */
	if (ssl_obj->write_blocked_on_read) {
		int r = async_ssl_do_write(ssl_obj);
		if (r & (OP_BLOCKED | OP_ERROR | OP_EOF)) {
			if (r & OP_ERROR) {
				async_ssl_conn_closed(ssl_obj, SSL_ERROR_SSL);
			}
			/* write_blocked_on_read stays set if do_write didn't clear it */
			return;
		}
		/* write made progress, clear blocked flag */
		ssl_obj->write_blocked_on_read = 0;
	}

	if (ssl_obj->read_blocked_on_write) {
		/* can't read right now, need write first */
		return;
	}

	if ((ssl_obj->stream.enabled & ASYNC_EVENT_READ) == 0) {
		return;
	}

	/* read loop */
	{
		long n_to_read = ASYNC_LOOP_BUFFER_SIZE;
		int r;

		while (n_to_read > 0) {
			r = async_ssl_do_read(ssl_obj, n_to_read);
			if (r & (OP_BLOCKED | OP_ERROR | OP_EOF)) {
				if (r & OP_ERROR) {
					async_ssl_conn_closed(ssl_obj, SSL_ERROR_SSL);
					return;
				}
				else if (r & OP_EOF) {
					SSL *ssl = (SSL*)ssl_obj->ssl;
					if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) {
						/* clean shutdown: peer sent close_notify.
						   Automatically reply with our close_notify
						   to complete the bidirectional shutdown. */
						ssl_obj->ssl_state = ASYNC_STREAM_SSL_SHUTTING;
						async_ssl_do_shutdown(ssl_obj);
					} else {
						/* dirty shutdown */
						if (ssl_obj->allow_dirty_shutdown) {
							ssl_obj->stream.eof |= ASYNC_STREAM_INPUT;
							async_ssl_enter_dead(ssl_obj);
							async_ssl_notify(ssl_obj,
								ASYNC_STREAM_EVT_EOF, 0);
						} else {
							async_ssl_conn_closed(ssl_obj, SSL_ERROR_SYSCALL);
							return;
						}
					}
				}
				break;
			}
			n_to_read = SSL_pending((SSL*)ssl_obj->ssl);
			if (n_to_read <= 0) {
				/* check if underlying has more data */
				if (async_stream_remain(ssl_obj->underlying) <= 0) {
					break;
				}
				n_to_read = ASYNC_LOOP_BUFFER_SIZE;
			}
		}
	}
}


//---------------------------------------------------------------------
// consider_writing: called when underlying can write or read unblocked
//---------------------------------------------------------------------
static void async_ssl_consider_writing(CAsyncSSL *ssl_obj)
{
	/* handle read ops blocked on write (renegotiation) */
	if (ssl_obj->read_blocked_on_write) {
		long n_to_read = ASYNC_LOOP_BUFFER_SIZE;
		int r = async_ssl_do_read(ssl_obj, n_to_read);
		if (r & (OP_BLOCKED | OP_ERROR | OP_EOF)) {
			if (r & OP_ERROR) {
				async_ssl_conn_closed(ssl_obj, SSL_ERROR_SSL);
			}
			else if (r & OP_EOF) {
				SSL *ssl = (SSL*)ssl_obj->ssl;
				if (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) {
					/* clean shutdown: peer sent close_notify.
					   Automatically reply to complete bidirectional
					   shutdown, same logic as consider_reading. */
					ssl_obj->ssl_state = ASYNC_STREAM_SSL_SHUTTING;
					async_ssl_do_shutdown(ssl_obj);
				} else {
					/* dirty shutdown */
					if (ssl_obj->allow_dirty_shutdown) {
						ssl_obj->stream.eof |= ASYNC_STREAM_INPUT;
						async_ssl_enter_dead(ssl_obj);
						async_ssl_notify(ssl_obj,
							ASYNC_STREAM_EVT_EOF, 0);
					} else {
						async_ssl_conn_closed(ssl_obj,
							SSL_ERROR_SYSCALL);
					}
				}
			}
			return;
		}
		/* read made progress, clear blocked flag */
		ssl_obj->read_blocked_on_write = 0;
	}

	if (ssl_obj->write_blocked_on_read) {
		/* can't write right now, need read first */
		return;
	}

	/* write loop */
	if (ssl_obj->sendbuf.size > 0) {
		int r = async_ssl_do_write(ssl_obj);
		if (r & OP_EOF) {
			ssl_obj->stream.eof |= ASYNC_STREAM_OUTPUT;
			async_ssl_notify(ssl_obj,
				ASYNC_STREAM_EVT_EOF, 0);
		}
		else if (r & OP_ERROR) {
			async_ssl_conn_closed(ssl_obj, SSL_ERROR_SSL);
			return;
		}
	}

	if (ssl_obj->closing) return;

	/* if write blocked on read, enable read on underlying */
	if (ssl_obj->write_blocked_on_read) {
		async_stream_enable(ssl_obj->underlying, ASYNC_EVENT_READ);
	}
}


//---------------------------------------------------------------------
// Enter DEAD state: disable underlying events and clear blocked flags
//---------------------------------------------------------------------
static void async_ssl_enter_dead(CAsyncSSL *ssl_obj)
{
	if (ssl_obj->underlying) {
		async_stream_disable(ssl_obj->underlying, ASYNC_EVENT_READ);
		async_stream_disable(ssl_obj->underlying, ASYNC_EVENT_WRITE);
	}
	ssl_obj->read_blocked_on_write = 0;
	ssl_obj->write_blocked_on_read = 0;
	ssl_obj->ssl_state = ASYNC_STREAM_SSL_DEAD;
}


//---------------------------------------------------------------------
// Handle connection close / error
//---------------------------------------------------------------------
static void async_ssl_conn_closed(CAsyncSSL *ssl_obj, int errcode)
{
	CAsyncStream *stream = &ssl_obj->stream;

	stream->error = errcode;
	stream->direction = 0;

	async_ssl_enter_dead(ssl_obj);

	async_ssl_dispatch(ssl_obj, ASYNC_STREAM_EVT_ERROR, errcode);
}


//=====================================================================
// CAsyncSSL vtable implementation
//=====================================================================

//---------------------------------------------------------------------
// Destroy: actual cleanup and resource release
//---------------------------------------------------------------------
static void async_ssl_destroy(CAsyncSSL *ssl_obj)
{
	CAsyncStream *stream;
	SSL *ssl;
	CAsyncLoop *loop;

	if (ssl_obj == NULL) return;

	stream = &ssl_obj->stream;
	ssl = (SSL*)ssl_obj->ssl;
	loop = stream->loop;

	/* stop postpone */
	if (async_post_is_active(&ssl_obj->evt_post)) {
		async_post_stop(loop, &ssl_obj->evt_post);
	}

	/* detach from underlying stream - restore original callback/user */
	if (ssl_obj->underlying) {
		ssl_obj->underlying->user = ssl_obj->orig_user;
		ssl_obj->underlying->callback = ssl_obj->orig_callback;

		if (ssl_obj->close_on_free) {
			async_stream_close(ssl_obj->underlying);
		}
		ssl_obj->underlying = NULL;
	}

	/* free SSL and BIO */
	if (ssl != NULL) {
		SSL_free(ssl);
		ssl_obj->ssl = NULL;
		ssl_obj->bio = NULL;
	}

	/* free hostname and ALPN copies */
	if (ssl_obj->sni_hostname) {
		ikmem_free(ssl_obj->sni_hostname);
		ssl_obj->sni_hostname = NULL;
	}
	if (ssl_obj->verify_host) {
		ikmem_free(ssl_obj->verify_host);
		ssl_obj->verify_host = NULL;
	}
	if (ssl_obj->verify_ip) {
		ikmem_free(ssl_obj->verify_ip);
		ssl_obj->verify_ip = NULL;
	}
	if (ssl_obj->alpn_protos) {
		ikmem_free(ssl_obj->alpn_protos);
		ssl_obj->alpn_protos = NULL;
	}
	if (ssl_obj->alpn_selected) {
		ikmem_free(ssl_obj->alpn_selected);
		ssl_obj->alpn_selected = NULL;
	}

	ims_destroy(&ssl_obj->recvbuf);
	ims_destroy(&ssl_obj->sendbuf);
	ims_destroy(&ssl_obj->notify);

	stream->instance = NULL;
	async_stream_zero(stream);
	ikmem_free(ssl_obj);
}


//---------------------------------------------------------------------
// close: set closing flag, defer destroy if busy
// This does NOT send close_notify. Use async_stream_ssl_shutdown()
// for graceful close. This function forces immediate close.
//---------------------------------------------------------------------
static void async_ssl_close(CAsyncStream *stream)
{
	CAsyncSSL *ssl_obj;

	assert(stream != NULL);
	assert(stream->name == ASYNC_STREAM_NAME_SSL);

	ssl_obj = SSL_UPCAST(stream);

	if (ssl_obj->closing) return;
	ssl_obj->closing = 1;

	/* For dirty shutdown: just mark closing and destroy.
	   For graceful shutdown, use async_stream_ssl_shutdown() instead. */
	if (ssl_obj->busy == 0) {
		async_ssl_destroy(ssl_obj);
	}
}


//---------------------------------------------------------------------
// read: return decrypted data from recvbuf
//---------------------------------------------------------------------
static long async_ssl_read(CAsyncStream *stream, void *ptr, long size)
{
	CAsyncSSL *ssl_obj = SSL_UPCAST(stream);
	SSL *ssl = (SSL*)ssl_obj->ssl;
	long hr;

	if (size <= 0 || ptr == NULL) return 0;

	hr = (long)ims_read(&ssl_obj->recvbuf, ptr, size);

	/* after reading, if below watermark and read is enabled,
	   re-enable underlying read to accept more data.
	   Also check SSL_pending: if there are buffered decrypted bytes
	   in the SSL object, we need to drive consider_reading to
	   extract them (watermark may have blocked the previous round). */
	if (hr > 0 && (stream->enabled & ASYNC_EVENT_READ)) {
		if (stream->hiwater <= 0 ||
			(long)ssl_obj->recvbuf.size < stream->hiwater) {
			if (!ssl_obj->read_blocked_on_write) {
				async_stream_enable(ssl_obj->underlying,
					ASYNC_EVENT_READ);
			}
			if (ssl != NULL && SSL_pending(ssl) > 0) {
				ssl_obj->busy++;
				async_ssl_consider_reading(ssl_obj);
				ssl_obj->busy--;
				if (ssl_obj->closing && ssl_obj->busy == 0) {
					async_ssl_destroy(ssl_obj);
					return -1;
				}
			}
		}
	}

	return hr;
}


//---------------------------------------------------------------------
// write: put plaintext data into sendbuf, trigger SSL_write
//---------------------------------------------------------------------
static long async_ssl_write(CAsyncStream *stream, const void *ptr, long size)
{
	CAsyncSSL *ssl_obj = SSL_UPCAST(stream);
	long hr;

	if (size <= 0 || ptr == NULL) return 0;
	if (ssl_obj->closing) return -1;
	if (ssl_obj->ssl_state != ASYNC_STREAM_SSL_OPEN) return -1;

	hr = ims_write(&ssl_obj->sendbuf, ptr, size);

	if (hr > 0) {
		/* try to write immediately through SSL */
		if (ssl_obj->ssl_state == ASYNC_STREAM_SSL_OPEN) {
			if (!ssl_obj->write_blocked_on_read) {
				ssl_obj->busy++;
				async_ssl_consider_writing(ssl_obj);
				ssl_obj->busy--;
				if (ssl_obj->closing && ssl_obj->busy == 0) {
					async_ssl_destroy(ssl_obj);
					return -1;
				}
			}
		}
	}

	return hr;
}


//---------------------------------------------------------------------
// peek: return decrypted data from recvbuf without consuming
//---------------------------------------------------------------------
static long async_ssl_peek(CAsyncStream *stream, void *ptr, long size)
{
	CAsyncSSL *ssl_obj = SSL_UPCAST(stream);
	if (size <= 0 || ptr == NULL) return 0;
	return (long)ims_peek(&ssl_obj->recvbuf, ptr, size);
}


//---------------------------------------------------------------------
// enable
//---------------------------------------------------------------------
static void async_ssl_enable(CAsyncStream *stream, int event)
{
	CAsyncSSL *ssl_obj = SSL_UPCAST(stream);
	CAsyncStream *underlying = ssl_obj->underlying;

	if (event & ASYNC_EVENT_READ) {
		ssl_obj->user_enabled |= ASYNC_EVENT_READ;
		stream->enabled |= ASYNC_EVENT_READ;
	}
	if (event & ASYNC_EVENT_WRITE) {
		ssl_obj->user_enabled |= ASYNC_EVENT_WRITE;
		stream->enabled |= ASYNC_EVENT_WRITE;
	}

	if (ssl_obj->ssl_state == ASYNC_STREAM_SSL_OPEN) {
		/* propagate enable to underlying, respecting role reversal */
		if (ssl_obj->user_enabled & ASYNC_EVENT_READ) {
			if (!ssl_obj->read_blocked_on_write) {
				async_stream_enable(underlying, ASYNC_EVENT_READ);
			} else {
				async_stream_enable(underlying, ASYNC_EVENT_WRITE);
			}
		}
		if (ssl_obj->user_enabled & ASYNC_EVENT_WRITE) {
			if (!ssl_obj->write_blocked_on_read) {
				async_stream_enable(underlying, ASYNC_EVENT_WRITE);
			} else {
				async_stream_enable(underlying, ASYNC_EVENT_READ);
			}
		}
	} else {
		/* during handshake, enable underlying for both */
		if (event & ASYNC_EVENT_READ) {
			async_stream_enable(underlying, ASYNC_EVENT_READ);
		}
		if (event & ASYNC_EVENT_WRITE) {
			async_stream_enable(underlying, ASYNC_EVENT_WRITE);
		}
	}


	/* if underlying is already established and handshake
	   has not started, trigger it now (handles pair streams
	   and already-connected sockets) */
	if (underlying->state == ASYNC_STREAM_ESTAB &&
		(ssl_obj->ssl_state == ASYNC_STREAM_SSL_CONNECTING ||
		 ssl_obj->ssl_state == ASYNC_STREAM_SSL_ACCEPTING)) {
		ssl_obj->busy++;
		async_ssl_do_handshake(ssl_obj);
		ssl_obj->busy--;
		if (ssl_obj->closing && ssl_obj->busy == 0) {
			async_ssl_destroy(ssl_obj);
			return;
		}
	}
	/* if we have data in recvbuf and read is just enabled,
	   notify immediately */
	if ((event & ASYNC_EVENT_READ) &&
		(long)ssl_obj->recvbuf.size > 0) {
		async_ssl_notify(ssl_obj, ASYNC_STREAM_EVT_READING,
			(long)ssl_obj->recvbuf.size);
	}
}


//---------------------------------------------------------------------
// disable
//---------------------------------------------------------------------
static void async_ssl_disable(CAsyncStream *stream, int event)
{
	CAsyncSSL *ssl_obj = SSL_UPCAST(stream);
	CAsyncStream *underlying = ssl_obj->underlying;

	if (event & ASYNC_EVENT_READ) {
		ssl_obj->user_enabled &= ~ASYNC_EVENT_READ;
		stream->enabled &= ~ASYNC_EVENT_READ;
	}
	if (event & ASYNC_EVENT_WRITE) {
		ssl_obj->user_enabled &= ~ASYNC_EVENT_WRITE;
		stream->enabled &= ~ASYNC_EVENT_WRITE;
	}

	/* propagate disable to underlying */
	if (event & ASYNC_EVENT_READ) {
		if (!ssl_obj->write_blocked_on_read) {
			async_stream_disable(underlying, ASYNC_EVENT_READ);
		}
	}
	if (event & ASYNC_EVENT_WRITE) {
		if (!ssl_obj->read_blocked_on_write) {
			async_stream_disable(underlying, ASYNC_EVENT_WRITE);
		}
	}
}


//---------------------------------------------------------------------
// remain: bytes available in recvbuf
//---------------------------------------------------------------------
static long async_ssl_remain(const CAsyncStream *stream)
{
	CAsyncSSL *ssl_obj = SSL_PRIVATE((CAsyncStream*)stream);
	long total = (long)ssl_obj->recvbuf.size;
	return total;
}


//---------------------------------------------------------------------
// pending: bytes in sendbuf
//---------------------------------------------------------------------
static long async_ssl_pending(const CAsyncStream *stream)
{
	CAsyncSSL *ssl_obj = SSL_PRIVATE((CAsyncStream*)stream);
	return (long)ssl_obj->sendbuf.size;
}


//---------------------------------------------------------------------
// watermark
//---------------------------------------------------------------------
static void async_ssl_watermark(CAsyncStream *stream, long high, long low)
{
	CAsyncSSL *ssl_obj = SSL_UPCAST(stream);

	if (high >= 0) {
		stream->hiwater = high;
	}
	if (low >= 0) {
		stream->lowater = low;
	}

	/* adjust underlying read based on watermark */
	if (stream->enabled & ASYNC_EVENT_READ) {
		if (high > 0 && (long)ssl_obj->recvbuf.size >= high) {
			async_stream_disable(ssl_obj->underlying, ASYNC_EVENT_READ);
		} else {
			if (!ssl_obj->read_blocked_on_write) {
				async_stream_enable(ssl_obj->underlying,
					ASYNC_EVENT_READ);
			}
		}
	}
}


//---------------------------------------------------------------------
// option
//---------------------------------------------------------------------
static long async_ssl_option(CAsyncStream *stream, int option, long value)
{
	CAsyncSSL *ssl_obj = SSL_UPCAST(stream);

	switch (option) {
	case ASYNC_STREAM_OPT_SSL_GET_SSL:
		/* WARNING: long truncates 64-bit pointers on Win64.
		   Use async_stream_ssl_get_ssl() instead. */
		return (long)(ilong)ssl_obj->ssl;
	case ASYNC_STREAM_OPT_SSL_GET_FD:
		/* use option pass-through instead of assuming TCP */
		if (ssl_obj->underlying) {
			return _async_stream_option(ssl_obj->underlying,
				ASYNC_STREAM_OPT_TCP_GETFD, 0);
		}
		return -1;
	case ASYNC_STREAM_OPT_SSL_CLOSE_FREE:
		ssl_obj->close_on_free = (int)value;
		return value;
	case ASYNC_STREAM_OPT_SSL_NO_AUTO_CLOSE:
		ssl_obj->no_auto_close = (int)value;
		return value;
	default:
		/* pass through to underlying for TCP options */
		if (ssl_obj->underlying) {
			return _async_stream_option(ssl_obj->underlying, option, value);
		}
		return -1;
	}
}


//=====================================================================
// Public interface
//=====================================================================

//---------------------------------------------------------------------
// Lazy initialization via ithread_once + atexit cleanup
//---------------------------------------------------------------------
static void ssl_cleanup(void)
{
	if (bio_method_async_stream != NULL) {
		BIO_meth_free(bio_method_async_stream);
		bio_method_async_stream = NULL;
	}
}

static void ssl_init_once(void)
{
	bio_method_async_stream = bio_method_async_stream_new();
	if (bio_method_async_stream != NULL) {
		atexit(ssl_cleanup);
	}
}

/* Ensure BIO_METHOD is initialized before creating any SSL stream.
   Called from filter_new / socket_new. Returns 0 on success, -1 on failure. */
static int ssl_ensure_init(void)
{
	ithread_once(&ssl_init_control, ssl_init_once);
	return (bio_method_async_stream != NULL) ? 0 : -1;
}


//---------------------------------------------------------------------
// Apply SNI/ALPN/hostname verification to SSL object (before handshake)
//---------------------------------------------------------------------
static void async_ssl_apply_client_config(CAsyncSSL *ssl_obj, SSL *ssl_ptr)
{
	/* SNI hostname */
	if (ssl_obj->sni_hostname) {
		SSL_set_tlsext_host_name(ssl_ptr, ssl_obj->sni_hostname);
	}

	/* ALPN protocols */
	if (ssl_obj->alpn_protos && ssl_obj->alpn_protos_len > 0) {
		if (SSL_set_alpn_protos(ssl_ptr,
			(const unsigned char*)ssl_obj->alpn_protos,
			ssl_obj->alpn_protos_len) != 0) {
			async_ssl_put_error(ssl_obj, ERR_get_error());
		}
	}

	/* peer certificate identity check. verify_ip and verify_host are
	   mutually exclusive (enforced by the setters) because OpenSSL's
	   check_id() requires every configured identity to match, so setting
	   both would reject any certificate. verify_host falls back to the
	   SNI hostname, preserving the historical behavior. */
	if (ssl_obj->hostname_verify) {
		if (ssl_obj->verify_ip) {
			X509_VERIFY_PARAM *param = SSL_get0_param(ssl_ptr);
			if (X509_VERIFY_PARAM_set1_ip_asc(param,
				ssl_obj->verify_ip) != 1) {
				async_ssl_put_error(ssl_obj, ERR_get_error());
			}
		}
		else {
			const char *name = (ssl_obj->verify_host != NULL)?
				ssl_obj->verify_host : ssl_obj->sni_hostname;
			if (name != NULL) {
				SSL_set1_host(ssl_ptr, name);
				SSL_set_hostflags(ssl_ptr,
					X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
			}
		}
	}
}


//---------------------------------------------------------------------
// Cleanup helper for filter_new failure paths
// If bio_owned is non-zero the BIO is freed (SSL has not yet taken
// ownership of it). The caller retains ownership of the SSL object.
//---------------------------------------------------------------------
static void async_ssl_filter_new_cleanup(CAsyncSSL *ssl_obj,
		int bio_owned, BIO *bio)
{
	if (bio_owned && bio) {
		BIO_free(bio);
	}
	if (ssl_obj->sni_hostname) {
		ikmem_free(ssl_obj->sni_hostname);
		ssl_obj->sni_hostname = NULL;
	}
	if (ssl_obj->verify_host) {
		ikmem_free(ssl_obj->verify_host);
		ssl_obj->verify_host = NULL;
	}
	if (ssl_obj->verify_ip) {
		ikmem_free(ssl_obj->verify_ip);
		ssl_obj->verify_ip = NULL;
	}
	if (ssl_obj->alpn_protos) {
		ikmem_free(ssl_obj->alpn_protos);
		ssl_obj->alpn_protos = NULL;
	}
	ims_destroy(&ssl_obj->recvbuf);
	ims_destroy(&ssl_obj->sendbuf);
	ims_destroy(&ssl_obj->notify);
	async_stream_zero(&ssl_obj->stream);
	ikmem_free(ssl_obj);
}


//---------------------------------------------------------------------
// Create SSL stream in filter mode (wrapping an underlying stream)
//---------------------------------------------------------------------
CAsyncStream *async_stream_ssl_filter_new(CAsyncLoop *loop,
		CAsyncStream *underlying, void *ssl, int ssl_state,
		int close_on_free,
		void (*callback)(CAsyncStream *stream, int event, int args))
{
	CAsyncSSL *ssl_obj;
	CAsyncStream *stream;
	BIO *bio;
	SSL *ssl_ptr = (SSL*)ssl;

	if (loop == NULL || underlying == NULL || ssl == NULL) {
		return NULL;
	}

	if (underlying->loop != loop) {
		return NULL;
	}

	if (ssl_ensure_init() != 0) {
		return NULL;
	}

	ssl_obj = (CAsyncSSL*)ikmem_malloc(sizeof(CAsyncSSL));
	if (ssl_obj == NULL) return NULL;

	memset(ssl_obj, 0, sizeof(CAsyncSSL));

	stream = &ssl_obj->stream;
	async_stream_zero(stream);

	stream->name = ASYNC_STREAM_NAME_SSL;
	stream->instance = ssl_obj;
	stream->loop = loop;
	stream->callback = callback;
	stream->direction = ASYNC_STREAM_BOTH;
	stream->state = ASYNC_STREAM_CONNECTING;
	stream->underlying = underlying;
	stream->underown = close_on_free;

	ssl_obj->ssl = ssl;
	ssl_obj->underlying = underlying;
	ssl_obj->ssl_state = ssl_state;
	ssl_obj->close_on_free = close_on_free;
	ssl_obj->closing = 0;
	ssl_obj->busy = 0;
	ssl_obj->user_enabled = ASYNC_EVENT_WRITE;  /* write enabled by default */
	ssl_obj->last_write = 0;
	ssl_obj->read_blocked_on_write = 0;
	ssl_obj->write_blocked_on_read = 0;
	ssl_obj->allow_dirty_shutdown = 0;
	ssl_obj->n_errors = 0;

	/* save original underlying callback/user for restoration on destroy */
	ssl_obj->orig_user = underlying->user;
	ssl_obj->orig_callback = underlying->callback;

	ims_init(&ssl_obj->recvbuf, &loop->memnode, 0, 0);
	ims_init(&ssl_obj->sendbuf, &loop->memnode, 0, 0);
	ims_init(&ssl_obj->notify, &loop->memnode, 0, 0);

	async_post_init(&ssl_obj->evt_post, async_ssl_postpone);
	ssl_obj->evt_post.user = stream;

	stream->close = async_ssl_close;
	stream->read = async_ssl_read;
	stream->write = async_ssl_write;
	stream->peek = async_ssl_peek;
	stream->enable = async_ssl_enable;
	stream->disable = async_ssl_disable;
	stream->remain = async_ssl_remain;
	stream->pending = async_ssl_pending;
	stream->watermark = async_ssl_watermark;
	stream->option = async_ssl_option;

	/* Configure SSL object */
	SSL_set_mode(ssl_ptr, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
		| SSL_MODE_ENABLE_PARTIAL_WRITE);

	/* Create custom BIO and bind to SSL */
	bio = bio_new_async_stream(underlying);
	if (bio == NULL) {
		/* caller still owns ssl_ptr; free only local resources */
		async_ssl_filter_new_cleanup(ssl_obj, 0, NULL);
		return NULL;
	}

	/* Set SSL connection state */
	switch (ssl_state) {
	case ASYNC_STREAM_SSL_CONNECTING:
		SSL_clear(ssl_ptr);
		SSL_set_connect_state(ssl_ptr);
		stream->state = ASYNC_STREAM_CONNECTING;
		break;
	case ASYNC_STREAM_SSL_ACCEPTING:
		SSL_clear(ssl_ptr);
		SSL_set_accept_state(ssl_ptr);
		stream->state = ASYNC_STREAM_CONNECTING;
		break;
	case ASYNC_STREAM_SSL_OPEN:
		stream->state = ASYNC_STREAM_ESTAB;
		break;
	default:
		/* invalid ssl_state: SSL has not taken ownership of BIO yet,
		   so free it here; caller still owns ssl_ptr */
		async_ssl_filter_new_cleanup(ssl_obj, 1, bio);
		return NULL;
	}

	ssl_obj->bio = bio;
	SSL_set_bio(ssl_ptr, bio, bio);

	/* Hijack underlying stream's callback (save originals already stored) */
	underlying->user = ssl_obj;
	underlying->callback = async_ssl_underlying_event;

	/* Do not enable underlying or start handshake here.
	   User must first set SNI/ALPN/hostname config, then call
	   async_stream_enable() on the SSL stream to start handshake.
	   When underlying is ESTAB, enable will trigger the handshake. */


	return stream;
}


//---------------------------------------------------------------------
// Create SSL stream in socket mode (direct fd)
//---------------------------------------------------------------------
CAsyncStream *async_stream_ssl_socket_new(CAsyncLoop *loop,
		int fd, void *ssl, int ssl_state,
		void (*callback)(CAsyncStream *stream, int event, int args))
{
	CAsyncStream *tcp_stream;
	CAsyncStream *ssl_stream;
	SSL *ssl_ptr = (SSL*)ssl;

	if (loop == NULL || fd < 0 || ssl == NULL) {
		return NULL;
	}

	/* Set fd on SSL if not already set */
	{
		BIO *existing_bio = SSL_get_wbio(ssl_ptr);
		if (existing_bio != NULL) {
			/* only check fd if the existing BIO is a socket BIO */
			if (BIO_method_type(existing_bio) == BIO_TYPE_SOCKET) {
				long existing_fd = BIO_get_fd(existing_bio, NULL);
				if (existing_fd >= 0 && existing_fd != fd) {
					return NULL;  /* conflicting fd */
				}
			}
		}
	}

	/* Create a TCP stream from the fd */
	tcp_stream = async_stream_tcp_assign(loop, NULL, fd, 1);
	if (tcp_stream == NULL) {
		return NULL;
	}

	/* Create SSL stream wrapping the TCP stream */
	ssl_stream = async_stream_ssl_filter_new(loop, tcp_stream, ssl,
		ssl_state, 1, callback);
	if (ssl_stream == NULL) {
		async_stream_close(tcp_stream);
		return NULL;
	}

	return ssl_stream;
}


//---------------------------------------------------------------------
// Gracefully shut down the SSL connection (send close_notify)
//---------------------------------------------------------------------
int async_stream_ssl_shutdown(CAsyncStream *stream)
{
	CAsyncSSL *ssl_obj;
	SSL *ssl;

	if (stream == NULL) return -1;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return -1;
	ssl_obj = SSL_PRIVATE(stream);

	if (ssl_obj->closing) return -1;
	if (ssl_obj->ssl_state != ASYNC_STREAM_SSL_OPEN) {
		return -1;
	}

	ssl = (SSL*)ssl_obj->ssl;
	if (ssl == NULL) return -1;

	/* transition to shutting state */
	ssl_obj->ssl_state = ASYNC_STREAM_SSL_SHUTTING;

	ssl_obj->busy++;

	/* flush any buffered plaintext data before starting shutdown,
	   otherwise sendbuf data would be lost */
	if (ssl_obj->sendbuf.size > 0) {
		async_ssl_consider_writing(ssl_obj);
		if (ssl_obj->closing) {
			ssl_obj->busy--;
			if (ssl_obj->busy == 0) async_ssl_destroy(ssl_obj);
			return -1;
		}
	}

	/* start the shutdown state machine */
	async_ssl_do_shutdown(ssl_obj);

	ssl_obj->busy--;

	return 0;
}


//---------------------------------------------------------------------
// Get the underlying SSL* object
//---------------------------------------------------------------------
void *async_stream_ssl_get_ssl(CAsyncStream *stream)
{
	if (stream == NULL) return NULL;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return NULL;
	return (void*)SSL_PRIVATE(stream)->ssl;
}


//---------------------------------------------------------------------
// Get the underlying socket fd
//---------------------------------------------------------------------
int async_stream_ssl_get_fd(const CAsyncStream *stream)
{
	CAsyncSSL *ssl_obj;
	long fd;
	if (stream == NULL) return -1;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return -1;
	ssl_obj = SSL_PRIVATE((CAsyncStream*)stream);
	/* use option pass-through instead of assuming TCP.
	   if underlying is not TCP (e.g. pair stream), option returns 0
	   which is ambiguous with fd=0, so check name first. */
	if (ssl_obj->underlying == NULL) return -1;
	if (ssl_obj->underlying->name != ASYNC_STREAM_NAME_TCP) return -1;
	fd = _async_stream_option(ssl_obj->underlying,
		ASYNC_STREAM_OPT_TCP_GETFD, 0);
	return (int)fd;
}


//---------------------------------------------------------------------
// Get/set dirty shutdown policy
//---------------------------------------------------------------------
int async_stream_ssl_get_allow_dirty_shutdown(CAsyncStream *stream)
{
	if (stream == NULL) return 0;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return 0;
	return SSL_PRIVATE(stream)->allow_dirty_shutdown;
}

void async_stream_ssl_set_allow_dirty_shutdown(CAsyncStream *stream, int allow)
{
	if (stream == NULL) return;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return;
	SSL_PRIVATE(stream)->allow_dirty_shutdown = allow;
}


//---------------------------------------------------------------------
// Get most recent OpenSSL error
//---------------------------------------------------------------------
unsigned long async_stream_ssl_get_error(CAsyncStream *stream)
{
	CAsyncSSL *ssl_obj;
	if (stream == NULL) return 0;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return 0;
	ssl_obj = SSL_PRIVATE(stream);
	if (ssl_obj->n_errors > 0) {
		return ssl_obj->errors[ssl_obj->n_errors - 1];
	}
	return 0;
}


//---------------------------------------------------------------------
// Initiate key update (TLS 1.3) or renegotiation (TLS 1.2)
//---------------------------------------------------------------------
int async_stream_ssl_key_update(CAsyncStream *stream, int request_peer_update)
{
	CAsyncSSL *ssl_obj;
	SSL *ssl;
	int ret;

	if (stream == NULL) return -1;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return -1;
	ssl_obj = SSL_PRIVATE(stream);
	ssl = (SSL*)ssl_obj->ssl;
	if (ssl == NULL) return -1;
	if (ssl_obj->ssl_state != ASYNC_STREAM_SSL_OPEN) return -1;

	ssl_obj->busy++;

#if defined(TLS1_3_VERSION) && TLS1_3_VERSION != 0
	if (SSL_version(ssl) >= TLS1_3_VERSION) {
		/* TLS 1.3: use KeyUpdate (post-handshake key rotation) */
		int updatetype = request_peer_update ?
			SSL_KEY_UPDATE_REQUESTED : SSL_KEY_UPDATE_NOT_REQUESTED;
		ret = SSL_key_update(ssl, updatetype);
		if (ret != 1) {
			async_ssl_put_error(ssl_obj, ERR_get_error());
			ssl_obj->busy--;
			return -1;
		}
		/* KeyUpdate doesn't change ssl_state, it's transparent.
		   Force it by calling SSL_do_handshake(). */
		ERR_clear_error();
		ret = SSL_do_handshake(ssl);
		if (ret != 1) {
			int err = SSL_get_error(ssl, ret);
			if (err == SSL_ERROR_WANT_READ) {
				async_stream_enable(ssl_obj->underlying,
					ASYNC_EVENT_READ);
			} else if (err == SSL_ERROR_WANT_WRITE) {
				async_stream_enable(ssl_obj->underlying,
					ASYNC_EVENT_WRITE);
			} else {
				/* fatal error during KeyUpdate */
				async_ssl_put_error(ssl_obj, ERR_get_error());
				ssl_obj->busy--;
				return -1;
			}
		}
	} else {
#else
	{
#endif
		/* TLS 1.2 and below: use renegotiation */
		ret = SSL_renegotiate(ssl);
		if (ret != 1) {
			async_ssl_put_error(ssl_obj, ERR_get_error());
			ssl_obj->busy--;
			return -1;
		}
		ssl_obj->ssl_state = ASYNC_STREAM_SSL_CONNECTING;
		async_ssl_do_handshake(ssl_obj);
	}

	ssl_obj->busy--;
	if (ssl_obj->closing && ssl_obj->busy == 0) {
		async_ssl_destroy(ssl_obj);
		return -1;
	}
	return 0;
}


//---------------------------------------------------------------------
// SNI hostname
//---------------------------------------------------------------------
int async_stream_ssl_set_sni_hostname(CAsyncStream *stream,
		const char *hostname)
{
	CAsyncSSL *ssl_obj;
	char *copy;
	long len;

	if (stream == NULL || hostname == NULL) return -1;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return -1;
	ssl_obj = SSL_PRIVATE(stream);

	len = (long)strlen(hostname);
	if (len <= 0) return -1;

	copy = (char*)ikmem_malloc(len + 1);
	if (copy == NULL) return -1;
	memcpy(copy, hostname, len + 1);

	if (ssl_obj->sni_hostname) {
		ikmem_free(ssl_obj->sni_hostname);
	}
	ssl_obj->sni_hostname = copy;

	return 0;
}

const char *async_stream_ssl_get_sni_hostname(const CAsyncStream *stream)
{
	CAsyncSSL *ssl_obj;
	SSL *ssl;
	const char *name;

	if (stream == NULL) return NULL;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return NULL;
	ssl_obj = SSL_PRIVATE((CAsyncStream*)stream);

	/* if handshake is complete, return what was actually sent/received */
	ssl = (SSL*)ssl_obj->ssl;
	if (ssl != NULL && ssl_obj->ssl_state == ASYNC_STREAM_SSL_OPEN) {
		name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
		if (name != NULL) return name;
	}

	/* otherwise return what was configured */
	return ssl_obj->sni_hostname;
}


//---------------------------------------------------------------------
// ALPN protocols
//---------------------------------------------------------------------
int async_stream_ssl_set_alpn_protos(CAsyncStream *stream,
		const char *protos, int protos_len)
{
	CAsyncSSL *ssl_obj;
	char *copy;

	if (stream == NULL || protos == NULL || protos_len <= 0) return -1;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return -1;
	ssl_obj = SSL_PRIVATE(stream);

	copy = (char*)ikmem_malloc(protos_len);
	if (copy == NULL) return -1;
	memcpy(copy, protos, protos_len);

	if (ssl_obj->alpn_protos) {
		ikmem_free(ssl_obj->alpn_protos);
	}
	ssl_obj->alpn_protos = copy;
	ssl_obj->alpn_protos_len = protos_len;

	return 0;
}

const char *async_stream_ssl_get_alpn_selected(const CAsyncStream *stream)
{
	CAsyncSSL *ssl_obj;

	if (stream == NULL) return NULL;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return NULL;
	ssl_obj = SSL_PRIVATE((CAsyncStream*)stream);

	if (ssl_obj->ssl_state != ASYNC_STREAM_SSL_OPEN) {
		return NULL;
	}

	return ssl_obj->alpn_selected;
}



//---------------------------------------------------------------------
// Hostname verification
//---------------------------------------------------------------------
int async_stream_ssl_set_hostname_verify(CAsyncStream *stream, int enable)
{
	CAsyncSSL *ssl_obj;

	if (stream == NULL) return -1;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return -1;
	ssl_obj = SSL_PRIVATE(stream);
	ssl_obj->hostname_verify = enable;
	return 0;
}

int async_stream_ssl_get_hostname_verify(const CAsyncStream *stream)
{
	CAsyncSSL *ssl_obj;

	if (stream == NULL) return 0;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return 0;
	ssl_obj = SSL_PRIVATE((CAsyncStream*)stream);
	return ssl_obj->hostname_verify;
}


//---------------------------------------------------------------------
// Verification identity (independent from SNI)
//---------------------------------------------------------------------

/* Duplicate text into a freshly allocated buffer, NULL/empty means the
   field is cleared. Returns 0 on success, -1 on allocation failure. */
static int async_ssl_replace_text(char **slot, const char *text)
{
	char *copy = NULL;

	if (text != NULL && text[0] != '\0') {
		long len = (long)strlen(text);
		copy = (char*)ikmem_malloc(len + 1);
		if (copy == NULL) return -1;
		memcpy(copy, text, len + 1);
	}
	if (*slot != NULL) {
		ikmem_free(*slot);
	}
	*slot = copy;
	return 0;
}

int async_stream_ssl_set_verify_host(CAsyncStream *stream,
		const char *hostname)
{
	CAsyncSSL *ssl_obj;

	if (stream == NULL) return -1;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return -1;
	ssl_obj = SSL_PRIVATE(stream);

	if (async_ssl_replace_text(&ssl_obj->verify_host, hostname) != 0) {
		return -1;
	}
	/* mutually exclusive with verify_ip, see the header comment */
	if (ssl_obj->verify_host != NULL) {
		async_ssl_replace_text(&ssl_obj->verify_ip, NULL);
	}
	return 0;
}

const char *async_stream_ssl_get_verify_host(const CAsyncStream *stream)
{
	CAsyncSSL *ssl_obj;

	if (stream == NULL) return NULL;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return NULL;
	ssl_obj = SSL_PRIVATE((CAsyncStream*)stream);
	return ssl_obj->verify_host;
}

int async_stream_ssl_set_verify_ip(CAsyncStream *stream, const char *ip)
{
	CAsyncSSL *ssl_obj;

	if (stream == NULL) return -1;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return -1;
	ssl_obj = SSL_PRIVATE(stream);

	/* reject malformed text early: X509_VERIFY_PARAM_set1_ip_asc() is
	   only called at handshake time, where a failure is much harder to
	   attribute to this call */
	if (ip != NULL && ip[0] != '\0') {
		unsigned char probe[16];
		if (isockaddr_pton(AF_INET, ip, probe) != 0 &&
			isockaddr_pton(AF_INET6, ip, probe) != 0) {
			return -1;
		}
	}
	if (async_ssl_replace_text(&ssl_obj->verify_ip, ip) != 0) {
		return -1;
	}
	/* mutually exclusive with verify_host, see the header comment */
	if (ssl_obj->verify_ip != NULL) {
		async_ssl_replace_text(&ssl_obj->verify_host, NULL);
	}
	return 0;
}

const char *async_stream_ssl_get_verify_ip(const CAsyncStream *stream)
{
	CAsyncSSL *ssl_obj;

	if (stream == NULL) return NULL;
	if (stream->name != ASYNC_STREAM_NAME_SSL) return NULL;
	ssl_obj = SSL_PRIVATE((CAsyncStream*)stream);
	return ssl_obj->verify_ip;
}


//---------------------------------------------------------------------
// Capability query
//---------------------------------------------------------------------
int async_stream_ssl_available(void)
{
	return 1;
}


//=====================================================================
// System root certificate loading
//=====================================================================

/* whether a native OS trust store implementation is compiled in */
#if (defined(_WIN32) && !defined(IHAVE_NOT_WINCRYPT)) || \
	(defined(__APPLE__) && defined(IHAVE_SECURITY_FRAMEWORK))
#define SSL_ROOTS_HAS_NATIVE 1
#else
#define SSL_ROOTS_HAS_NATIVE 0
#endif


#if SSL_ROOTS_HAS_NATIVE
//---------------------------------------------------------------------
// add one DER certificate to the store, ignoring duplicates and
// malformed entries; returns 1 on success, 0 otherwise
//---------------------------------------------------------------------
static int ssl_roots_add_der(X509_STORE *xs, const unsigned char *der,
		long size)
{
	X509 *x = d2i_X509(NULL, &der, size);
	int hr;
	if (x == NULL) {
		ERR_clear_error();
		return 0;
	}
	hr = X509_STORE_add_cert(xs, x);
	if (hr != 1) ERR_clear_error();   /* pre-1.1.0 flags duplicates */
	X509_free(x);                     /* add_cert took its own ref */
	return (hr == 1)? 1 : 0;
}
#endif


//---------------------------------------------------------------------
// import every certificate from a PEM bundle file, returns the
// number imported, or -1 if the file cannot be opened
//---------------------------------------------------------------------
static int ssl_roots_load_pem(X509_STORE *xs, const char *path)
{
	BIO *bio = BIO_new_file(path, "r");
	X509 *x;
	int count = 0;
	if (bio == NULL) {
		ERR_clear_error();
		return -1;
	}
	while ((x = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
		if (X509_STORE_add_cert(xs, x) == 1) count++;
		else ERR_clear_error();
		X509_free(x);
	}
	ERR_clear_error();   /* PEM_R_NO_START_LINE at EOF is expected */
	BIO_free(bio);
	return count;
}


//---------------------------------------------------------------------
// check that a directory exists (X509_LOOKUP_add_dir stores the path
// without validating it, which would fake a success)
//---------------------------------------------------------------------
static int ssl_roots_dir_exists(const char *path)
{
#ifdef _WIN32
	DWORD attr = GetFileAttributesA(path);
	if (attr == INVALID_FILE_ATTRIBUTES) return 0;
	return (attr & FILE_ATTRIBUTE_DIRECTORY)? 1 : 0;
#else
	struct stat st;
	if (stat(path, &st) != 0) return 0;
	return S_ISDIR(st.st_mode)? 1 : 0;
#endif
}


//---------------------------------------------------------------------
// register a hashed certificate directory, returns 0 on success
//---------------------------------------------------------------------
static int ssl_roots_add_dir(SSL_CTX *ctx, const char *path)
{
	if (ssl_roots_dir_exists(path) == 0) return -1;
	if (SSL_CTX_load_verify_locations(ctx, NULL, path) != 1) {
		ERR_clear_error();
		return -1;
	}
	return 0;
}


#if defined(_WIN32) && !defined(IHAVE_NOT_WINCRYPT)
//---------------------------------------------------------------------
// Windows: enumerate the system certificate stores ("ROOT" holds the
// trusted root CAs, "CA" the intermediates). Known simplification:
// per-certificate trust properties (EKU restrictions, Disallowed
// store) are ignored.
//---------------------------------------------------------------------
static int ssl_roots_load_native(X509_STORE *xs)
{
	static const char *names[] = { "ROOT", "CA" };
	int count = 0, opened = 0;
	int i;
	for (i = 0; i < 2; i++) {
		HCERTSTORE store = CertOpenSystemStoreA(0, names[i]);
		PCCERT_CONTEXT it = NULL;
		if (store == NULL) continue;
		opened++;
		/* passing the previous context makes the enumerator free it,
		   so no manual CertFreeCertificateContext is needed when the
		   loop runs to NULL */
		while ((it = CertEnumCertificatesInStore(store, it)) != NULL) {
			if ((it->dwCertEncodingType & X509_ASN_ENCODING) == 0)
				continue;
			count += ssl_roots_add_der(xs, it->pbCertEncoded,
					(long)it->cbCertEncoded);
		}
		CertCloseStore(store, 0);
	}
	return (opened > 0)? count : -1;
}

#elif defined(__APPLE__) && defined(IHAVE_SECURITY_FRAMEWORK)
//---------------------------------------------------------------------
// macOS: system anchors from Security.framework. Known simplification:
// only system anchors are imported, user-added trust settings are not.
//---------------------------------------------------------------------
static int ssl_roots_load_native(X509_STORE *xs)
{
	CFArrayRef anchors = NULL;
	CFIndex i, n;
	int count = 0;
	if (SecTrustCopyAnchorCertificates(&anchors) != errSecSuccess ||
		anchors == NULL) {
		return -1;
	}
	n = CFArrayGetCount(anchors);
	for (i = 0; i < n; i++) {
		SecCertificateRef cert = (SecCertificateRef)
				CFArrayGetValueAtIndex(anchors, i);
		CFDataRef der = SecCertificateCopyData(cert);
		if (der != NULL) {
			count += ssl_roots_add_der(xs, CFDataGetBytePtr(der),
					(long)CFDataGetLength(der));
			CFRelease(der);
		}
	}
	CFRelease(anchors);
	return count;
}
#endif


//---------------------------------------------------------------------
// load system root certificates, see inetssl.h for the source order,
// the return value convention and the build-time macros
//---------------------------------------------------------------------
int async_ssl_load_system_roots(void *ssl_ctx)
{
	SSL_CTX *ctx = (SSL_CTX*)ssl_ctx;
	X509_STORE *xs;
	const char *env;
	int hr;

	if (ctx == NULL) return -1;
	xs = SSL_CTX_get_cert_store(ctx);
	if (xs == NULL) return -1;

	/* 1. explicit user override via environment variables, same
	      convention as curl/OpenSSL */
	env = getenv("SSL_CERT_FILE");
	if (env != NULL && env[0] != '\0') {
		hr = ssl_roots_load_pem(xs, env);
		if (hr > 0) return hr;
	}
	env = getenv("SSL_CERT_DIR");
	if (env != NULL && env[0] != '\0') {
		if (ssl_roots_add_dir(ctx, env) == 0) return 0;
	}

	/* 2. native OS trust store */
#if SSL_ROOTS_HAS_NATIVE
	hr = ssl_roots_load_native(xs);
	if (hr > 0) return hr;
#endif

#ifndef _WIN32
	/* 3. well-known CA bundle files */
	{
		static const char *bundles[] = {
			"/etc/ssl/certs/ca-certificates.crt",       /* Debian/Ubuntu/Arch */
			"/etc/pki/tls/certs/ca-bundle.crt",         /* RHEL/CentOS/Fedora */
			"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", /* ca-trust */
			"/etc/ssl/ca-bundle.pem",                   /* openSUSE */
			"/etc/ssl/cert.pem",                        /* Alpine/BSD/macOS */
			"/usr/local/share/certs/ca-root-nss.crt",   /* FreeBSD ca_root_nss */
			"/usr/local/etc/ssl/cert.pem",              /* FreeBSD ports */
			"/opt/homebrew/etc/openssl@3/cert.pem",     /* macOS homebrew arm */
			"/usr/local/etc/openssl@3/cert.pem",        /* macOS homebrew x86 */
			NULL,
		};
		int i;
		for (i = 0; bundles[i] != NULL; i++) {
			hr = ssl_roots_load_pem(xs, bundles[i]);
			if (hr > 0) return hr;
		}
	}

	/* 4. well-known hashed CA directories */
	{
		static const char *dirs[] = {
			"/etc/ssl/certs",                  /* most distros */
			"/etc/pki/tls/certs",              /* RHEL family */
			"/system/etc/security/cacerts",    /* Android */
			NULL,
		};
		int i;
		for (i = 0; dirs[i] != NULL; i++) {
			if (ssl_roots_add_dir(ctx, dirs[i]) == 0) return 0;
		}
	}
#endif

	/* 5. OpenSSL compile-time default paths (count unknown) */
	if (SSL_CTX_set_default_verify_paths(ctx) == 1) return 0;
	ERR_clear_error();
	return -1;
}


#else  /* !IHAVE_OPENSSL */

//=====================================================================
// Stub implementation (compiled without OpenSSL)
//
// Every function fails with NULL/-1 (or a neutral value for pure
// getters), keeping the library linkable in environments without
// OpenSSL. Use async_stream_ssl_available() to detect this at
// runtime and report a clear error to the user.
//=====================================================================

int async_stream_ssl_available(void)
{
	return 0;
}

CAsyncStream *async_stream_ssl_filter_new(CAsyncLoop *loop,
		CAsyncStream *underlying, void *ssl, int ssl_state,
		int close_on_free,
		void (*callback)(CAsyncStream *stream, int event, int args))
{
	(void)loop; (void)underlying; (void)ssl; (void)ssl_state;
	(void)close_on_free; (void)callback;
	return NULL;
}

CAsyncStream *async_stream_ssl_socket_new(CAsyncLoop *loop,
		int fd, void *ssl, int ssl_state,
		void (*callback)(CAsyncStream *stream, int event, int args))
{
	(void)loop; (void)fd; (void)ssl; (void)ssl_state; (void)callback;
	return NULL;
}

int async_stream_ssl_shutdown(CAsyncStream *stream)
{
	(void)stream;
	return -1;
}

void *async_stream_ssl_get_ssl(CAsyncStream *stream)
{
	(void)stream;
	return NULL;
}

int async_stream_ssl_get_fd(const CAsyncStream *stream)
{
	(void)stream;
	return -1;
}

int async_stream_ssl_get_allow_dirty_shutdown(CAsyncStream *stream)
{
	(void)stream;
	return 0;
}

void async_stream_ssl_set_allow_dirty_shutdown(CAsyncStream *stream, int allow)
{
	(void)stream; (void)allow;
}

unsigned long async_stream_ssl_get_error(CAsyncStream *stream)
{
	(void)stream;
	return 0;
}

int async_stream_ssl_key_update(CAsyncStream *stream, int request_peer_update)
{
	(void)stream; (void)request_peer_update;
	return -1;
}

int async_stream_ssl_set_sni_hostname(CAsyncStream *stream,
		const char *hostname)
{
	(void)stream; (void)hostname;
	return -1;
}

const char *async_stream_ssl_get_sni_hostname(const CAsyncStream *stream)
{
	(void)stream;
	return NULL;
}

int async_stream_ssl_set_alpn_protos(CAsyncStream *stream,
		const char *protos, int protos_len)
{
	(void)stream; (void)protos; (void)protos_len;
	return -1;
}

const char *async_stream_ssl_get_alpn_selected(const CAsyncStream *stream)
{
	(void)stream;
	return NULL;
}

int async_stream_ssl_set_hostname_verify(CAsyncStream *stream, int enable)
{
	(void)stream; (void)enable;
	return -1;
}

int async_stream_ssl_get_hostname_verify(const CAsyncStream *stream)
{
	(void)stream;
	return 0;
}

int async_stream_ssl_set_verify_host(CAsyncStream *stream,
		const char *hostname)
{
	(void)stream; (void)hostname;
	return -1;
}

const char *async_stream_ssl_get_verify_host(const CAsyncStream *stream)
{
	(void)stream;
	return NULL;
}

int async_stream_ssl_set_verify_ip(CAsyncStream *stream, const char *ip)
{
	(void)stream; (void)ip;
	return -1;
}

const char *async_stream_ssl_get_verify_ip(const CAsyncStream *stream)
{
	(void)stream;
	return NULL;
}

int async_ssl_load_system_roots(void *ssl_ctx)
{
	(void)ssl_ctx;
	return -1;
}


#endif  /* IHAVE_OPENSSL */
