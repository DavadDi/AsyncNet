//=====================================================================
//
// AsyncEvt.cpp - 
//
// Created by skywind on 2015/07/19
// Last Modified: 2025/04/19 22:08:19
//
//=====================================================================
#include <stddef.h>
#include <assert.h>

#include "AsyncEvt.h"


NAMESPACE_BEGIN(System);


//=====================================================================
// AsyncLoop
//=====================================================================

//---------------------------------------------------------------------
// dtor
//---------------------------------------------------------------------
AsyncLoop::~AsyncLoop()
{
	if (_loop != NULL) {
		_loop->self = NULL;
		_loop->writelog = NULL;
	}
	if (_borrow == false) {
		if (_loop != NULL) {
			async_loop_delete(_loop);
		}
	}
	_loop = NULL;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncLoop::AsyncLoop()
{
	_loop = async_loop_new();
	_loop->self = this;
	_borrow = false;
	_ptr = NULL;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncLoop::AsyncLoop(CAsyncLoop *loop)
{
	_loop = loop;
	_loop->self = this;
	_ptr = NULL;
	_borrow = true;
}


//---------------------------------------------------------------------
// move ctor
//---------------------------------------------------------------------
AsyncLoop::AsyncLoop(AsyncLoop &&src)
{
	this->_loop = src._loop;
	this->_borrow = src._borrow;
	this->_loop->self = this;
	this->_cb_log = src._cb_log;
	this->_cb_once = src._cb_once;
	this->_cb_idle = src._cb_idle;
	this->_cb_timer = src._cb_timer;
	this->_ptr = src._ptr;
	src._loop = NULL;
	src._borrow = false;
	src._cb_log = NULL;
	src._cb_once = NULL;
	src._cb_idle = NULL;
	src._cb_timer = NULL;
	src._ptr = NULL;
	if (src._log_cache.size() > 0) {
		this->_log_cache = std::move(src._log_cache);
	} else {
		this->_log_cache.clear();
	}
}


//---------------------------------------------------------------------
// run once
//---------------------------------------------------------------------
void AsyncLoop::RunOnce(uint32_t millisec)
{
	async_loop_once(_loop, millisec);
}


//---------------------------------------------------------------------
// run endless
//---------------------------------------------------------------------
void AsyncLoop::RunEndless()
{
	async_loop_run(_loop);
}


//---------------------------------------------------------------------
// exit RunEndless()
//---------------------------------------------------------------------
void AsyncLoop::Exit()
{
	async_loop_exit(_loop);
}


//---------------------------------------------------------------------
// setup interval (async_loop_once wait time, aka. epoll wait time)
//---------------------------------------------------------------------
void AsyncLoop::SetInterval(int millisec)
{
	if (millisec < 0) {
		millisec = 10; // default interval
	}
	if (_loop->poller) {
		async_loop_interval(_loop, millisec);
	}
}


//---------------------------------------------------------------------
// publish data to a topic
//---------------------------------------------------------------------
void AsyncLoop::Publish(int topic, const void *data, int size)
{
	async_loop_pub(_loop, topic, data, size);
}


//---------------------------------------------------------------------
// callback for c
//---------------------------------------------------------------------
void AsyncLoop::OnLog(void *logger, const char *text)
{
	AsyncLoop *self = (AsyncLoop*)logger;
	if (self) {
		if (self->_cb_log != nullptr) {
			self->_cb_log(text);
		}
	}
}


//---------------------------------------------------------------------
// callback for c
//---------------------------------------------------------------------
void AsyncLoop::OnOnce(CAsyncLoop *loop)
{
	AsyncLoop *self = (AsyncLoop*)loop->self;
	if (self) {
		if (self->_cb_once != nullptr) {
			self->_cb_once();
		}
	}
}


//---------------------------------------------------------------------
// callback for c
//---------------------------------------------------------------------
void AsyncLoop::OnTimer(CAsyncLoop *loop)
{
	AsyncLoop *self = (AsyncLoop*)loop->self;
	if (self) {
		if (self->_cb_timer != nullptr) {
			self->_cb_timer();
		}
	}
}


//---------------------------------------------------------------------
// callback for c
//---------------------------------------------------------------------
void AsyncLoop::OnIdle(CAsyncLoop *loop)
{
	AsyncLoop *self = (AsyncLoop*)loop->self;
	if (self) {
		if (self->_cb_idle != nullptr) {
			self->_cb_idle();
		}
	}
}


//---------------------------------------------------------------------
// set log handler
//---------------------------------------------------------------------
void AsyncLoop::SetLogHandler(std::function<void(const char *msg)> handler)
{
	if (handler == NULL) {
		_loop->writelog = NULL;
		_loop->logger = NULL;
		_cb_log = NULL;
	}
	else {
		_loop->writelog = OnLog;
		_loop->logger = this;
		_cb_log = handler;
	}
}


//---------------------------------------------------------------------
// write log
//---------------------------------------------------------------------
void AsyncLoop::Log(int channel, const char *fmt, ...)
{
	if (channel & _loop->logmask) {
		if (_loop->writelog != nullptr) {
			va_list argptr;
			char *buffer;
			if (_log_cache.size() < 1024) {
				_log_cache.resize(1024);
			}
			buffer = &_log_cache[0];
			va_start(argptr, fmt);
			vsprintf(buffer, fmt, argptr);
			va_end(argptr);
			if (_cb_log != nullptr) {
				_cb_log(buffer);
			}
		}
	}
}


//---------------------------------------------------------------------
// set log mask
//---------------------------------------------------------------------
void AsyncLoop::SetLogMask(int mask)
{
	_loop->logmask = mask;
}


//---------------------------------------------------------------------
// set once handler
//---------------------------------------------------------------------
void AsyncLoop::SetOnceHandler(std::function<void()> handler)
{
	_cb_once = handler;
	_loop->on_once = (handler == NULL)? NULL : OnOnce;
}


//---------------------------------------------------------------------
// set idle handler
//---------------------------------------------------------------------
void AsyncLoop::SetIdleHandler(std::function<void()> handler)
{
	_cb_idle = handler;
	_loop->on_idle = (handler == NULL)? NULL : OnIdle;
}


//---------------------------------------------------------------------
// set timer handler
//---------------------------------------------------------------------
void AsyncLoop::SetTimerHandler(std::function<void()> handler)
{
	_cb_timer = handler;
	_loop->on_timer = (handler == NULL)? NULL : OnTimer;
}



//=====================================================================
// AsyncEvent
//=====================================================================


//---------------------------------------------------------------------
// dtor
//---------------------------------------------------------------------
AsyncEvent::~AsyncEvent()
{
	if (_event.active) {
		async_event_stop(_loop, &_event);
	}
	_loop = NULL;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncEvent::AsyncEvent(CAsyncLoop *loop)
{
	assert(loop);
	async_event_init(&_event, EventCB, -1, 0);
	_event.user = this;
	_loop = loop;
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncEvent::AsyncEvent(AsyncLoop &loop)
{
	async_event_init(&_event, EventCB, -1, 0);
	_event.user = this;
	_loop = loop.GetLoop();
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// callback
//---------------------------------------------------------------------
void AsyncEvent::EventCB(CAsyncLoop *loop, CAsyncEvent *evt, int event)
{
	AsyncEvent *self = (AsyncEvent*)evt->user;
	if ((*self->_cb_ptr) != nullptr) {
		auto ref_ptr = self->_cb_ptr;
		(*ref_ptr)(event);
	}
}


//---------------------------------------------------------------------
// setup event callback
//---------------------------------------------------------------------
void AsyncEvent::SetCallback(std::function<void(int)> callback)
{
	(*_cb_ptr) = callback;
}


//---------------------------------------------------------------------
// mask can be one of ASYNC_EVENT_READ or ASYNC_EVENT_WRITE
// or ASYNC_EVENT_READ | ASYNC_EVENT_WRITE
// must be called without active
//---------------------------------------------------------------------
bool AsyncEvent::Set(int fd, int mask)
{
	int cc = async_event_set(&_event, fd, mask);
	return (cc == 0)? true : false;
}


//---------------------------------------------------------------------
// change event mask only, must be called without active
//---------------------------------------------------------------------
bool AsyncEvent::Modify(int mask)
{
	int cc = async_event_modify(&_event, mask);
	return (cc == 0)? true : false;
}


//---------------------------------------------------------------------
// start watching
//---------------------------------------------------------------------
int AsyncEvent::Start()
{
	if (_event.fd < 0) return -1000;
	return async_event_start(_loop, &_event);
}


//---------------------------------------------------------------------
// stop watching
//---------------------------------------------------------------------
int AsyncEvent::Stop()
{
	return async_event_stop(_loop, &_event);
}



//=====================================================================
// AsyncTimer
//=====================================================================

//---------------------------------------------------------------------
// dtor
//---------------------------------------------------------------------
AsyncTimer::~AsyncTimer()
{
	if (async_timer_active(&_timer)) {
		async_timer_stop(_loop, &_timer);
	}
	_loop = NULL;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncTimer::AsyncTimer(AsyncLoop &loop)
{
	async_timer_init(&_timer, TimerCB);
	_timer.user = this;
	_loop = loop.GetLoop();
	*_cb_ptr = nullptr;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncTimer::AsyncTimer(CAsyncLoop *loop)
{
	async_timer_init(&_timer, TimerCB);
	_timer.user = this;
	_loop = loop;
	*_cb_ptr = nullptr;
}


//---------------------------------------------------------------------
// timer callback
//---------------------------------------------------------------------
void AsyncTimer::TimerCB(CAsyncLoop *loop, CAsyncTimer *timer)
{
	AsyncTimer *self = (AsyncTimer*)timer->user;
	if ((*self->_cb_ptr) != nullptr) {
		std::shared_ptr<AsyncTimer::Callback> ref_ptr = self->_cb_ptr;
		(*ref_ptr)();
	}
}


//---------------------------------------------------------------------
// start timer, repeat forever if repeat <= 0
//---------------------------------------------------------------------
int AsyncTimer::Start(uint32_t period, int repeat)
{
	return async_timer_start(_loop, &_timer, period, repeat);
}


//---------------------------------------------------------------------
// stop timer
//---------------------------------------------------------------------
int AsyncTimer::Stop()
{
	return async_timer_stop(_loop, &_timer);
}


//---------------------------------------------------------------------
// setup callback
//---------------------------------------------------------------------
void AsyncTimer::SetCallback(std::function<void()> callback)
{
	*_cb_ptr = callback;
}



//=====================================================================
// AsyncSemaphore
//=====================================================================


//---------------------------------------------------------------------
// dtor
//---------------------------------------------------------------------
AsyncSemaphore::~AsyncSemaphore()
{
	async_sem_destroy(&_sem);
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncSemaphore::AsyncSemaphore(AsyncLoop &loop)
{
	async_sem_init(&_sem, NotifyCB);
	_sem.user = this;
	_loop = loop.GetLoop();
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncSemaphore::AsyncSemaphore(CAsyncLoop *loop)
{
	async_sem_init(&_sem, NotifyCB);
	_sem.user = this;
	_loop = loop;
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// C callback
//---------------------------------------------------------------------
void AsyncSemaphore::NotifyCB(CAsyncLoop *loop, CAsyncSemaphore *notify)
{
	AsyncSemaphore *self = (AsyncSemaphore*)(notify->user);
	if ((*self->_cb_ptr) != nullptr) {
		auto ref_ptr = self->_cb_ptr;
		(*ref_ptr)();
	}
}


//---------------------------------------------------------------------
// setup callback
//---------------------------------------------------------------------
void AsyncSemaphore::SetCallback(std::function<void()> callback)
{
	(*_cb_ptr) = callback;
}


//---------------------------------------------------------------------
// start watching
//---------------------------------------------------------------------
int AsyncSemaphore::Start()
{
	int cc = async_sem_start(_loop, &_sem);
	return cc;
}


//---------------------------------------------------------------------
// stop watching
//---------------------------------------------------------------------
int AsyncSemaphore::Stop()
{
	int cc = async_sem_stop(_loop, &_sem);
	return cc;
}


//---------------------------------------------------------------------
// post semaphore from another thread
//---------------------------------------------------------------------
int AsyncSemaphore::Post()
{
	int cc = async_sem_post(&_sem);
	return cc;
}


//=====================================================================
// AsyncPostpone
//=====================================================================


//---------------------------------------------------------------------
// dtor
//---------------------------------------------------------------------
AsyncPostpone::~AsyncPostpone()
{
	if (_postpone.active) {
		async_post_stop(_loop, &_postpone);
	}
	_loop = NULL;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncPostpone::AsyncPostpone(AsyncLoop &loop)
{
	async_post_init(&_postpone, InternalCB);
	_postpone.user = this;
	_loop = loop.GetLoop();
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncPostpone::AsyncPostpone(CAsyncLoop *loop)
{
	async_post_init(&_postpone, InternalCB);
	_postpone.user = this;
	_loop = loop;
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// internal callback
//---------------------------------------------------------------------
void AsyncPostpone::InternalCB(CAsyncLoop *loop, CAsyncPostpone *postpone)
{
	AsyncPostpone *self = (AsyncPostpone*)postpone->user;
	if ((*self->_cb_ptr) != NULL) {
		auto ref_ptr = self->_cb_ptr;
		(*ref_ptr)();
	}
}


//---------------------------------------------------------------------
// setup callback
//---------------------------------------------------------------------
void AsyncPostpone::SetCallback(std::function<void()> callback)
{
	(*_cb_ptr) = callback;
}


//---------------------------------------------------------------------
// start watching
//---------------------------------------------------------------------
int AsyncPostpone::Start()
{
	return async_post_start(_loop, &_postpone);
}


//---------------------------------------------------------------------
// stop watching
//---------------------------------------------------------------------
int AsyncPostpone::Stop()
{
	return async_post_stop(_loop, &_postpone);
}



//=====================================================================
// AsyncIdle
//=====================================================================


//---------------------------------------------------------------------
// dtor
//---------------------------------------------------------------------
AsyncIdle::~AsyncIdle()
{
	if (_idle.active) {
		async_idle_stop(_loop, &_idle);
	}
	_loop = NULL;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncIdle::AsyncIdle(AsyncLoop &loop)
{
	async_idle_init(&_idle, InternalCB);
	_idle.user = this;
	_loop = loop.GetLoop();
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncIdle::AsyncIdle(CAsyncLoop *loop)
{
	async_idle_init(&_idle, InternalCB);
	_idle.user = this;
	_loop = loop;
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// callback
//---------------------------------------------------------------------
void AsyncIdle::InternalCB(CAsyncLoop *loop, CAsyncIdle *idle)
{
	AsyncIdle *self = (AsyncIdle*)idle->user;
	if ((*self->_cb_ptr) != nullptr) {
		auto ref_ptr = self->_cb_ptr;
		(*ref_ptr)();
	}
}


//---------------------------------------------------------------------
// setup callback
//---------------------------------------------------------------------
void AsyncIdle::SetCallback(std::function<void()> callback)
{
	(*_cb_ptr) = callback;
}


//---------------------------------------------------------------------
// start watching
//---------------------------------------------------------------------
int AsyncIdle::Start()
{
	int cc = async_idle_start(_loop, &_idle);
	return cc;
}


//---------------------------------------------------------------------
// stop watching
//---------------------------------------------------------------------
int AsyncIdle::Stop()
{
	int cc = async_idle_stop(_loop, &_idle);
	return cc;
}



//=====================================================================
// AsyncOnce
//=====================================================================

//---------------------------------------------------------------------
// dtor
//---------------------------------------------------------------------
AsyncOnce::~AsyncOnce()
{
	if (_once.active) {
		async_once_stop(_loop, &_once);
	}
	_loop = NULL;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncOnce::AsyncOnce(AsyncLoop &loop)
{
	async_once_init(&_once, InternalCB);
	_once.user = this;
	_loop = loop.GetLoop();
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncOnce::AsyncOnce(CAsyncLoop *loop)
{
	async_once_init(&_once, InternalCB);
	_once.user = this;
	_loop = loop;
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// setup callback
//---------------------------------------------------------------------
void AsyncOnce::SetCallback(std::function<void()> callback)
{
	(*_cb_ptr) = callback;
}


//---------------------------------------------------------------------
// callback
//---------------------------------------------------------------------
void AsyncOnce::InternalCB(CAsyncLoop *loop, CAsyncOnce *once)
{
	AsyncOnce *self = (AsyncOnce*)once->user;
	if ((*self->_cb_ptr) != nullptr) {
		auto ref_ptr = self->_cb_ptr;
		(*ref_ptr)();
	}
}


//---------------------------------------------------------------------
// start watching
//---------------------------------------------------------------------
int AsyncOnce::Start()
{
	int cc = async_once_start(_loop, &_once);
	return cc;
}


//---------------------------------------------------------------------
// stop watching
//---------------------------------------------------------------------
int AsyncOnce::Stop()
{
	int cc = async_once_stop(_loop, &_once);
	return cc;
}



//=====================================================================
// AsyncSubscribe
//=====================================================================

//---------------------------------------------------------------------
// dtor
//---------------------------------------------------------------------
AsyncSubscribe::~AsyncSubscribe()
{
	if (_subscribe.active) {
		async_sub_stop(_loop, &_subscribe);
	}
	_loop = NULL;
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncSubscribe::AsyncSubscribe(CAsyncLoop *loop)
{
	_loop = loop;
	async_sub_init(&_subscribe, InternalCB);
	_subscribe.user = this;
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// ctor
//---------------------------------------------------------------------
AsyncSubscribe::AsyncSubscribe(AsyncLoop &loop)
{
	_loop = loop.GetLoop();
	async_sub_init(&_subscribe, InternalCB);
	_subscribe.user = this;
	(*_cb_ptr) = nullptr;
}


//---------------------------------------------------------------------
// setup callback
//---------------------------------------------------------------------
void AsyncSubscribe::SetCallback(std::function<int(const void *data, int size)> callback)
{
	(*_cb_ptr) = callback;
}


//---------------------------------------------------------------------
// internal callback
//---------------------------------------------------------------------
int AsyncSubscribe::InternalCB(CAsyncLoop *loop, CAsyncSubscribe *sub, 
		const void *data, int size)
{
	AsyncSubscribe *self = (AsyncSubscribe*)sub->user;
	if ((*self->_cb_ptr) != nullptr) {
		auto ref_ptr = self->_cb_ptr;
		int hr = (*ref_ptr)(data, size);
		return hr;
	}
	return 0; // no callback
}


//---------------------------------------------------------------------
// start subscribing to a topic
//---------------------------------------------------------------------
int AsyncSubscribe::Start(int topic)
{
	return async_sub_start(_loop, &_subscribe, topic);
}


//---------------------------------------------------------------------
// stop subscribing
//---------------------------------------------------------------------
int AsyncSubscribe::Stop()
{
	return async_sub_stop(_loop, &_subscribe);
}



NAMESPACE_END(System);




