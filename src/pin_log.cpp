#include <stdio.h>
#include <assert.h>
#include <stdexcept>
#include <unistd.h>
#include <sys/types.h>
#include "pin-log.H"

/*! \brief Initialize PinLogPerProcess logger.
 */
PinLogPerProcess::PinLogPerProcess(const char *ffmt)
{
	this->pin_initialized = FALSE;
	this->file_fmt = string(ffmt);
	if (!PIN_MutexInit(&this->mutex))
		throw std::runtime_error("could not initialize mutex");
	this->data.file = NULL;
	this->ctx_update();
	this->pin_init();
}

/*! \brief Destroy PinLogPerProcess logger.
 */
PinLogPerProcess::~PinLogPerProcess()
{
	log_ctx_t *data = &this->data;
	PIN_MutexLock(&this->mutex);
	if (data->file != NULL && fclose(data->file))
		throw std::runtime_error("error closing log file");
	data->file = NULL;
	PIN_MutexUnlock(&this->mutex);
	PIN_MutexFini(&this->mutex);
}

/*! \brief Initialize PinLogPerThread logger.
 */
PinLogPerThread::PinLogPerThread(const char *ffmt)
{
	this->pin_initialized = FALSE;
	this->file_fmt = string(ffmt);
	this->tlsk = PIN_CreateThreadDataKey(NULL);
	this->ctx_update();
	this->pin_init();
}

/*! \brief Destroy PinLogPerThread logger.
 */
PinLogPerThread::~PinLogPerThread()
{
	THREADID tid = PIN_ThreadId();
	log_ctx_t *data = static_cast<log_ctx_t *>(PIN_GetThreadData(this->tlsk, tid));

	if (data != NULL) {
		//TODO: object is shared by multiple threads
		//      probably we'll have to keep track of tids that use it, so all files are closed here
		if (data->file != NULL && fclose(data->file))
			throw std::runtime_error("error closing log file");
		data->file = NULL;
		PIN_SetThreadData(this->tlsk, NULL, tid);
	}

	PIN_DeleteThreadDataKey(this->tlsk);
}

/*! \brief Updates the logging object to reflect its current context.
 */
void PinLogPerProcess::ctx_update()
{
	char path[PINLOG_MAXPATHLEN];
	std::string id_cur = this->makeid();
	log_ctx_t *data = &this->data;

	if (data->file != NULL && id_cur == data->id) {
		// context not changed
		return;
	}

	// update context
	PIN_MutexLock(&this->mutex);
	if (data->file != NULL && fclose(data->file))
		throw std::runtime_error("error closing log file");
	data->id = id_cur;
	data->pid = PIN_GetPid();
	data->threadid = PIN_ThreadId();
	snprintf(path, PINLOG_MAXPATHLEN, this->file_fmt.c_str(), data->id.c_str());
	data->file_path = std::string(path);
	data->file = fopen(data->file_path.c_str(), "w");
	if (!data->file)
		throw std::runtime_error("could not open log file for writing");
	data->started = FALSE;
	PIN_MutexUnlock(&this->mutex);
}

/*! \brief Updates the logging object to reflect its current context.
 */
void PinLogPerThread::ctx_update()
{
	char path[PINLOG_MAXPATHLEN];
	std::string id_cur = this->makeid();
	int pid = PIN_GetPid();
	THREADID threadid = PIN_ThreadId();
	log_ctx_t *data = static_cast<log_ctx_t *>(PIN_GetThreadData(this->tlsk, threadid));

	if (data == NULL) {
		// initialization of context required
		data = new log_ctx_t;
		data->file = NULL;
		PIN_SetThreadData(this->tlsk, data, threadid);
	}
	else if (id_cur != data->id) {
		if (pid == data->pid) {
			// this shouldn't really happen
			this->_logts("ABOUT TO HIT ASSERTION\n");
			assert(1);
		}

		// if pid != data->pid, we've just been forked
		if (data->file != NULL && fclose(data->file))
			throw std::runtime_error("error closing log file");
	}
	else {
		// context not changed
		return;
	}

	// update context
	data->id = string(id_cur);
	data->pid = pid;
	data->threadid = threadid;
	snprintf(path, PINLOG_MAXPATHLEN, this->file_fmt.c_str(), data->id.c_str());
	data->file_path = std::string(path);
	data->file = fopen(data->file_path.c_str(), "w");
	if (!data->file)
		throw std::runtime_error("could not open log file for writing");
	data->started = FALSE;
}

void PinLogPerProcess::pin_fork(THREADID threadid, const CONTEXT *ctxt, VOID *v)
{
	PinLogPerProcess *_this = static_cast<PinLogPerProcess *>(v);
	_this->ctx_update();
	_this->_logts("process started pid:%d ppid:%d tid:%d ptid:%d\n", PIN_GetPid(), getppid(), PIN_GetTid(), PIN_GetParentTid());
}

void PinLogPerThread::pin_fork(THREADID threadid, const CONTEXT *ctxt, VOID *v)
{
	PinLogPerThread *_this = static_cast<PinLogPerThread *>(v);
	_this->ctx_update();
	_this->_logts("process started pid:%d ppid:%d tid:%d ptid:%d\n", PIN_GetPid(), getppid(), PIN_GetTid(), PIN_GetParentTid());
}

void PinLogPerThread::pin_thread_start(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	PinLogPerThread *_this = static_cast<PinLogPerThread *>(v);
	_this->ctx_update();
	_this->_logts("thread started pid:%d ppid:%d tid:%d ptid:%d\n", PIN_GetPid(), getppid(), PIN_GetTid(), PIN_GetParentTid());
}

void PinLogPerThread::pin_thread_fini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	PinLogPerThread *_this = static_cast<PinLogPerThread *>(v);
	log_ctx_t *data = static_cast<log_ctx_t *>(PIN_GetThreadData(_this->tlsk, tid));

	if (data != NULL) {
		_this->_logts("thread finished pid:%d tid:%d\n", PIN_GetPid(), PIN_GetTid());
		if (data->file != NULL && fclose(data->file))
			throw std::runtime_error("error closing log file");
		data->file = NULL;
		delete data;
		PIN_SetThreadData(_this->tlsk, NULL, tid);
	}
}
// vim: noet:ts=4:sts=4:sw=4:
