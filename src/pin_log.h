#ifndef PIN_LOG_H
#define PIN_LOG_H
/*! \file pin-log.H
 *  \brief Classes wrapping logging functionality for Pin Tools.
 */
#include <stdio.h>
#include <assert.h>
#include <sstream>
#include <pin.H>

// For some reason, PIN does not allow us to use std::to_string().
// TODO: Put this in a more appropriate file, e.g., a utils.
template < class T >
std::string my_to_string( const T& v )
{
    std::ostringstream oss;
	oss << v;
	return oss.str();
}

//*******************************************************************
// Logging macros
//*******************************************************************
/*! \def PINLOG_MAXPATHLEN
 *  \brief Maximum path length for the log file.
 *
 *  \def PINLOG_MAXIDLEN
 *  \brief Maximum length for the unique identifier part of the log file.
 */
#define PINLOG_MAXPATHLEN 256
#define PINLOG_MAXIDLEN 32

#if 0
#define NDEBUG
#define PRINTLN printf("--------------------> %s:%d\n", __FILE__, __LINE__)
#define PRINTID printf("--------------------> %s:%d pid:%d tid:%d\n", __FILE__, __LINE__, PIN_GetPid(), PIN_GetTid())
#endif

//*******************************************************************
// Logging supporting types
//*******************************************************************
typedef struct {
	std::string id;			//!< Context-specific id.
	int pid;				//!< Pid of the process where this log was initialized.
	THREADID threadid;		//!< Thread id of the thread were this log was initialized.
	std::string file_path;	//!< The path of the log file.
	FILE *file;				//!< Log file object.
	BOOL started;			//!< Logging has started.
} log_ctx_t;

//*******************************************************************
// Logging classes
//*******************************************************************
/*! \brief Base logger class.
 */
class PinLog {
	public:
		virtual ~PinLog() {};
		virtual void logts(const char *fmt, ...) = 0;
		virtual void log(const char *fmt, ...) = 0;
		virtual void lock() = 0;
		virtual void unlock() = 0;
		virtual BOOL has_started() = 0;
		void toggle();

	protected:
		virtual void _logts(const char *fmt, ...) = 0;	//!< Log for internal class use. Does not affect the \c has_started flag.
		virtual std::string makeid() = 0;	//!< Create a unique identifier for the log file.
		virtual void ctx_update() = 0;		//!< Update the logger to reflect its current context.
		virtual void pin_init() = 0;		//!< Initialize Pin hooks for logging.
		BOOL pin_initialized;				//!< Flag showing whether Pin hooks have been initialized.
		std::string file_fmt;				//!< \c printf format for constructing the PinLog#file_path.
		BOOL log_enabled = TRUE;			//<! \c toggles logging on/off (???where do we use this???)
};

/*! \brief Logging class for per-process log files.
 */
class PinLogPerProcess: public PinLog {
	public:
		PinLogPerProcess(const char *ffmt);
		virtual ~PinLogPerProcess();
		void logts(const char *fmt, ...) override;
		void log(const char *fmt, ...) override;
		void lock() override;
		void unlock() override;
		BOOL has_started() override;

	protected:
		void _logts(const char *fmt, ...) override;
		void ctx_update() override;
		std::string makeid() override;
		void pin_init() override;
		log_ctx_t data;						//!< Logger context information.
		PIN_MUTEX mutex;					//!< Mutex used for thread safety.

	private:
		static void pin_fork(THREADID threadid, const CONTEXT *ctxt, VOID *v);	//!< Pin callback function, to be installed by PinLogPerProcess::pin_init().
};

/*! \brief Logging class for per-thread log files.
 */
class PinLogPerThread: public PinLog {
	public:
		PinLogPerThread(const char *ffmt);
		virtual ~PinLogPerThread();
		void logts(const char *fmt, ...) override;
		void log(const char *fmt, ...) override;
		void lock() override;
		void unlock() override;
		BOOL has_started() override;

	protected:
		void _logts(const char *fmt, ...) override;
		void ctx_update() override;
		std::string makeid() override;
		void pin_init() override;
		TLS_KEY tlsk;						//!< Key for accessing the TLS data.

	private:
		static void pin_fork(THREADID threadid, const CONTEXT *ctxt, VOID *v);					//!< Pin callback function, to be installed by PinLogPerProcess::pin_init().
		static void pin_thread_start(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v);		//!< Pin callback function, to be installed by PinLogPerProcess::pin_init().
		static void pin_thread_fini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v);	//!< Pin callback function, to be installed by PinLogPerProcess::pin_init().
};



//*******************************************************************
// Inlines
//*******************************************************************
/*! \brief Toggles logging on/off.
 */
inline void PinLog::toggle()
{
	this->log_enabled = this->log_enabled ? FALSE : TRUE;
}

/*! \brief Log a single line - thread safe.
 *  Thread safety achieved by aquiring the object's PinLog#mutex lock.
 */
inline void PinLogPerProcess::logts(const char *fmt, ...)
{
	if (!this->log_enabled) return;

	va_list args;
	log_ctx_t *data = &this->data;

	va_start(args, fmt);
	PIN_MutexLock(&this->mutex);
	vfprintf(data->file, fmt, args);
	fflush(data->file);
	PIN_MutexUnlock(&this->mutex);
	va_end(args);

	fflush(data->file);
	this->data.started = TRUE;
}

/*! \brief Log a single line - thread safe - intenal class use.
 *  \c has_started flag will not be affected.
 */
inline void PinLogPerProcess::_logts(const char *fmt, ...)
{
	if (!this->log_enabled) return;

	va_list args;
	log_ctx_t *data = &this->data;

	va_start(args, fmt);
	PIN_MutexLock(&this->mutex);
	vfprintf(data->file, fmt, args);
	fflush(data->file);
	PIN_MutexUnlock(&this->mutex);

    fflush(data->file);
	va_end(args);
}

/*! \brief Log a single line - thread safe.
 *  Thread safety achieved is implicit because there is one log per thread.
 */
inline void PinLogPerThread::logts(const char *fmt, ...)
{
	if (!this->log_enabled) return;

	va_list args;
	log_ctx_t *data = static_cast<log_ctx_t *>(PIN_GetThreadData(this->tlsk, PIN_ThreadId()));
	assert(data != NULL);

	va_start(args, fmt);
	vfprintf(data->file, fmt, args);
	fflush(data->file);
	va_end(args);
	data->started = TRUE;
}

/*! \brief Log a single line - thread safe - internal class use.
 *  \c has_started flag will not be affected.
 */
inline void PinLogPerThread::_logts(const char *fmt, ...)
{
	if (!this->log_enabled) return;

	va_list args;
	log_ctx_t *data = static_cast<log_ctx_t *>(PIN_GetThreadData(this->tlsk, PIN_ThreadId()));
	assert(data != NULL);

	va_start(args, fmt);
	vfprintf(data->file, fmt, args);
	fflush(data->file);
	va_end(args);
}

/*! \brief Log a single line.
 *  Thread-safety not guaranteed - it is left up to the caller.
 */
inline void PinLogPerProcess::log(const char *fmt, ...)
{
	if (!this->log_enabled) return;

	va_list args;
	log_ctx_t *data = &this->data;

	va_start(args, fmt);
	vfprintf(data->file, fmt, args);
	fflush(data->file);
	va_end(args);

	fflush(data->file);
}

/*! \brief Log a single line.
 *  Thread-safety not guaranteed - it is left up to the caller.
 */
inline void PinLogPerThread::log(const char *fmt, ...)
{
	if (!this->log_enabled) return;

	va_list args;
	log_ctx_t *data = static_cast<log_ctx_t *>(PIN_GetThreadData(this->tlsk, PIN_ThreadId()));
	assert(data != NULL);

	va_start(args, fmt);
	vfprintf(data->file, fmt, args);
	fflush(data->file);
	va_end(args);

	fflush(data->file);
}

/*! \brief Acquire the object's lock.
 */
inline void PinLogPerProcess::lock()
{
	PIN_MutexLock(&this->mutex);
}

/*! \brief Acquire the object's lock.
 *  For PinLogPerThread no lock is required, so the method does nothing.
 */
inline void PinLogPerThread::lock()
{
	// dummy - provided for API compatibility
}

/*! \brief Release the object's lock.
 */
inline void PinLogPerProcess::unlock()
{
	log_ctx_t *data = &this->data;
	fflush(data->file);
	PIN_MutexUnlock(&this->mutex);
}

/*! \brief Release the object's lock.
 *  For PinLogPerThread no lock is required, so the method only flushes.
 */
inline void PinLogPerThread::unlock()
{
	log_ctx_t *data = static_cast<log_ctx_t *>(PIN_GetThreadData(this->tlsk, PIN_ThreadId()));
	assert(data != NULL);
	fflush(data->file);
}

/*! \brief Returns whether the first line has been logged by the pin tool.
 */
inline BOOL PinLogPerProcess::has_started()
{
	log_ctx_t *data = &this->data;
	assert(data != NULL);
	return data->started;
}

/*! \brief Returns whether the first line has been logged by the pin tool.
 */
inline BOOL PinLogPerThread::has_started()
{
	log_ctx_t *data = static_cast<log_ctx_t *>(PIN_GetThreadData(this->tlsk, PIN_ThreadId()));
	assert(data != NULL);
	return data->started;
}

/*! \brief Creates a context-specific file-id - unique per process.
 */
inline std::string PinLogPerProcess::makeid()
{
	return my_to_string(PIN_GetPid());
}

/*! \brief Creates a context-specific file-id - unique per thread.
 */
inline std::string PinLogPerThread::makeid()
{
    std::string ret = my_to_string(PIN_GetPid()) + "." + my_to_string(PIN_GetTid());
    return ret;
}

/*! \brief Do Pin-specific initializations (set callbacks etc.)
 */
inline void PinLogPerProcess::pin_init()
{
	if (this->pin_initialized) return;
	PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, this->pin_fork, this);
	this->pin_initialized = TRUE;
}

/*! \brief Do Pin-specific initializations (set callbacks etc.)
 */
inline void PinLogPerThread::pin_init()
{
	if (this->pin_initialized) return;
	PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, this->pin_fork, this);
	PIN_AddThreadStartFunction(this->pin_thread_start, this);
	PIN_AddThreadFiniFunction(this->pin_thread_fini, this);
	this->pin_initialized = TRUE;
}
#endif


#if 0
Available identifiers for threads:
    i. PIN_GetTid() - This returns the OS thread id.
       In Linux this is similar to a process id in Linux.
   ii. PIN_ThreadUid() - A 64 bit unique id for the thread.
  iii. PIN_ThreadId() - A sequential thread id for the current process.
#endif
// vim: noet:ts=4:sts=4:sw=4:
