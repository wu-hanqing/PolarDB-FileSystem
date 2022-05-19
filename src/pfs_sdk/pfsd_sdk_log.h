#ifndef PFSD_SDK_LOG_H
#define PFSD_SDK_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*pfsd_log_func_t)(const char *filename,
	const char *func, int line,
	int priority, const char *fmt, va_list);

void pfsd_sdk_set_log_func(pfsd_log_func_t f);

enum {
	PFSD_SDK_INFO = 0,
	PFSD_SDK_WARNING,
	PFSD_SDK_ERROR,
	PFSD_SDK_FATAL,
	PFSD_NUM_SEVERITIES
};

void pfsd_sdk_log(const char *filename, const char *func, int line,
        int priority, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
