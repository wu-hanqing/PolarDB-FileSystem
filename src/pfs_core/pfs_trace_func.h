#ifndef PFS_TRACE_FUNC_H
#define PFS_TRACE_FUNC_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
	PFS_TRACE_FATAL,
	PFS_TRACE_ERROR,
	PFS_TRACE_WARN,
	PFS_TRACE_INFO,
	PFS_TRACE_DBG,
	PFS_TRACE_DEBUG	= PFS_TRACE_DBG,
	PFS_TRACE_VERB
};

void    pfs_vtrace(int level, const char *file, const char *func, int line,
	const char *fmt, ...);

typedef void (*pfs_trace_func_t)(int level, const char *filename,
	const char *func, int line, const char *fmt, va_list ap);
                                                                                
void	pfs_set_trace_func(pfs_trace_func_t func);
pfs_trace_func_t pfs_get_trace_func();
int	pfs_set_trace_level(int);
int	pfs_get_trace_level();

#ifdef __cplusplus
}
#endif

#endif // PFS_TRACE_FUNC_H
