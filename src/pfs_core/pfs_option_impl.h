/*
 * Copyright (c) 2017-2021, Alibaba Group Holding Limited
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _PFS_OPTION_IMPL_H_
#define _PFS_OPTION_IMPL_H_

#include "pfs_util.h"

#define PFS_OPT_DISABLE	0
#define PFS_OPT_ENABLE	1

#define PFS_MAX_OPTLEN	128
#define	MAX_NORPHAN	500

typedef enum pfs_option_kind {
    OPT_INT, OPT_LONG, OPT_STR
} pfs_option_kind_t;

typedef struct msg_header msg_header_t;
typedef struct msg_option msg_option_t;

typedef bool	pfs_option_checkfunc_t(int64_t);

typedef struct pfs_option {
	const char	*o_file;
	int		o_line;
	const char	*o_name;
	pfs_option_kind_t	o_kind;
	void    	*o_valuep;		/* pointer of option */
	const char 	*o_default;		/* default value */
	bool		(*o_check)(struct pfs_option *, const char*); /* check value */
    	bool        	(*o_store)(struct pfs_option *, const char *); /* store value */
} pfs_option_t;

#define PFS_OPTION_REG(name, def, check_func)				\
	static pfs_option_t opt_##name __attribute__((used)) = {	\
		__FILE__,						\
		__LINE__,						\
		#name,							\
		OPT_LONG,						\
		&name,							\
		def,							\
		check_func,						\
		pfs_store_generic                  			\
	};								\
	static pfs_option_t *opt_##name##_ptr DATA_SET_ATTR(_pfsopt)	\
	    = &opt_##name

#define PFS_OPTION_REG2(name, var, _kind, def, check_func)		\
	static pfs_option_t opt_##name __attribute__((used)) = {	\
		__FILE__,						\
		__LINE__,						\
		#name,							\
		_kind,							\
		&var,							\
		def,							\
		check_func,						\
		pfs_store_generic                  			\
	};								\
	static pfs_option_t *opt_##name##_ptr DATA_SET_ATTR(_pfsopt)	\
	    = &opt_##name


bool	pfs_check_lval_normal(struct pfs_option *opt, const char *data);
bool	pfs_check_lval_switch(struct pfs_option *opt, const char *data);
bool	pfs_store_generic(struct pfs_option *opt, const char *data);

int	pfs_option_handle(int sock, msg_header_t *mh, msg_option_t *msgopt);

#endif
