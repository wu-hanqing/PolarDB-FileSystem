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

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "pfs_admin.h"
#include "pfs_option.h"
#include "pfs_trace.h"
#include "pfs_config.h"

#include "pfs_errno_wrapper.h"

/*
 * define the config option which need restart to make effect
 */
#define LOAD_THREAD_COUNT "loadthread_count"
#define FILE_MAX_NFD "file_max_nfd"

bool
pfs_check_lval_normal(struct pfs_option *, const char *data)
{
	int64_t val;

	if (pfs_strtol(data, &val))
		return false;

	if (val <= 0)
		return false;
	return true;
}

/* 0 or 1 */
bool
pfs_check_lval_switch(struct pfs_option *, const char *data)
{
	int64_t val;

	if (pfs_strtol(data, &val))
		return false;
	if (val != PFS_OPT_ENABLE && val != PFS_OPT_DISABLE)
		return false;
	return true;
}

bool
pfs_option_store_generic(struct pfs_option *opt, const char *data)
{
	int kind;
	int64_t lval;
	int32_t ival;

	switch((kind = PFS_OPT_KIND(opt->o_flags))) {
	case OPT_INT:
		if (pfs_strtoi(data, &ival))
			return false;
		*(int *)opt->o_valuep = ival;
		break;
	case OPT_LONG:
		if (pfs_strtol(data, &lval))
			return false;
		*(int64_t *)opt->o_valuep = lval;
		break;
	case OPT_STR:
		free(*((char **)opt->o_valuep));
                *((char **)opt->o_valuep) = data ? strdup(data) : NULL;
		break;
	default:
		pfs_etrace("can not handle option value type: %d\n", kind);
		break;
	}
	return true;
}

bool
pfs_option_release_generic(struct pfs_option *opt)
{
	int kind;

	switch((kind = PFS_OPT_KIND(opt->o_flags))) {
	case OPT_STR:
		free(*((char **)opt->o_valuep));
                *((char **)opt->o_valuep) = NULL;
		break;
	}
	return true;
}

static int
pfs_option_get_str(pfs_option_t *opt, bool pretty, char buf[], size_t len)
{
	int kind = 0;

	buf[0] = 0;
	switch((kind = PFS_OPT_KIND(opt->o_flags))) {
	case OPT_INT:
		if (!pretty)
			snprintf(buf, len, "%d", *(int *)opt->o_valuep);
		else
			snprintf(buf, len, "%-10d", *(int *)opt->o_valuep);
		break;
	case OPT_LONG:
		if (!pretty)
			snprintf(buf, len, "%ld", *(long *)opt->o_valuep);
		else
			snprintf(buf, len, "%-10ld", *(long *)opt->o_valuep);
		break;
	case OPT_STR: {
		char *p = *(char **)opt->o_valuep;
		snprintf(buf, len, "%s", p ? p : "");
		}
		break;
	default:
		pfs_etrace("can not understand value type: %d\n", kind);
		return -1;
	}
	return 0;
}

static int
pfs_option_get_default_str(pfs_option_t *opt, bool pretty, char buf[], size_t len)
{
	int kind = 0;

	buf[0] = 0;
	switch((kind = PFS_OPT_DVAL_KIND(opt->o_flags))) {
	case OPT_INT:
		if (!pretty)
			snprintf(buf, len, "%d", (int)opt->o_default);
		else
			snprintf(buf, len, "%-10d", (int)opt->o_default);
		break;
	case OPT_LONG:
		if (!pretty)
			snprintf(buf, len, "%ld", (long)opt->o_default);
		else
			snprintf(buf, len, "%-10ld", (long)opt->o_default);
		break;
	case OPT_CSTR: {
		char *p = (char *)(void *)opt->o_default;
		snprintf(buf, len, "%s", p ? p : "");
		}
		break;
	default:
		pfs_etrace("can not understand default value type: %d\n", kind);
		return -1;
	}
	return 0;
}

static int
pfs_option_list(admin_buf_t *ab)
{
	DATA_SET_DECL(pfs_option, _pfsopt);
	pfs_option_t **optp, *opt;
	char buf[1024], dval[1024];
	int n;

	n = pfs_adminbuf_printf(ab, "option\t\t\t\t\tcurrent\t\tdefault\n");
	if (n < 0)
		return n;

	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;

		n = pfs_adminbuf_printf(ab, "%-36s\t", opt->o_name);
		if (n < 0)
			return n;
		pfs_option_get_str(opt, true, buf, sizeof(buf));
		pfs_option_get_default_str(opt, true, dval, sizeof(dval));
		pfs_adminbuf_printf(ab, "%s\t%s\n", buf, dval);
	}
	return 0;
}

/*
 * add more protection when dukang working incorrect
 */
static bool
is_effect_after_restart_option(const char *option_name)
{
	if ((strcmp(option_name, LOAD_THREAD_COUNT) == 0) ||
	    (strcmp(option_name, FILE_MAX_NFD) == 0)) {
		return true;
	}
	return false;
}

int
pfs_option_set(const char *name, const char *val)
{
	DATA_SET_DECL(pfs_option, _pfsopt);
    	char buf[1024];
	pfs_option_t **optp, *opt;
	int n;
	bool flag = false;

	if (is_effect_after_restart_option(name)) {
		pfs_etrace("change %s should restart to take effect\n", name);
		return -EPERM;
	}

	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;
		if (strcmp(name, opt->o_name) != 0)
			continue;

		if (opt->o_check && !opt->o_check(opt, val)) {
			pfs_etrace("option %s new value is invalid\n", opt->o_name);
			return -EINVAL;
		}

		pfs_option_get_str(opt, false, buf, sizeof(buf));
		bool rc = opt->o_store(opt, val);
		pfs_itrace("option %s is changing from '%s' to '%s', %s\n",
			   opt->o_name, buf, val, rc ? "success":"failure");

		flag = true;
		break;
	}

	if (!flag) {
		pfs_etrace("option %s is not found\n", name);
		return -EINVAL;
	}

	return 0;
}

int
pfs_option_set_int(const char *name, int val)
{
	char buf[128];
	snprintf(buf, sizeof(buf), "%d", val);
	return pfs_option_set(name, buf);
}

int
pfs_option_set_long(const char *name, long val)
{
	char buf[128];
	snprintf(buf, sizeof(buf), "%ld", val);
	return pfs_option_set(name, buf);
}

static int
pfs_option_set_ab(const char *name, const char *val, admin_buf_t *ab)
{
	DATA_SET_DECL(pfs_option, _pfsopt);
    	char buf[1024];
	pfs_option_t **optp, *opt;
	int n;
	bool flag = false;

	if (is_effect_after_restart_option(name)) {
		pfs_itrace("change %s should restart to take effect\n", name);
		n = pfs_adminbuf_printf(ab, "%s should restart to take effect!", name);
		return n < 0 ? n : 0;
	}

	bool rc = false;
	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;
		if (strcmp(name, opt->o_name) != 0)
			continue;

		if (opt->o_check && !opt->o_check(opt, val)) {
			pfs_etrace("option %s new value is invalid\n", opt->o_name);
			ERR_RETVAL(EINVAL);
		}

		pfs_option_get_str(opt, false, buf, sizeof(buf));
		rc = opt->o_store(opt, val);
		pfs_itrace("option %s is changing from '%s' to '%s', %s\n",
			   opt->o_name, buf, val, rc ? "success":"failure");
		flag = true;
		break;
	}

	if (!flag) {
		pfs_etrace("option %s is not found\n", name);
		n = pfs_adminbuf_printf(ab, "option %s is not found\n", name);
		ERR_RETVAL(EINVAL);
	} else {
		n = pfs_adminbuf_printf(ab, "%s\n", rc ? "succeed":"failure");
	}
	return n < 0 ? n : 0;
}

static void
pfs_option_update_value(const char *name, const char *value, void *data)
{
	char buf[1024];
	int n = 0;
	int64_t ival = 0;

	admin_buf_t *ab = (admin_buf_t*)data;

	if (data && is_effect_after_restart_option(name)) {
		pfs_itrace("change %s should restart to take effect\n", name);
		pfs_adminbuf_printf(ab, "%s should restart to take effect!\n", name);
		return;
	}

	DATA_SET_DECL(pfs_option, _pfsopt);
	pfs_option_t **optp, *opt;
	bool flag = false;

	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;
		if (strcmp(name, opt->o_name) != 0)
			continue;
		if (opt->o_check && !opt->o_check(opt, value)) {
			pfs_etrace("option %s new value '%s' is invalid\n", opt->o_name, value);
			if (ab)
				pfs_adminbuf_printf(ab,"option %s new value '%s' is invalid\n",
                                    opt->o_name, value);
			return;
		}

		pfs_option_get_str(opt, false, buf, sizeof(buf));

		bool rc = opt->o_store(opt, value);

		pfs_itrace("option %s is changing from '%s' to '%s', %s\n",
			    opt->o_name, buf, value, rc ? "success":"failure");

		if (ab) {
			pfs_option_get_default_str(opt, false, buf, sizeof(buf));
			n = pfs_adminbuf_printf(ab,"%-36s\t%s\t%s\t%s\n",
				    opt->o_name, value, buf,
				    rc ? "success":"failure");
			if (n < 0)
				return;
		}

		flag = true;
		break;
	}
	if (!flag) {
		pfs_itrace("find unknown option name %s\n", name);
		if (ab)
			pfs_adminbuf_printf(ab, "%-36s\t%s\t%-10ld\tn/a\n",
					    name, value, 0);
	}
}

static int
pfs_option_reload(admin_buf_t *ab)
{
	int ret = 0;
	int n = 0;

	n = pfs_adminbuf_printf(ab, "loading config file from path %s\n"
		    "option\t\t\t\t\tnew\t\tdefault\t\tresult\n", DEFAULT_CONFIG_PATH);
	if (n < 0) {
		pfs_etrace("init return message fail\n");
		ERR_RETVAL(EINVAL);
	}

	ret = pfs_config_load(NULL, pfs_option_update_value, ab);
	if (ret != CONFIG_OK)
		pfs_etrace("pfs config load err, errno %d\n", ret);

	return ret;
}

__attribute__((constructor))
int
pfs_option_set_default(void)
{
	DATA_SET_DECL(pfs_option, _pfsopt);
	pfs_option_t **optp, *opt;
	int ret = 0;
	char buf[1024];

	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;
		pfs_option_get_default_str(opt, false, buf, sizeof(buf));

		if (!opt->o_store(opt, buf)) {
			pfs_etrace("option %s can not set default value '%s'",
				opt->o_name, buf);
			ret = -1;
		}
	}

	return ret;
}

__attribute__((destructor))
int
pfs_option_release(void)
{
	DATA_SET_DECL(pfs_option, _pfsopt);
	pfs_option_t **optp, *opt;

	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;
		pfs_option_release_generic(opt);
	}

	return 0;
}

/*
 *  update pfs option value
 *  1.after received config update command
 *  2.pfs was run at the first time
 */
int
pfs_option_init(const char *config_path)
{
	int ret = 0;

	ret = pfs_config_load(config_path, pfs_option_update_value, NULL);
	if (ret != CONFIG_OK)
		pfs_etrace("pfs config load err, errno %d\n", ret);

	return ret;
}

int
pfs_option_handle(int sock, msg_header_t *mh, msg_option_t *msgopt)
{
	int err;
	admin_buf_t *ab;

	ab = pfs_adminbuf_create(sock, mh->mh_type, mh->mh_op + 1, 32 << 10);
	if (ab == NULL) {
		ERR_RETVAL(ENOMEM);
	}
	pfs_itrace("pfs admin enter option handle, opid %d\n", mh->mh_op);

	switch (mh->mh_op) {
	case OPTION_LIST_REQ:
		err = pfs_option_list(ab);
		break;

	case OPTION_SET_REQ:
		err = pfs_option_set_ab(msgopt->o_name, msgopt->o_value, ab);
		break;

	case OPTION_RELOAD_REQ:
		err = pfs_option_reload(ab);
		break;

	default:
		err = -1;
		break;
	}
	pfs_adminbuf_destroy(ab, err);

	return err;
}
