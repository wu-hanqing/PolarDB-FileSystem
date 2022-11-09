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

#include <string>

#include "pfs_admin.h"
#include "pfs_option.h"
#include "pfs_trace.h"
#include "pfs_config.h"

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
pfs_store_generic(struct pfs_option *opt, const char *data)
{
	int64_t val;

	switch(opt->o_kind) {
	case OPT_INT:
		if (pfs_strtol(data, &val))
			return false;
		*(int *)opt->o_valuep = val;
		break;
	case OPT_LONG:
		if (pfs_strtol(data, &val))
			return false;
		*(int64_t *)opt->o_valuep = val;
		break;
	case OPT_STR:
		*(std::string *)opt->o_valuep = data;
		break;
	}
	return true;
}

static int
pfs_option_list(admin_buf_t *ab)
{
	DATA_SET_DECL(pfs_option, _pfsopt);
	pfs_option_t **optp, *opt;
	int n;

	n = pfs_adminbuf_printf(ab, "option\t\t\t\t\tcurrent\t\tdefault\n");
	if (n < 0)
		return n;

	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;

		n = pfs_adminbuf_printf(ab, "%-36s\t", opt->o_name);
		if (n < 0)
			return n;
		switch(opt->o_kind) {
		case OPT_INT:
			pfs_adminbuf_printf(ab, "%-10d\t", *(int *)(opt->o_valuep));
			pfs_adminbuf_printf(ab, "%s\n", opt->o_default);
			break;
		case OPT_LONG:
			pfs_adminbuf_printf(ab, "%-10ld\t", *(int64_t *)(opt->o_valuep));
			pfs_adminbuf_printf(ab, "%s\n", opt->o_default);
			break;
		case OPT_STR:
			pfs_adminbuf_printf(ab, "%s\t", ((std::string *)(opt->o_valuep))->c_str());
			pfs_adminbuf_printf(ab, "%s\n", opt->o_default);
			break;
		}
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

static int
pfs_option_get_str(pfs_option_t *opt, char buf[], size_t len)
{
	buf[0] = 0;
	switch(opt->o_kind) {
	case OPT_INT:
		snprintf(buf, len, "%d", *(int *)opt->o_valuep);
		break;
	case OPT_LONG:
		snprintf(buf, len, "%ld", *(long *)opt->o_valuep);
		break;
	case OPT_STR:
		snprintf(buf, len, "%s", *(char **)opt->o_valuep);
		break;
	default:
		return -1;
	}
	return 0;
}

static int
pfs_option_get_default_str(pfs_option_t *opt, char buf[], size_t len)
{
	snprintf(buf, len, "%s", opt->o_default);
	return 0;
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

		pfs_option_get_str(opt, buf, sizeof(buf));
		pfs_itrace("option %s is changing from '%s' to %s\n",
			   opt->o_name, buf, val);
		opt->o_store(opt, val);
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
pfs_option_set(const char *name, int val)
{
	char buf[128];
	snprintf(buf, sizeof(buf), "%d", val);
	return pfs_option_set(name, buf);
}

int
pfs_option_set(const char *name, long val)
{
	char buf[128];
	snprintf(buf, sizeof(buf), "%ld", val);
	return pfs_option_set(name, buf);
}

int
pfs_option_set(const char *name, const std::string &val)
{
	return pfs_option_set(name, val.c_str());
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

	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;
		if (strcmp(name, opt->o_name) != 0)
			continue;

		if (opt->o_check && !opt->o_check(opt, val)) {
			pfs_etrace("option %s new value is invalid\n", opt->o_name);
			ERR_RETVAL(EINVAL);
		}

		pfs_option_get_str(opt, buf, sizeof(buf));
		pfs_itrace("option %s is changing from %s to %s\n",
				opt->o_name, buf, val);
		opt->o_store(opt, val);
		flag = true;
		break;
	}

	if (!flag) {
		pfs_etrace("option %s is not found\n", name);
		ERR_RETVAL(EINVAL);
	}

	n = pfs_adminbuf_printf(ab, "succeeded\n");
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

		pfs_option_get_str(opt, buf, sizeof(buf));

		bool rc = opt->o_store(opt, value);

		pfs_itrace("option %s is changing from '%s' to '%s', %s\n",
			    opt->o_name, buf, value,
			    rc ? "success":"failure");

		if (ab) {
			pfs_option_get_default_str(opt, buf, sizeof(buf));
			n = pfs_adminbuf_printf(ab,"%-36s\t%s\t%-10ld\t%s\n",
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

int
pfs_option_set_default(void)
{
	DATA_SET_DECL(pfs_option, _pfsopt);
	pfs_option_t **optp, *opt;
	int ret = true;

	DATA_SET_FOREACH(optp, _pfsopt) {
		opt = *optp;

		if (!opt->o_store(opt, opt->o_default)) {
			pfs_etrace("option %s can not set default value '%s'",
				opt->o_name, opt->o_default);
			ret = false;
		}
	}

	return ret;
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
