/*
 *  Copyright (c) 2020 NetEase Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/**
 * Project : curve
 * Date : 2022/11/09
 * Author: XuYifeng
 */

#ifndef _PFS_OPTION_API_H_
#define _PFS_OPTION_API_H_

#include <string>

int	pfs_option_init(const char *config_path);
int     pfs_option_set_default(void);
int     pfs_option_set(const char *name, int);
int     pfs_option_set(const char *name, long);
int     pfs_option_set(const char *name, const char *val);
int     pfs_option_set(const char *name, const std::string& val);

#endif
