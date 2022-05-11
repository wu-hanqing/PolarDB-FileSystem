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

#ifndef _TRACE_TYPE_H_
#define _TRACE_TYPE_H_

#include "trace_common.h"

#define InvalidStatType "###"

enum STAT_DEF_TYPE {
    STAT_TYPE_DUMMY = 0,
    STAT_TYPE_CNT,
    STAT_TYPE_HIST,
};

enum STAT_OP_TYPE {
    STAT_OP_SET_CNT = 0,
    STAT_OP_UPDATE_CNT,
    STAT_OP_UPDATE_BW,
    STAT_OP_UPDATE_LAT,
};

// APP TYPE
enum STAT_TYPE_BASE {
    BSR_STAT_TYPE_BASE = TRACE_APP_BSR << OFFSET_APP_TYPE,
    PLS_STAT_TYPE_BASE = TRACE_APP_PLS << OFFSET_APP_TYPE,
    PFS_STAT_TYPE_BASE = TRACE_APP_PFS << OFFSET_APP_TYPE,
};

enum EasyStatType {

// bsr
    STAT_BSR_REQ                  = BSR_STAT_TYPE_BASE + 0,
    STAT_BSR_IO_READ_REQ          = BSR_STAT_TYPE_BASE + 1,
    STAT_BSR_IO_WRITE_REQ         = BSR_STAT_TYPE_BASE + 2,
    STAT_BSR_RSP                  = BSR_STAT_TYPE_BASE + 3,
    STAT_BSR_ERROR                = BSR_STAT_TYPE_BASE + 4,
    STAT_BSR_DISK_ERROR           = BSR_STAT_TYPE_BASE + 5,
    STAT_BSR_NET_ERROR            = BSR_STAT_TYPE_BASE + 6,
    STAT_BSR_JNL_HOLE             = BSR_STAT_TYPE_BASE + 7,
    STAT_BSR_LCTX_CNT             = BSR_STAT_TYPE_BASE + 8,
    STAT_BSR_FCTX_CNT             = BSR_STAT_TYPE_BASE + 9,

    STAT_BSR_LEADER_REPL_ERROR    = BSR_STAT_TYPE_BASE + 10,
    STAT_BSR_FOLLOWER_REPL_ERROR  = BSR_STAT_TYPE_BASE + 11,
    STAT_BSR_IOSCH_EQ             = BSR_STAT_TYPE_BASE + 12,
    STAT_BSR_IOSCH_DQ             = BSR_STAT_TYPE_BASE + 13,
    STAT_BSR_IOSCH_CP             = BSR_STAT_TYPE_BASE + 14,

    STAT_BSR_IOMSG_MP_CNT         = BSR_STAT_TYPE_BASE + 15,
    STAT_BSR_AppJNL_MP_CNT        = BSR_STAT_TYPE_BASE + 16,
    STAT_BSR_LAJ_MP_CNT           = BSR_STAT_TYPE_BASE + 17,
    STAT_BSR_LCMT_MP_CNT          = BSR_STAT_TYPE_BASE + 18,
    STAT_BSR_IOCHK_ERROR          = BSR_STAT_TYPE_BASE + 19,

    STAT_BSR_SVRMSG_MP_CNT        = BSR_STAT_TYPE_BASE + 20,
    STAT_BSR_CLIMSG_MP_CNT        = BSR_STAT_TYPE_BASE + 21,
    STAT_BSR_FCMT_MP_CNT          = BSR_STAT_TYPE_BASE + 22,
    STAT_BSR_RdmaConn_MP_CNT      = BSR_STAT_TYPE_BASE + 23,
    STAT_BSR_JnlWnd_CNT           = BSR_STAT_TYPE_BASE + 24,
    STAT_BSR_MigOP1_CNT           = BSR_STAT_TYPE_BASE + 25,
    STAT_BSR_MigOP2_CNT           = BSR_STAT_TYPE_BASE + 26,
    STAT_BSR_MigOP3_CNT           = BSR_STAT_TYPE_BASE + 27,
    STAT_BSR_OnGo_REPL_CNT        = BSR_STAT_TYPE_BASE + 28,
    STAT_BSR_OnGo_CMT_CNT         = BSR_STAT_TYPE_BASE + 29,

    STAT_BSR_CHKPT_CNT            = BSR_STAT_TYPE_BASE + 30,
    STAT_BSR_TRIM_CNT             = BSR_STAT_TYPE_BASE + 31,

    STAT_BSR_LWIOThrot_CNT        = BSR_STAT_TYPE_BASE + 32,
    STAT_BSR_ReplThrot_CNT        = BSR_STAT_TYPE_BASE + 33,
    STAT_BSR_JnlWndThrot_CNT      = BSR_STAT_TYPE_BASE + 34,
    STAT_BSR_LAJThrot_CNT         = BSR_STAT_TYPE_BASE + 35,
    STAT_BSR_LCMThrot_CNT         = BSR_STAT_TYPE_BASE + 36,
    STAT_BSR_LJnlWndHighThrot_CNT = BSR_STAT_TYPE_BASE + 37,
    STAT_BSR_RJnlWndHighThrot_CNT = BSR_STAT_TYPE_BASE + 38,
    STAT_BSR_R2LJnlWndThrot_CNT   = BSR_STAT_TYPE_BASE + 39,

    STAT_BSR_UnCMT_CNT            = BSR_STAT_TYPE_BASE + 40,
    STAT_BSR_LCMT_IGN_CNT         = BSR_STAT_TYPE_BASE + 41,
    STAT_BSR_LCMT_APL_CNT         = BSR_STAT_TYPE_BASE + 42,
    STAT_BSR_FCMT_IGN_CNT         = BSR_STAT_TYPE_BASE + 43,
    STAT_BSR_FCMT_APL_CNT         = BSR_STAT_TYPE_BASE + 44,

    STAT_BSR_LRIOThrot_CNT        = BSR_STAT_TYPE_BASE + 45,
    STAT_BSR_COWThrot_CNT         = BSR_STAT_TYPE_BASE + 46,
    STAT_BSR_NetThrot_CNT         = BSR_STAT_TYPE_BASE + 47,

    /* LCMT_APL == Apply,  Leader send CommitMsg with FOLLOWER_COMMIT_TYPE_COMMIT */
    /* LCMT_IGN == Ignore, Leader send CommitMsg with FOLLOWER_COMMIT_TYPE_INVALID */

// pls
    STAT_PBD_Req                  = PLS_STAT_TYPE_BASE + 0,
    STAT_PBD_ReqErr               = PLS_STAT_TYPE_BASE + 1,
    STAT_PBD_SubReq               = PLS_STAT_TYPE_BASE + 2,
    STAT_PBD_SubReqErr            = PLS_STAT_TYPE_BASE + 3,
    STAT_PBD_ReqCB                = PLS_STAT_TYPE_BASE + 4,
    STAT_PBD_SubReqCB             = PLS_STAT_TYPE_BASE + 5,
    STAT_PBD_ReqRead              = PLS_STAT_TYPE_BASE + 6,
    STAT_PBD_ReqWrite             = PLS_STAT_TYPE_BASE + 7,
    STAT_PBD_BytesRead            = PLS_STAT_TYPE_BASE + 8,
    STAT_PBD_BytesWrite           = PLS_STAT_TYPE_BASE + 9,
    STAT_PBD_UnrecoverIO          = PLS_STAT_TYPE_BASE + 10,
    STAT_PBD_SNAPSHOTIO           = PLS_STAT_TYPE_BASE + 11,

    STAT_PKT_RxNumSucc            = PLS_STAT_TYPE_BASE + 12,
    STAT_PKT_RxNumInvalid         = PLS_STAT_TYPE_BASE + 13,
    STAT_PKT_TxNumSucc            = PLS_STAT_TYPE_BASE + 14,
    STAT_PKT_TxNumFail            = PLS_STAT_TYPE_BASE + 15,
    STAT_PKT_ReTxNumSucc          = PLS_STAT_TYPE_BASE + 16,
    STAT_PKT_ReTxNumFail          = PLS_STAT_TYPE_BASE + 17,
    STAT_PKT_RxBytesSucc          = PLS_STAT_TYPE_BASE + 18,
    STAT_PKT_RxBytesInvalid       = PLS_STAT_TYPE_BASE + 19,
    STAT_PKT_TxBytesSucc          = PLS_STAT_TYPE_BASE + 20,
    STAT_PKT_TxBytesFail          = PLS_STAT_TYPE_BASE + 21,
    STAT_PKT_ReTxBytesSucc        = PLS_STAT_TYPE_BASE + 22,
    STAT_PKT_ReTxBytesFail        = PLS_STAT_TYPE_BASE + 23,

    STAT_PBD_ReqInflight          = PLS_STAT_TYPE_BASE + 24,
    STAT_PBD_SubReqInflight       = PLS_STAT_TYPE_BASE + 25,
    STAT_PBD_SubWaiting           = PLS_STAT_TYPE_BASE + 26,

    STAT_PFS_UnAligned_R_4K       = PFS_STAT_TYPE_BASE + 0,
    STAT_PFS_UnAligned_R_16K      = PFS_STAT_TYPE_BASE + 1,
    STAT_PFS_UnAligned_W_4K       = PFS_STAT_TYPE_BASE + 2,
    STAT_PFS_UnAligned_W_16K      = PFS_STAT_TYPE_BASE + 3,
    STAT_PFS_PaxosAcquire         = PFS_STAT_TYPE_BASE + 4,
    STAT_PFS_PaxosRunBallot       = PFS_STAT_TYPE_BASE + 5,
};

enum StatType {

//  bsr
    STAT_BSR_READ_IO_ENTRY        = BSR_STAT_TYPE_BASE + 0,
    STAT_BSR_READ_IO_DONE         = BSR_STAT_TYPE_BASE + 1,
    STAT_BSR_READ_TX_ENTRY        = BSR_STAT_TYPE_BASE + 2,
    STAT_BSR_READ_TX_DONE         = BSR_STAT_TYPE_BASE + 3,
    STAT_BSR_WRITE_IO_ENTRY       = BSR_STAT_TYPE_BASE + 4,
    STAT_BSR_WRITE_IO_DONE        = BSR_STAT_TYPE_BASE + 5,
    STAT_BSR_WRITE_TX_ENTRY       = BSR_STAT_TYPE_BASE + 6,
    STAT_BSR_WRITE_TX_DONE        = BSR_STAT_TYPE_BASE + 7,
    STAT_BSR_SPDK_WRITE_ENTRY     = BSR_STAT_TYPE_BASE + 8,
    STAT_BSR_SPDK_WRITE_DONE      = BSR_STAT_TYPE_BASE + 9,
    STAT_BSR_SPDK_READ_ENTRY      = BSR_STAT_TYPE_BASE + 10,
    STAT_BSR_SPDK_READ_DONE       = BSR_STAT_TYPE_BASE + 11,
    STAT_BSR_LEADER_REPL_ENTRY    = BSR_STAT_TYPE_BASE + 12,
    STAT_BSR_LEADER_REPL_DONE     = BSR_STAT_TYPE_BASE + 13,
    STAT_BSR_FOLLOWER_REPL_ENTRY  = BSR_STAT_TYPE_BASE + 14,
    STAT_BSR_FOLLOWER_REPL_DONE   = BSR_STAT_TYPE_BASE + 15,

    STAT_BSR_DATA_IOWAIT_ENTRY    = BSR_STAT_TYPE_BASE + 16,
    STAT_BSR_DATA_IOWAIT_DONE     = BSR_STAT_TYPE_BASE + 17,
    STAT_BSR_DATA_WRITE_ENTRY     = BSR_STAT_TYPE_BASE + 18,
    STAT_BSR_DATA_WRITE_DONE      = BSR_STAT_TYPE_BASE + 19,
    STAT_BSR_DATA_READ_ENTRY      = BSR_STAT_TYPE_BASE + 20,
    STAT_BSR_DATA_READ_DONE       = BSR_STAT_TYPE_BASE + 21,
    STAT_BSR_JNL_IOWAIT_ENTRY     = BSR_STAT_TYPE_BASE + 22,
    STAT_BSR_JNL_IOWAIT_DONE      = BSR_STAT_TYPE_BASE + 23,
    STAT_BSR_JNL_WRITE_ENTRY      = BSR_STAT_TYPE_BASE + 24,
    STAT_BSR_JNL_WRITE_DONE       = BSR_STAT_TYPE_BASE + 25,

    STAT_BSR_IO_RECV_BW           = BSR_STAT_TYPE_BASE + 26,
    STAT_BSR_IO_SENT_BW           = BSR_STAT_TYPE_BASE + 27,
    STAT_BSR_SPDK_WRITE_BW        = BSR_STAT_TYPE_BASE + 28,
    STAT_BSR_SPDK_READ_BW         = BSR_STAT_TYPE_BASE + 29,
    STAT_BSR_L_DATA_WRITE_BW      = BSR_STAT_TYPE_BASE + 30,
    STAT_BSR_L_DATA_READ_BW       = BSR_STAT_TYPE_BASE + 31,
    STAT_BSR_META_READ_BW         = BSR_STAT_TYPE_BASE + 32,
    STAT_BSR_META_WRITE_BW        = BSR_STAT_TYPE_BASE + 33,
    STAT_BSR_REPL_RECV_BW         = BSR_STAT_TYPE_BASE + 34,
    STAT_BSR_REPL_SENT_BW         = BSR_STAT_TYPE_BASE + 35,
    STAT_BSR_MIG_DATA_RECV_BW     = BSR_STAT_TYPE_BASE + 36,
    STAT_BSR_MIG_DATA_SENT_BW     = BSR_STAT_TYPE_BASE + 37,
    STAT_BSR_L_JNL_WRITE_BW       = BSR_STAT_TYPE_BASE + 38,
    STAT_BSR_F_DATA_WRITE_BW      = BSR_STAT_TYPE_BASE + 39,
    STAT_BSR_F_JNL_WRITE_BW       = BSR_STAT_TYPE_BASE + 40,

    STAT_BSR_COW_READ_BW          = BSR_STAT_TYPE_BASE + 41,
    STAT_BSR_COW_WRITE_BW         = BSR_STAT_TYPE_BASE + 42,

    STAT_BSR_DATA_INC_READ_BW     = BSR_STAT_TYPE_BASE + 43,
    STAT_BSR_DATA_ALL_READ_BW     = BSR_STAT_TYPE_BASE + 44,
    STAT_BSR_DATA_INC_WRITE_BW    = BSR_STAT_TYPE_BASE + 45,
    STAT_BSR_DATA_ALL_WRITE_BW    = BSR_STAT_TYPE_BASE + 46,

    STAT_BSR_MIG_JNL_RECV_BW      = BSR_STAT_TYPE_BASE + 47,
    STAT_BSR_MIG_JNL_SENT_BW      = BSR_STAT_TYPE_BASE + 48,

//  pls
    STAT_PBD_READ_IO_ENTRY        = PLS_STAT_TYPE_BASE + 0,
    STAT_PBD_READ_IO_DONE         = PLS_STAT_TYPE_BASE + 1,
    STAT_PBD_READ_SUB_IO_ENTRY    = PLS_STAT_TYPE_BASE + 2,
    STAT_PBD_READ_SUB_IO_DONE     = PLS_STAT_TYPE_BASE + 3,

    STAT_PBD_WRITE_IO_ENTRY       = PLS_STAT_TYPE_BASE + 4,
    STAT_PBD_WRITE_IO_DONE        = PLS_STAT_TYPE_BASE + 5,
    STAT_PBD_WRITE_SUB_IO_ENTRY   = PLS_STAT_TYPE_BASE + 6,
    STAT_PBD_WRITE_SUB_IO_DONE    = PLS_STAT_TYPE_BASE + 7,

    STAT_PBD_READ_BW              = PLS_STAT_TYPE_BASE + 8,
    STAT_PBD_WRITE_BW             = PLS_STAT_TYPE_BASE + 9,

//  pfs
    STAT_PFS_API_READ_DONE        = PFS_STAT_TYPE_BASE + 0,
    STAT_PFS_API_WRITE_DONE       = PFS_STAT_TYPE_BASE + 1,
    STAT_PFS_DEV_READ_DONE        = PFS_STAT_TYPE_BASE + 2,
    STAT_PFS_DEV_WRITE_DONE       = PFS_STAT_TYPE_BASE + 3,

    STAT_PFS_API_READ_BW          = PFS_STAT_TYPE_BASE + 4,
    STAT_PFS_API_WRITE_BW         = PFS_STAT_TYPE_BASE + 5,
    STAT_PFS_API_PREAD_BW         = PFS_STAT_TYPE_BASE + 6,
    STAT_PFS_API_PWRITE_BW        = PFS_STAT_TYPE_BASE + 7,
    STAT_PFS_DEV_READ_BW          = PFS_STAT_TYPE_BASE + 8,
    STAT_PFS_DEV_WRITE_BW         = PFS_STAT_TYPE_BASE + 9,

    STAT_PFS_API_PREAD_DONE       = PFS_STAT_TYPE_BASE + 10,
    STAT_PFS_API_PWRITE_DONE      = PFS_STAT_TYPE_BASE + 11,
    STAT_PFS_DEV_TRIM_DONE        = PFS_STAT_TYPE_BASE + 12,
    STAT_PFS_API_FSYNC_DONE       = PFS_STAT_TYPE_BASE + 13,
};

const static int32_t bsr_timeout_array[HISTGRAM_TYPE_CNT] = {
                // caution: sequence important
    10000,     // BSR_READ_IO_BENCH
    12000,     // BSR_READ_TX_BENCH
    8000 ,     // BSR_WRITE_IO_BENCH
    10000 ,     // BSR_WRITE_TX_BENCH
    5000 ,     // BSR_SPDK_WRITE_IO_BENCH
    10000,     // BSR_SPDK_READ_IO_BENCH
    10000 ,     // BSR_LEADER_REPL_BENCH
    10000       // BSR_FOLLOWER_REPL_BENCH
};

#endif

