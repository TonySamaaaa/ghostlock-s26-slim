#ifndef PARAMS_H
#define PARAMS_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
 * Single-target build (no runtime matching). Every symbol offset lives in
 * targets/<PROJECT>/target.h, pulled in via offset.h. These macros are the
 * direct image addresses — there is no `target` pointer or per-line table.
 */
#include "offset.h"

#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define MISC_LIST (KIMAGE_TEXT_BASE + MISC_LIST_OFF)
#define UINPUT_MISC (KIMAGE_TEXT_BASE + UINPUT_MISC_OFF)
#define SIMPLE_ATTR_READ (KIMAGE_TEXT_BASE + SIMPLE_ATTR_READ_OFF)
#define SIMPLE_ATTR_WRITE (KIMAGE_TEXT_BASE + SIMPLE_ATTR_WRITE_OFF)
#define DEBUGFS_U64_GET (KIMAGE_TEXT_BASE + DEBUGFS_U64_GET_OFF)
#define DEBUGFS_U64_SET (KIMAGE_TEXT_BASE + DEBUGFS_U64_SET_OFF)
#define DEBUGFS_U64_FORMAT (KIMAGE_TEXT_BASE + DEBUGFS_U64_FORMAT_OFF)
#define DEFAULT_LLSEEK (KIMAGE_TEXT_BASE + DEFAULT_LLSEEK_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)

#endif /* PARAMS_H */
