# GhostLock S26 精简版（ghostlock-s26-slim）

> 原项目：[snothin/ghostlock-s26](https://github.com/snothin/ghostlock-s26)

基于 [`ghostlock-s26`](https://github.com/snothin/ghostlock-s26) 的**精简版**，只服务 `S9480ZCS1AZC7`
（SM-S9480 / m3q / S26 Ultra CN）一个固件。攻击链与偏移与原项目完全一致，
去掉的只是"运行时多目标匹配 + 配置层"这层臃肿。

## 与 ghostlock-s26 的对比（精简了什么）

| 项 | ghostlock-s26（原项目） | ghostlock-s26-slim（精简版） |
|---|---|---|
| 定位 | 覆盖 S26 全系：cn / intl / exynos 三线，运行时匹配 | 单固件：S9480ZCS1AZC7（m3q / cn） |
| 目标匹配 | `params.c` + `params_table.c` + `kernel_line` 运行时绑定 | **删除**，`target.h` 单一事实来源 |
| 运行时自定义线 | `/data/local/tmp/ghostlock-lines.conf` 注入新线 | **删除**，编译期定死 |
| 配置层 | `config.c` / `config.h`（`ghostlock.conf` 文件 + env + `--key=value` CLI 三级优先级） | **删除**，`ksu.skip` 直接读 `KSU_SKIP` 环境变量 |
| boot 运行判断 | `bootclaim.c` 写 `ghostlock-boot.log` + `BOOT_FORCE` 覆盖 | **删除**，人工控制每次 boot 只跑一次 |
| 源码 `.c` | 16 个 | 12 个（11 个进 `preload.so` + `su_daemon.c` 单独编译） |
| 攻击链 | KASLR → attr 载具 → UMH → KernelSU | **不变** |
| 偏移 | 按 kernel line 运行时选择 | S9480ZCS1AZC7 编译期固化 |

核心攻击链与 ghostlock-s26 完全一致，偏移零改动，只是去掉了运行时型号匹配
与配置这层"臃肿"。

## 目录结构

```
ghostlock-s26-slim/
  Makefile          # 单目标构建（默认 PROJECT=S9480ZCS1AZC7）
  src/
    main.c          # stability keeper + 主链路
    preload.c       # supervisor 重试
    slide.c         # 通用 tracefs KASLR（被 target 版本覆盖）
    targets/S9480ZCS1AZC7/slide.c   # S26 KASLR 范围特化
    targets/S9480ZCS1AZC7/target.h  # 全部偏移（单一事实来源）
    attr.c          # misc/simple_attr + debugfs_u64 任意读写载具
    root.c          # UMH 伪造 → call_usermodehelper_exec_work
    walk.c / payload.c / pselect.c / heap.c
    ksud.c / ksu_proto.h   # KernelSU late-load
    su_daemon.c     # root 守护进程（PIE，推送到 ROOT_UMH_PATH）
    kernelsnitch/
```

## 偏移验证（BTF + kallsyms）

已用 `magiskboot` 解包 `boot.img`、`vmlinux-to-elf` 提取符号、`bpftool` 解析
BTF（`BTF @ 0x19c842c`，7 085 396 字节），逐项核对 `target.h`：

- `task_struct`：`usage=0x40` `prio=0x94` `normal_prio=0x9c`
  `sched_task_group=0x420` `pi_lock=0x9ec` `pi_waiters=0xa00`
  `pi_top_task=0xa10` `pi_blocked_on=0xa18` ✅
- `rt_mutex_waiter`：`task=0x50` `lock=0x58` `wake_state=0x60` `ww_ctx=0x68` ✅
- `rt_waiter_node`：`entry=0x0` `prio=0x18` `deadline=0x20` ✅
- `work_struct`：`data=0x0` `entry=0x8` `func=0x18` ✅
- `workqueue_struct`：`dfl_pwq=0xc0` ✅
- `miscdevice`：`minor=0x0` `name=0x8` `fops=0x10` `list=0x18` `nodename=0x40`
  `mode=0x48` ✅

符号偏移与 ghostlock-s26 的 cn 线完全一致（原项目已实测跑通，此处从
`/proc/kallsyms` 复验）。

## 针对 S9480ZCS1AZC7 的优化说明

本 target 在 `src/targets/S9480ZCS1AZC7/`下做了如下特化：

### 1. KASLR slide 范围修正（关键）

S26（6.12）的 arm64 39-bit VA KASLR slide 是 **2 MiB 对齐**，取值范围
`[0xf8fe00000, 0x2eafa00000)`。原实现的 `0x1f0000` 上界会把 S26 上所有真实
slide（约 172 GB 量级）全部过滤掉，导致 tracefs 探测永远失败。

- 依据：反汇编 `__pi_kaslr_early_init`
  - 下界 `0xf8fe00000`：`mov x10,#0x8fe00000; movk x10,#0xf,lsl#32`
  - 区间 `0x1f1fc00000`：`mov x8,#0x1fc00000; movk x8,#0x1f,lsl#32`
- 实现：`src/targets/S9480ZCS1AZC7/slide.c` 特化版本

```c
if (candidate >= 0xf8fe00000ULL && candidate < 0x2eafa00000ULL &&
    (candidate & 0x1fffffULL) == 0) { ... }
```

### 2. task_struct 布局特化（sched_ext / dl_server 回移）

S9480ZCS1AZC7 回移了 `sched_ext` / `dl_server`，使 task_struct 字段相对默认
布局整体偏移——即使 kallsyms 地址完全一致。这些是编译期常量
（`prepare_skb_payload` codegen 对时序敏感），二进制必须与目标布局严格匹配：

| 字段 | 偏移 |
|---|---|
| `prio` | `0x94` |
| `normal_prio` | `0x9c` |
| `sched_task_group` | `0x420` |
| `pi_lock` | `0x9ec` |
| `pi_waiters` | `0xa00` |
| `pi_top_task` | `0xa10` |
| `pi_blocked_on` | `0xa18` |

### 3. 物理 slide 推导

虚拟 slide 由 tracefs 泄漏；物理 slide 独立，需在拿到任意读后从
`kimage_voffset` 推导：`KIMAGE_VOFFSET_OFF=0x01911008`（cn/intl 线）。

### 4. 内核线布尔化

`BUILD_LINE_ID`（字符串）改为 `BUILD_EXYNOS`（布尔）。S9480ZCS1AZC7 为 cn 线，
`BUILD_EXYNOS=0`，exynos 分支（`KSUD_TREE=exynos` 环境注入）在编译期关闭。

### 5. DEFEX 规避

S26 的 [`polygraphene`](https://github.com/xrzcc/s26-m1q-ghostlock-selinux) 项目走 pipe-flag → 覆盖 `/vendor/bin/vendor_modprobe.sh`
路由，在 S9480 上被 Samsung DEFEX 以 EPERM 阻断（即使 SELinux permissive 也
EPERM）。本 target 走 attr-carrier + UMH 路由，不受该 DEFEX 限制。

## 构建

```bash
make
```

产物：

```
build/bin/preload.so              # exploit LD_PRELOAD 库
build/bin/cve-2026-43499-root     # root 命令守护进程（UMH 启动）
```

## 部署

```bash
# 1. 推文件
adb push build/bin/preload.so /data/local/tmp/preload.so
adb push build/bin/cve-2026-43499-root /data/local/tmp/cve-2026-43499-root
adb shell chmod 755 /data/local/tmp/cve-2026-43499-root

# 2. 触发 exploit（supervisor 自动重试，失败可 KP 重启后重跑）
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/true"
```

成功标志：`root chain complete` + `kernelsu late-load succeeded`。
KernelSU 授权需安装 `me.weishu.kernelsu` Manager APK。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `EXPLOIT_ATTEMPTS` | 16 | supervisor 重试次数 |
| `WALK_DELAY` | 120000 | pselect 进入延迟 (usec) |
| `KSU_SKIP` | 未设 | 设置则跳过 KernelSU late-load（仅 socket root） |
