API ?= 35

# ── Single-version target build ─────────────────────────────────────────
# This project builds exactly one target profile (firmware version). There is
# no runtime model / firmware matching. To support a new firmware version,
# create src/targets/<PROJECT>/target.h (plus any per-target source overrides,
# e.g. slide.c) and build with PROJECT=<PROJECT>.
PROJECT ?= S9480ZCS1AZC7
OUTDIR ?= build/bin

TARGET_DIR := src/targets/$(PROJECT)
TARGET_HEADER := $(TARGET_DIR)/target.h

ifeq ($(wildcard $(TARGET_HEADER)),)
$(error unknown PROJECT=$(PROJECT), missing $(TARGET_HEADER))
endif

# pick_src: use a target-specific override if it exists, otherwise the generic
# src/ file. Per-version specializations (e.g. the S9480ZCS1AZC7 KASLR slide
# range in slide.c) live in the target dir while the main program stays on the
# original code.
define pick_src
$(if $(wildcard $(TARGET_DIR)/$(1)),$(TARGET_DIR)/$(1),src/$(1))
endef

SU_DAEMON := $(OUTDIR)/cve-2026-43499-root
PRELOAD := $(OUTDIR)/preload.so

CORE_SRCS := \
  $(call pick_src,main.c) \
  $(call pick_src,walk.c) \
  $(call pick_src,ksud.c) \
  $(call pick_src,util.c) \
  $(call pick_src,payload.c) \
  $(call pick_src,heap.c) \
  $(call pick_src,slide.c) \
  $(call pick_src,pselect.c) \
  $(call pick_src,attr.c) \
  $(call pick_src,root.c)
PRELOAD_SRCS := $(CORE_SRCS) $(call pick_src,preload.c)

.DEFAULT_GOAL := preload

DEFAULT_NDK_ROOT := $(or \
  $(wildcard $(HOME)/Android/Sdk/ndk/*), \
  $(wildcard /opt/android-sdk-linux/ndk/*), \
  $(wildcard /opt/android-sdk/ndk/*), \
  $(wildcard /opt/android-ndk), \
  $(wildcard $(HOME)/android-ndk-cache/android-ndk-r29))
NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),$(DEFAULT_NDK_ROOT))
# Host tag / exe suffix: NDK prebuilts ship .cmd wrapper scripts on Windows,
# extensionless ELF-shebang scripts on Linux/macOS.
NDK_HOST_TAG ?= $(if $(filter Windows_NT,$(OS)),windows-x86_64,linux-x86_64)
NDK_EXE := $(if $(filter windows-x86_64,$(NDK_HOST_TAG)),.cmd,)
NDK_TOOLCHAIN ?= $(if $(NDK_ROOT),$(NDK_ROOT)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG))
NDK_CC := $(NDK_TOOLCHAIN)/bin/aarch64-linux-android$(API)-clang$(NDK_EXE)
HOST_CLANG ?= clang
SYSROOT ?= $(if $(NDK_TOOLCHAIN),$(NDK_TOOLCHAIN)/sysroot)
RESOURCE_DIR ?= $(if $(NDK_TOOLCHAIN),$(NDK_TOOLCHAIN)/lib/clang/21)

HOST_TARGET_FLAGS := \
  --target=aarch64-linux-android$(API) \
  --sysroot=$(SYSROOT) \
  -resource-dir $(RESOURCE_DIR) \
  --rtlib=compiler-rt \
  --unwindlib=none
HOST_COMMON_LDFLAGS := \
  -fuse-ld=lld \
  -Wl,-rpath-link,$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android/$(API) \
  -L$(SYSROOT)/usr/lib/aarch64-linux-android
HOST_PIE_LDFLAGS := \
  $(HOST_COMMON_LDFLAGS) \
  -Wl,-dynamic-linker,/system/bin/linker64

ifneq ($(origin CC),default)
  TARGET_CC := $(CC)
  TARGET_FLAGS :=
  TARGET_COMMON_LDFLAGS :=
  TARGET_PIE_LDFLAGS :=
else ifneq ($(wildcard $(NDK_CC)),)
  NDK_CC_WORKS := $(shell $(NDK_CC) --version >/dev/null 2>&1 && echo yes)
  ifeq ($(NDK_CC_WORKS),yes)
    TARGET_CC := $(NDK_CC)
    TARGET_FLAGS :=
    TARGET_COMMON_LDFLAGS :=
    TARGET_PIE_LDFLAGS :=
  else
    TARGET_CC := $(HOST_CLANG)
    TARGET_FLAGS := $(HOST_TARGET_FLAGS)
    TARGET_COMMON_LDFLAGS := $(HOST_COMMON_LDFLAGS)
    TARGET_PIE_LDFLAGS := $(HOST_PIE_LDFLAGS)
  endif
else
  TARGET_CC := $(HOST_CLANG)
  TARGET_FLAGS := $(HOST_TARGET_FLAGS)
  TARGET_COMMON_LDFLAGS := $(HOST_COMMON_LDFLAGS)
  TARGET_PIE_LDFLAGS := $(HOST_PIE_LDFLAGS)
endif

TARGET_CFLAGS := -DTARGET_CONFIG_H=\"targets/$(PROJECT)/target.h\" -I$(TARGET_DIR)
COMMON_CFLAGS := -O2 -g0 -Wall -Wextra -Isrc $(TARGET_CFLAGS)
PIE_CFLAGS := -fPIE -pie $(COMMON_CFLAGS)
SO_CFLAGS := -fPIC $(COMMON_CFLAGS)
WARN_CFLAGS := -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function

.PHONY: all preload clean list-projects

all: preload

preload: $(PRELOAD)

$(OUTDIR):
	mkdir -p $@

$(SU_DAEMON): $(call pick_src,su_daemon.c) | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(PIE_CFLAGS) \
	  $< $(TARGET_PIE_LDFLAGS) -o $@

$(PRELOAD): $(PRELOAD_SRCS) $(SU_DAEMON) src/common.h src/params.h src/offset.h \
  $(TARGET_HEADER) src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) $(TARGET_FLAGS) $(SO_CFLAGS) $(WARN_CFLAGS) \
	  $(PRELOAD_SRCS) $(TARGET_COMMON_LDFLAGS) -llog \
	  -shared -o $@ -pthread
	sha256sum $@

list-projects:
	@ls src/targets

clean:
	rm -rf build
