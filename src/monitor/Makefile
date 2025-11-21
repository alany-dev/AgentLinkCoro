# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
OUTPUT := $(MAKEFILE_DIR).output
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LIBBPF_SRC := $(MAKEFILE_DIR)../../third_party/libbpf/src
BPFTOOL_SRC := $(MAKEFILE_DIR)../../third_party/bpftool/src
LIBBPF_OBJ := $(OUTPUT)/libbpf.a
BPFTOOL_OUTPUT ?= $(OUTPUT)/bpftool
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/riscv64/riscv/')
VMLINUX := $(MAKEFILE_DIR)../../third_party/vmlinux.h/include/$(ARCH)/vmlinux.h
# 包含路径（libbpf和vmlinux头文件）
INCLUDES := -I$(OUTPUT) -I$(MAKEFILE_DIR)../../third_party/libbpf/include/uapi -I$(MAKEFILE_DIR)../../third_party/vmlinux.h/include/$(ARCH)

# 定义需要生成skeleton的BPF源文件（根据实际情况修改）
BPF_SOURCES := weaknet/server/flow_monitor.bpf.c
# 对应的skeleton目标文件
SKEL_TARGETS := $(patsubst %.bpf.c,$(OUTPUT)/%.bpf.skel.h,$(BPF_SOURCES))

# 编译Verbose控制
V ?= 0
CROSS_COMPILE ?=

# Clang默认系统头文件路径（BPF编译需要）
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# 静默编译控制
ifeq ($(V),1)
	Q =
	msg = @true
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
endif

# 工具链覆盖控制
define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef
$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

# 默认目标：生成所有skeleton
.PHONY: all
all: $(SKEL_TARGETS)

# 清理规则
.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT)

# 创建输出目录
$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# 构建libbpf（BPF编译依赖）
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# 构建bpftool（生成skeleton依赖）
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# 编译BPF目标文件（.bpf.o）
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$@)
	# 新增：创建目标文件所在的子目录
	$(Q)mkdir -p $(dir $@)
	# 编译生成.bpf.o
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # 移除无用调试信息

# 生成BPF skeleton（.skel.h）
$(OUTPUT)/%.bpf.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# 删除失败的目标文件
.DELETE_ON_ERROR:

# 保留中间文件（.bpf.o等）
.SECONDARY:

# 禁止make默认打印目录
MAKEFLAGS += --no-print-directory