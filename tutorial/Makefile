TARGET ?= hello
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CLANG := clang -I./include

SUDO := sudo

BPF_OBJ := $(TARGET:=.bpf.o)


%.bpf.o: %.bpf.c include/vmlinux.h
	$(CLANG) \
		-target bpf \
	-D __TARGET_ARCH_$(ARCH) \
		-Wall \
		-O2 -g -o $@ -c $<

.PHONY: clean
clean: clean-topology
	rm *.bpf.o

.PHONY: attach
attach:
	$(SUDO) ip netns exec host0 ip link set dev h0 xdp obj $(BPF_OBJ) section xdp 

.PHONY: detach
detach:
	$(SUDO) ip netns exec host0 ip link set dev h0 xdp off

.PHONY: topology
topology:
	$(MAKE) -C ../ topology TOPO=pair

.PHONY: clean-topology
clean-topology:
	$(MAKE) -C ../ clean-topology

.PHONY: log
log:
	$(SUDO) cat /sys/kernel/debug/tracing/trace_pipe

/usr/include/asm:
	$(SUDO) ln -s /usr/include/asm-generic /usr/include/asm
