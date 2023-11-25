
SUDO ?= sudo
HEADER_DIR := ./tutorial/include
VMLINUX := $(HEADER_DIR)/vmlinux.h
BPFTOOL := /usr/local/sbin/bpftool
PWRU := /usr/local/go/bin/pwru
TEST_APP := ./app/app

GO_VERSION := 1.20.7
PWRU_VERSION := 0.0.9

.PHONY: setup
setup: vmlinux
	$(SUDO) apt update -y
	$(SUDO) apt install -y git unzip libelf-dev zlib1g zlib1g-dev libbpf-dev pkg-config clang llvm lldb gcc curl vim tcpdump net-tools jq hping3 telnetd nmap
	$(SUDO) apt install -y nginx
	$(SUDO) systemctl stop nginx 2>/dev/null || true # in container, this line is failed
	$(SUDO) systemctl disable nginx 2>/dev/null || true # in container, this line is failed

.PHONY: setup-golang
setup-golang:
	$(SUDO) curl -sSLf https://dl.google.com/go/go$(GO_VERSION).linux-amd64.tar.gz | $(SUDO) tar -C /usr/local -xzf -
	echo "export PATH=$$PATH:/usr/local/go/bin" >> $(HOME)/.bashrc

.PHONY: bpftool
bpftool: $(BPFTOOL)
$(BPFTOOL):
	git clone --recurse-submodules https://github.com/libbpf/bpftool.git
	cd bpftool && \
	git submodule update --init && \
	cd src && \
	$(MAKE) && \
	$(SUDO) $(MAKE) install

.PHONY: pwru
pwru: $(PWRU)
$(PWRU):
	git clone --depth 1 -b v$(PWRU_VERSION) https://github.com/cilium/pwru.git
	cd pwru && \
	$(MAKE) && \
	$(SUDO) cp pwru /usr/local/bin

.PHONY: vmlinux
vmlinux: $(VMLINUX) $(BPFTOOL)
$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)


TOPO ?= "pair"

.PHONY: topology
topology: clean-topology
	$(SUDO) sysctl -w net.ipv4.ip_forward=1
ifeq "$(TOPO)" "pair"
	$(SUDO) topology/pair.sh
endif
ifeq "$(TOPO)" "line"
	$(SUDO) topology/line.sh
endif
ifeq "$(TOPO)" "tree"
	$(SUDO) topology/tree.sh
endif

.PHONY: clean-topology
clean-topology:
	$(SUDO) ip netns del host0 2>/dev/null || true
	$(SUDO) ip netns del host1 2>/dev/null || true
	$(SUDO) ip netns del host2 2>/dev/null || true
	$(SUDO) ip netns del host3 2>/dev/null || true
	$(SUDO) ip netns del host4 2>/dev/null || true
	$(SUDO) ip netns del host5 2>/dev/null || true
	$(SUDO) ip netns del host6 2>/dev/null || true
	$(SUDO) ip netns del host7 2>/dev/null || true
	$(SUDO) ip link del dev vipdev 2>/dev/null || true

NGINX_CONF := nginx/nginx.conf
SERVER1 ?= app1
SERVER2 ?= app2
LB ?= "nginx"

.PHONY: app-docker
app-docker: $(NGINX_CONF)
	docker compose -f topology/docker-compose.yaml up

.PHONY: app-netns
app-netns: $(TEST_APP)
	mkdir -p ./run
	$(MAKE) TOPO=tree topology
	$(MAKE) SERVER1=10.0.4.2 SERVER2=10.0.5.2 $(NGINX_CONF)

ifeq "${LB}" "nginx"
	$(SUDO) ./topology/run-with-nginx.sh
else
	$(SUDO) ./topology/run.sh
endif

.PHONY: clean-app-netns
clean-app-netns:
	$(SUDO) kill -9 `cat ./run/app1.pid`
	$(SUDO) kill -9 `cat ./run/app2.pid`
	$(SUDO) kill -9 `cat ./run/nginx.pid` || true
	rm -rf ./run
	rm $(TEST_APP)


$(NGINX_CONF): clean-nginx-conf
	sed -e s/SERVER1/'${SERVER1}'/g \
		-e s/SERVER2/'${SERVER2}'/g \
		./nginx/nginx.conf.tmpl > $(NGINX_CONF)

.PHONY: clean-nginx-conf
clean-nginx-conf:
	rm $(NGINX_CONF) 2>/dev/null || true

.PHONY: build-test-app
build-test-app: $(TEST_APP)
$(TEST_APP):
	cd app; go build -o app main.go

.PHONY: clean-test-app
clean-test-app:
	rm $(TEST_APP)
