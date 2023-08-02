
PROTOC_VERSION=22.3
PROTOC_GEN_GO_VERSION := 1.31.0
PROTOC_GEN_GO_GRPC_VERSON=1.3.0
PROTOC_GEN_DOC_VERSION=1.5.1 

SUDO := sudo
VMLINUX := bpf/include/vmlinux.h
PROTOC := PATH=$(PWD)/bin:'$(PATH)' $(PWD)/bin/protoc -I=$(PWD)/protobuf/include:.
BPFTOOL := /usr/local/sbin/bpftool
CLI := bin/scmlb
DAEMON := bin/scmlbd

.PHONY: setup
setup:
	curl -sfL -o protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-linux-x86_64.zip
	unzip -o protoc.zip bin/protoc 'include/*'
	mv include protobuf/
	rm -f protoc.zip
	GOBIN=$(PWD)/bin go install google.golang.org/protobuf/cmd/protoc-gen-go@v$(PROTOC_GEN_GO_VERSION)
	GOBIN=$(PWD)/bin go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v$(PROTOC_GEN_GO_GRPC_VERSON)
	GOBIN=$(PWD)/bin go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v$(PROTOC_GEN_DOC_VERSION)

.PHONY: build
build: generate-xdp pkg/rpc/scmlb.pb.go pkg/rpc/scmlb_grpc.pb.go $(CLI) $(DAEMON)

.PHONY: cli
cli: $(CLI)
$(CLI):
	mkdir -p bin
	go build -o bin/scmlb cmd/scmlb/main.go

.PHONY: daemon
daemon: $(DAEMON)
$(DAEMON):
	mkdir -p bin
	go build -o bin/scmlbd cmd/scmlbd/main.go

.PHONY: clean
clean:
	rm $(CLI)
	rm $(DAEMON)
	rm pkg/rpc/scmlb.pb.go 
	rm pkg/rpc/scmlb_grpc.pb.go
	find pkg/ -type f -name '*bpfe*' -delete

pkg/rpc/scmlb.pb.go: protobuf/scmlb.proto
	mkdir -p pkg/rpc
	$(PROTOC) --go_out=module=github.com/terassyi/seccamp-xdp/scmlb:pkg $<

pkg/rpc/scmlb_grpc.pb.go: protobuf/scmlb.proto
	mkdir -p pkg/rpc
	$(PROTOC) --go-grpc_out=module=github.com/terassyi/seccamp-xdp/scmlb:pkg $<

.PHONY: generate-xdp
generate-xdp:
	go generate ./...

.PHONY: vmlinux
vmlinux: $(VMLINUX)
$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

GC ?= --gc
.PHONY: devenv
devenv: 
	$(MAKE) -C ../ clean-topology
	$(MAKE) clean || true
	$(MAKE) build
	$(MAKE) -C ../ TOPO=tree topology
	$(SUDO) ip netns exec host2 bin/scmlbd start --upstream h2-h0 --vip 203.0.113.11 $(GC) --level -4

.PHONY: run-test-app
run-test-app:
	$(MAKE) -C ../ build-test-app
	mkdir -p ./run
	$(SUDO) ./run-test-app.sh

.PHONY: stop-test-app
stop-test-app:
	$(SUDO) kill -9 `cat ./run/app1.pid`
	$(SUDO) kill -9 `cat ./run/app2.pid`
	$(SUDO) kill -9 `cat ./run/app3.pid`
	rm -rf ./run

.PHONY: connectivity-test
connectivity-test:
	$(SUDO) ip netns exec host2 bin/scmlb lb set -n node5 -a 10.0.5.2 -c http://10.0.5.2:8080/health # host6 ns
	$(SUDO) ip netns exec host2 bin/scmlb lb set -n node4 -a 10.0.4.2 -c http://10.0.4.2:8080/health # host5 ns

	sleep 3

	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who
	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who
	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who
	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who

.PHONY: drain-test
drain-test:
	$(SUDO) ip netns exec host2 bin/scmlb lb get
	$(SUDO) ip netns exec host2 bin/scmlb lb drain --id 1

	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who
	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who
	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who
	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who

	$(SUDO) ip netns exec host2 bin/scmlb lb get
	$(SUDO) ip netns exec host2 bin/scmlb lb delete --id 1
	$(SUDO) ip netns exec host2 bin/scmlb lb get

.PHONY: add-backend-test
add-backend-test:
	$(SUDO) ip netns exec host2 bin/scmlb lb get
	$(SUDO) ip netns exec host2 bin/scmlb lb set -n node7 -a 10.0.6.2 -c http://10.0.6.2:8080/health
	$(SUDO) ip netns exec host2 bin/scmlb lb get

	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who
	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who
	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who
	$(SUDO) ip netns exec host1 curl -m 2 http://203.0.113.11:8080/who

.PHONY: firewall-test
firewall-test:
	$(SUDO) ip netns exec host3 ping -w 1 -c 1 203.0.113.11
	$(SUDO) ip netns exec host1 ping -w 1 -c 1 203.0.113.11

	@echo "INSERT ICMP DENY RULE"
	$(SUDO) ip netns exec host2 bin/scmlb fw set --network 10.0.2.0/24 --protocol icmp

	$(SUDO) ip netns exec host3 ping -w 1 -c 1 203.0.113.11 || true
	$(SUDO) ip netns exec host1 ping -w 1 -c 1 203.0.113.11

	$(SUDO) ip netns exec host4 curl -m 2 http://203.0.113.11:8080/who

	@echo "INSERT TCP DENY 8000-9000 RULE"
	$(SUDO) ip netns exec host2 bin/scmlb fw set --network 10.0.3.0/24 --protocol tcp --dst-port 8000-9000

	$(SUDO) ip netns exec host4 curl -m 2 http://203.0.113.11:8080/who || true

	$(SUDO) ip netns exec host2 bin/scmlb fw get
