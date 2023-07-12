
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
build: pkg/rpc/scmlb.pb.go pkg/rpc/scmlb_grpc.pb.go $(CLI) $(DAEMON)

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

pkg/rpc/scmlb.pb.go: protobuf/scmlb.proto
	mkdir -p pkg/rpc
	$(PROTOC) --go_out=module=github.com/terassyi/seccamp-xdp/scmlb:pkg/rpc $<

pkg/rpc/scmlb_grpc.pb.go: protobuf/scmlb.proto
	mkdir -p pkg/rpc
	$(PROTOC) --go-grpc_out=module=github.com/terassyi/seccamp-xdp/scmlb:pkg/rpc $<

.PHONY: vmlinux
vmlinux: $(VMLINUX)
$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
