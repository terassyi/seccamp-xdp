FROM --platform=$TARGETPLATFORM ubuntu:22.04 as builder

ARG TARGETARCH

RUN apt update -y \
	&& apt install -y make git unzip libelf-dev zlib1g zlib1g-dev libbpf-dev pkg-config clang llvm lldb gcc curl \
	&& git clone --recurse-submodules https://github.com/libbpf/bpftool.git \
	&& cd bpftool \
	&& git submodule update --init \
	&& cd src \
	&& make \
	&& make install



FROM --platform=$TARGETPLATFORM ubuntu:22.04

ARG TARGETARCH
ARG TARGETPLATFORM
ARG GO_VERSION=1.21.1
ARG PROTOC_VERSION=22.3
ARG PROTOC_GEN_GO_VERSION=1.31.0
ARG PROTOC_GEN_GO_GRPC_VERSON=1.3.0
ARG PROTOC_GEN_DOC_VERSION=1.5.1

ENV GOARCH=${TARGETARCH}
ENV GOPATH=/go
ENV PATH=/go/bin:/usr/local/go/bin:"$PATH"

COPY . /seccamp-xdp

RUN apt update -y \
	&& apt install -y curl git make libelf-dev zlib1g zlib1g-dev libbpf-dev pkg-config clang llvm lldb gcc iproute2 unzip iputils-ping

RUN rm -rf /usr/local/go \
	&& curl -sfL https://dl.google.com/go/go${GO_VERSION}.linux-${GOARCH}.tar.gz \
	| tar -x -z -C /usr/local -f - \
	&& mkdir -p /go/src \
	&& GOBIN=/usr/local/bin go install golang.org/x/tools/cmd/goimports@latest \
	&& GOBIN=/usr/local/bin go install golang.org/x/lint/golint@latest \
	&& GOBIN=/usr/local/bin go install honnef.co/go/tools/cmd/staticcheck@latest \
	&& GOBIN=/usr/local/bin go install github.com/gordonklaus/ineffassign@latest \
	&& GOBIN=/usr/local/bin go install github.com/tcnksm/ghr@latest \
	&& GOBIN=/usr/local/bin go install github.com/cybozu-go/golang-custom-analyzer/cmd/...@latest \
	&& rm -rf /go \
	&& mkdir -p /go/src

RUN case "$TARGETPLATFORM" in \
	"linux/arm64") echo "x86_64" > /arch.txt ;; \
	"linux/amd64") echo "aarch_64" > /arch.txt ;; \
	*) exit 1 ;; \
	esac

RUN curl -sfL -o protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-$(cat /arch.txt).zip \
	&& unzip -o protoc.zip bin/protoc 'include/*' \
	&& mv include protobuf/ \
	&& rm -f protoc.zip \
	&& go install google.golang.org/protobuf/cmd/protoc-gen-go@v${PROTOC_GEN_GO_VERSION} \
	&& go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v${PROTOC_GEN_GO_GRPC_VERSON} \
	&& go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v${PROTOC_GEN_DOC_VERSION}

COPY --from=builder /usr/local/sbin/bpftool /usr/local/bin/bpftool

WORKDIR /seccamp-xdp


CMD [ "/bin/bash" ]
