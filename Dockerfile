FROM ubuntu:22.04

ENV GO_VERSION=1.20.5

RUN apt update -y && \
	apt install -y git make libelf-dev zlib1g zlib1g-dev libbpf-dev pkg-config clang llvm lldb gcc curl

WORKDIR /work

# install golang
RUN curl -sSLf https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xzf -

ENV GOPATH=/go
ENV PATH=/go/bin:/usr/local/go/bin:"$PATH"

# install bpftool
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git && \
	cd bpftool && \
	git submodule update --init && \
	cd src && \
	make && \
	make install

CMD [ "/bin/bash" ]
