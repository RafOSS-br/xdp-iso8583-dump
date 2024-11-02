GO_GENERATE_DIRECTIVE := ebpf/main.go

export BPF_SOURCE := main.bpf.c

BPF_GO_PACKAGE_NAME := ebpf

export BPF_GO_FUNCTION_NAME := Bpf
export KERNEL := /kernel/linux/usr/include/
.PHONY: run
run: build
	./bin/main

.PHONY: build
build: clean build-ebpf
	go build -o bin/main cmd/xdp-iso8583-dump/main.go
	chmod +x bin/main

.PHONY: build-ebpf
build-ebpf:
	go generate $(GO_GENERATE_DIRECTIVE)

.PHONY: clean
clean:
	rm -rf bin
	rm -rf ebpf/bpf*

.PHONY: log
log:
	cat /sys/kernel/debug/tracing/trace_pipe
