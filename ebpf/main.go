package ebpf

import (
	"C"
)

//go:generate bash -c "echo KERNEL: $KERNEL"
//go:generate bash -c "go run github.com/cilium/ebpf/cmd/bpf2go $BPF_GO_FUNCTION_NAME $BPF_SOURCE -- -I{KERNEL} -I."
