// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"
	lEbpf "xdp-iso8583-dump/ebpf"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I../headers

func main() {
	// Look up the network interface by name.
	ifaceName := "eth0"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := lEbpf.BpfObjects{}
	if err := lEbpf.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(objs.XdpStatsMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}

type value struct {
	CountInvalid uint32
	CountValid   uint32
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key netip.Addr
		val value
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := key
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%s => Valid Package: %d, Invalid Package: %d\n", sourceIP, packetCount.CountValid, packetCount.CountInvalid))
	}
	return sb.String(), iter.Err()
}
