package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/miekg/dns"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type event -cc clang -cflags "-O2 -g -Wall -Werror" bpf dns_snoop_kern.c -- -I../headers

// NetToHostShort converts a 16-bit integer from network to host byte order, aka "ntohs"
func NetToHostShort(i uint16) uint16 {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, i)
	return binary.LittleEndian.Uint16(data)
}

func ipv6ArrayToString(ipv6Array [16]byte) string {
	ip := net.IP(ipv6Array[:])
	return ip.String()
}

func ipv4ArrayToString(ipv4Array [4]byte) string {
	ip := net.IP(ipv4Array[:])
	return ip.String()
}

func main() {
	ifaceName := "lo"

	if len(os.Args) > 1 {
		ifaceName = os.Args[len(os.Args)-1]
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	l_ingress, err := link.AttachTCX(link.TCXOptions{
		Program:   objs.TcDnsSnoop,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("could not attach eBPF program: %s", err)
	}
	defer l_ingress.Close()

	if ifaceName != "lo" {
		// do not handle both ingress & egress on lo, this is kinda useless.
		l_egress, err := link.AttachTCX(link.TCXOptions{
			Program:   objs.TcDnsSnoop,
			Interface: iface.Index,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			log.Fatalf("could not attach eBPF program: %s", err)
		}
		defer l_egress.Close()

	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		rawPayload := event.Payload[0:event.Len]

		msg := new(dns.Msg)
		err = msg.Unpack(rawPayload)
		if err != nil {
			log.Println(err)
			continue
		}

		kind := "Request"
		if msg.Response {
			kind = "Response"
		}

		src := "n/a"
		dst := "n/a"

		switch NetToHostShort(event.Protocol) {
		case syscall.ETH_P_IP:
			src = ipv4ArrayToString(event.V4S_addr)
			dst = ipv4ArrayToString(event.V4D_addr)
		case syscall.ETH_P_IPV6:
			src = ipv6ArrayToString(event.V6S_addr)
			dst = ipv6ArrayToString(event.V6D_addr)
		}

		fmt.Printf("=== %s (%s -> %s) ===\n", kind, src, dst)
		fmt.Println(msg)
	}
}
