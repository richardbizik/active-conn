package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type connKey struct {
	Saddr uint32
	Dport uint16
	Daddr uint32
}

type connData struct {
	created time.Time
	bpfEvent
}

var openConnections = make(map[connKey]connData)
var rbReader *ringbuf.Reader
var event bpfEvent
var objs bpfObjects
var ltcpSetState link.Link

func StopEBPF() {
	if err := rbReader.Close(); err != nil {
		log.Fatalf("closing ringbuf reader: %s", err)
	}
	objs.TcpSetState.Unpin()
	objs.Events.Unpin()
	ltcpSetState.Unpin()
	objs.Close()
	ltcpSetState.Close()
}

func InitEBPF() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs = bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	var err error
	ltcpSetState, err = link.AttachTracing(link.TracingOptions{
		Program: objs.TcpSetState,
	})
	if err != nil {
		log.Fatal(err)
	}

	rbReader, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}

	go startEBPFLoop()
}

func startEBPFLoop() {
	var localhost = uint32(2130706433)
	for {
		record, err := rbReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		if (event.Saddr == localhost && event.Daddr == localhost) ||
			event.Sport == 0 {
			continue
		}

		// fmt.Printf("%-18s %-15s %-6d -> %-15s %-6d %-5d\n",
		// 	B2S(event.Comm),
		// 	intToIP(event.Saddr),
		// 	event.Sport,
		// 	intToIP(event.Daddr),
		// 	event.Dport,
		// 	event.State,
		// )
		switch event.State {
		case TCP_ESTABLISHED:
			openConnections[connKey{
				Saddr: event.Saddr,
				Daddr: event.Daddr,
				Dport: event.Dport,
			}] = connData{bpfEvent: event, created: time.Now()}
		case TCP_CLOSE:
			delete(openConnections, connKey{
				Dport: event.Dport,
				Saddr: event.Saddr,
				Daddr: event.Daddr,
			})
		default:
			fmt.Printf("Unhandled state %d", event.State)
		}
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}

func B2S(bs [16]uint8) string {
	b := make([]byte, len(bs))
	for i, v := range bs {
		b[i] = byte(v)
	}
	b = bytes.Trim(b, "\x00")
	return string(b)
}
