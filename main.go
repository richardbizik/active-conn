package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/exp/slices"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -type event bpf fentry.c -- -Iheaders

// var stopper = make(chan struct{}, 1)
var stopper = make(chan os.Signal, 1)
var screenUpdateStopper = make(chan struct{}, 1)

func main() {
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		screenUpdateStopper <- struct{}{}
		StopEBPF()
	}()
	InitEBPF()
	updateScreenModel()
	fmt.Println("Connections left open:")
	for _, cd := range openConnections {
		fmt.Printf("%-27s %-18s %-15s %-6d -> %-15s %-6d %-8d\n",
			cd.created.Format(time.RFC3339),
			B2S(cd.Comm),
			intToIP(cd.Saddr),
			cd.Sport,
			intToIP(cd.Daddr),
			cd.Dport,
			cd.State,
		)
	}

}

func updateScreenModel() {
	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			data := make([]connData, 0, len(openConnections))
			for _, cd := range openConnections {
				data = append(data, cd)
			}
			slices.SortFunc[connData](data, func(a, b connData) bool {
				return a.created.Before(b.created)
			})
			draw(data)
		case <-screenUpdateStopper:
			ticker.Stop()
			return
		}
	}
}

func draw(data []connData) {
	fmt.Print("\033[2J")            //Clear screen
	fmt.Printf("\033[%d;%dH", 0, 0) // Set cursor position
	fmt.Printf("%-27s %-18s %-15s %-6s -> %-15s %-6s %-5s\n",
		"Time",
		"Comm",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
		"State",
	)
	fmt.Printf("-----------------------------------------------------------------------------------------------------\n")
	for _, cd := range data {
		fmt.Printf("%-27s %-18s %-15s %-6d -> %-15s %-6d %-5d\n",
			cd.created.Format(time.RFC3339),
			B2S(cd.Comm),
			intToIP(cd.Saddr),
			cd.Sport,
			intToIP(cd.Daddr),
			cd.Dport,
			cd.State,
		)
	}
}
