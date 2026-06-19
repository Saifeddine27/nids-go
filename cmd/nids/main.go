package main

import (
	"fmt"

	"github.com/Saifeddine27/nids-go/internal/capture"
	"github.com/Saifeddine27/nids-go/internal/engine"
	"github.com/Saifeddine27/nids-go/internal/filter"
	"github.com/Saifeddine27/nids-go/internal/parser"
	"github.com/google/gopacket"
)

func main() {
	/*devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	for _, dev := range devices {
		fmt.Println(dev.Name)
	}*/
	eng := engine.NewEngine()
	sniffer := capture.NewSniffer("wlp0s20f3")
	fmt.Println("Listening on:", sniffer.Interface)
	packetChan := make(chan gopacket.Packet)
	go sniffer.Start(packetChan)
	for packet := range packetChan {
		ne := parser.ParsePacket(packet)
		if filter.IsAllowed(ne) {
			if ne.Protocol == "TCP" || ne.Protocol == "UDP" {
				fmt.Printf("%s:%d --> %s:%d : %s\n", ne.IPSource, ne.SourcePort,
					ne.IPDest, ne.DestPort, ne.Protocol)
				eng.Process(*ne)
			} else if ne.Protocol == "ICMP" {
				eng.DetectorPingSweep(*ne)
			} else {
				return
			}
		}
	}
}
