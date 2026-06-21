package main

import (
	"fmt"

	"github.com/Saifeddine27/nids-go/internal/capture"
	"github.com/Saifeddine27/nids-go/internal/config"
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
	cfg, err := config.LoadConfig("rules/rules.yaml")
	if err != nil {
		fmt.Printf("Erreur fatale au démarrage : %v\n", err)
		return
	}
	compiledRules := engine.CompileRules(cfg)
	if compiledRules == nil {
		fmt.Println("Erreur fatale : Impossible de compiler les règles.")
		return
	}
	fmt.Printf("%d règles chargées avec succès.\n", len(compiledRules))

	eng := engine.NewEngine(compiledRules)
	sniffer := capture.NewSniffer("any")
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
				fmt.Printf("%s --> %s : %s\n", ne.IPSource, ne.IPDest, ne.Protocol)
				eng.DetectorPingSweep(*ne)
			} else {
				return
			}
		}
	}
}
