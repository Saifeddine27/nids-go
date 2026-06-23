package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/Saifeddine27/nids-go/internal/capture"
	"github.com/Saifeddine27/nids-go/internal/config"
	"github.com/Saifeddine27/nids-go/internal/engine"
	"github.com/Saifeddine27/nids-go/internal/filter"
	"github.com/Saifeddine27/nids-go/internal/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		fmt.Printf("Erreur fatale lors de la recherche des interfaces : %v\n", err)
		return
	}

	fmt.Println("🌐 Interfaces réseau disponibles :")

	for i, dev := range devices {
		desc := dev.Description
		if desc == "" {
			desc = "Aucune description"
		}
		fmt.Printf("  [%d] %s (%s)\n", i, dev.Name, desc)
	}

	fmt.Print("\n👉 Entrez le nom de l'interface à écouter (ex: eth0, lo, wlan0) ou 'any' pour toutes : ")
	reader := bufio.NewReader(os.Stdin)
	selectedInterface, _ := reader.ReadString('\n')
	selectedInterface = strings.TrimSpace(selectedInterface)

	if selectedInterface == "" {
		selectedInterface = "any"
	}

	fmt.Println("--------------------------------------------------")

	cfg, err := config.LoadConfig("rules/rules.yaml")
	if err != nil {
		fmt.Printf("Erreur fatale au démarrage : %v\n", err)
		return
	}
	compiledRules, err := engine.CompileRules(cfg)
	if err != nil {
		fmt.Printf("Erreur fatale : impossible de compiler les règles : %v\n", err)
		return
	}
	fmt.Printf("%d règles chargées avec succès.\n", len(compiledRules))

	eng := engine.NewEngine(compiledRules)
	sniffer := capture.NewSniffer(selectedInterface)
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
			}
		}
	}
}
