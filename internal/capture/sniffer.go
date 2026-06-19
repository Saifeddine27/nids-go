package capture

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Sniffer struct {
	Interface string
}

func NewSniffer(iface string) *Sniffer {
	return &Sniffer{
		Interface: iface,
	}
}

func (s *Sniffer) Start(packetChan chan gopacket.Packet) {
	handle, err := pcap.OpenLive(s.Interface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("error opening interface %s: %v", s.Interface, err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetChan <- packet
	}
}
