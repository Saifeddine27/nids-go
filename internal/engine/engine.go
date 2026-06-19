package engine

import (
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/Saifeddine27/nids-go/internal/alert"
	"github.com/Saifeddine27/nids-go/internal/config"
	"github.com/Saifeddine27/nids-go/internal/parser"
)

type Engine struct {
	PortScanMem map[string]map[uint16]time.Time
	ICMPMem     map[string]map[string]time.Time
}

type CompiledRule struct {
	Nom         string
	Description string
	CompiledExp *regexp.Regexp
}

func NewEngine() *Engine {
	return &Engine{
		PortScanMem: make(map[string]map[uint16]time.Time),
		ICMPMem:     make(map[string]map[string]time.Time),
	}
}
func CompileRules(cfg *config.Config) []CompiledRule {
	tab := make([]CompiledRule, 0)
	for _, rule := range cfg.Rules {
		compExp, err := regexp.Compile(rule.Pattern)
		if err != nil {
			fmt.Printf("Erreur lors de la compilation de la règle %s : %v\n", rule.Name, err)
			return nil
		}

		compRule := CompiledRule{
			Nom:         rule.Name,
			Description: rule.Description,
			CompiledExp: compExp,
		}
		tab = append(tab, compRule)
	}

	return tab

}

func (e *Engine) Process(ne parser.NetworkEvent) {
	window := 10 * time.Second
	now := time.Now()
	ip := ne.IPSource.String()

	if _, exists := e.PortScanMem[ip]; !exists {
		e.PortScanMem[ip] = make(map[uint16]time.Time)
	}

	e.PortScanMem[ip][ne.DestPort] = now

	for port, t := range e.PortScanMem[ip] {
		if now.Sub(t) > window {
			delete(e.PortScanMem[ip], port)
		}
	}

	uniquePorts := len(e.PortScanMem[ip])

	if uniquePorts >= 15 {
		alerte := &alert.AlertInfos{
			Time:        time.Now(),
			IpSrc:       net.ParseIP(ip),
			AttaqueType: "PORT_SCAN",
			DegreAlert:  "CRITICAL",
			Description: fmt.Sprintf("%d ports uniques ciblés en moins de 10s", uniquePorts),
		}
		alert.LogAlert(alerte)
		fmt.Printf("[+] ALERTE CRITIQUE LOGGUÉE : Scan de ports depuis %s\n", ip)

	} else if uniquePorts >= 5 {
		alerte := &alert.AlertInfos{
			Time:        time.Now(),
			IpSrc:       net.ParseIP(ip),
			AttaqueType: "PORT_SCAN",
			DegreAlert:  "WARNING",
			Description: fmt.Sprintf("%d ports uniques ciblés en moins de 10s", uniquePorts),
		}
		alert.LogAlert(alerte)
		fmt.Printf("[-] ALERTE WARNING LOGGUÉE : Activité suspecte sur les ports depuis %s\n", ip)
	}
}

func (e *Engine) DetectorPingSweep(ne parser.NetworkEvent) {
	window := 10 * time.Second
	now := time.Now()
	ipSrc := ne.IPSource.String()
	ipDst := ne.IPDest.String()

	if _, exists := e.ICMPMem[ipSrc]; !exists {
		e.ICMPMem[ipSrc] = make(map[string]time.Time)
	}

	e.ICMPMem[ipSrc][ipDst] = now

	for dst, t := range e.ICMPMem[ipSrc] {
		if now.Sub(t) > window {
			delete(e.ICMPMem[ipSrc], dst)
		}
	}

	uniqueHosts := len(e.ICMPMem[ipSrc])

	if uniqueHosts >= 10 {
		alerte := &alert.AlertInfos{
			Time:        time.Now(),
			IpSrc:       net.ParseIP(ipSrc),
			AttaqueType: "PING_SWEEP",
			DegreAlert:  "CRITICAL",
			Description: fmt.Sprintf("%d hôtes uniques pingués en moins de 10s", uniqueHosts),
		}
		alert.LogAlert(alerte)
		fmt.Printf("[+] ALERTE CRITIQUE LOGGUÉE : Ping Sweep depuis %s\n", ipSrc)

	} else if uniqueHosts >= 4 {
		alerte := &alert.AlertInfos{
			Time:        time.Now(),
			IpSrc:       net.ParseIP(ipSrc),
			AttaqueType: "PING_SWEEP",
			DegreAlert:  "WARNING",
			Description: fmt.Sprintf("%d hôtes uniques pingués en moins de 10s", uniqueHosts),
		}
		alert.LogAlert(alerte)
		fmt.Printf("[-] ALERTE WARNING LOGGUÉE : Activité ICMP suspecte depuis %s\n", ipSrc)
	}
}
