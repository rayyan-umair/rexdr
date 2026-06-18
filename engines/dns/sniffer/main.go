/*
rexdr - DNS Behavioral Intelligence Engine
sniffer/main.go - Go sniffer entry point

Author  : Rayyan Umair
Date    : 2026-06-16
Purpose : Passive DNS capture on UDP/TCP port 53 using gopacket.
          Parses DNS queries and writes JSON events to stdout where
          the Python brain reads them via subprocess pipe.
          Uses raw IANA numeric values for any gopacket DNS type
          constants that may be undefined in the installed version,
          e.g. case 255 for ANY instead of layers.DNSTypeANY.
Contact : rayyanxumair@gmail.com
GitHub  : github.com/rayyan-umair/rexdr

"Hunt the whisper."

--- Part of the REXDR platform. ---
*/

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmsgprefix)
	log.SetPrefix("[REXDR-DNS-SNIFFER] ")

	log.Println("=== REXDR DNS Sniffer starting ===")

	iface := getEnv("CAPTURE_INTERFACE", "eth0")

	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Failed to open interface - iface=%s error=%v", iface, err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("udp port 53 or tcp port 53"); err != nil {
		log.Fatalf("Failed to set BPF filter - error=%v", err)
	}

	log.Printf("=== DNS Sniffer running - interface=%s ===", iface)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-sigCh:
			log.Println("Shutdown signal received")
			return
		case packet := <-packets:
			processPacket(packet)
		}
	}
}

func processPacket(packet gopacket.Packet) {
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok || len(dns.Questions) == 0 {
		return
	}

	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	srcIP := networkLayer.NetworkFlow().Src().String()

	for _, q := range dns.Questions {
		event := buildEvent(dns, q, srcIP)
		output, err := json.Marshal(event)
		if err != nil {
			log.Printf("JSON marshal error - error=%v", err)
			continue
		}
		fmt.Println(string(output))
	}
}

func buildEvent(dns *layers.DNS, q layers.DNSQuestion, srcIP string) map[string]interface{} {
	responseCode := "NOERROR"
	resolvedIPs := []string{}

	if dns.QR {
		responseCode = dnsResponseCodeToString(dns.ResponseCode)
		for _, a := range dns.Answers {
			if a.IP != nil {
				resolvedIPs = append(resolvedIPs, a.IP.String())
			}
		}
	}

	return map[string]interface{}{
		"id":            fmt.Sprintf("%d_%s_%d", time.Now().UnixNano(), srcIP, q.Type),
		"source_ip":     srcIP,
		"query_name":    string(q.Name),
		"query_type":    dnsTypeToString(q.Type),
		"response_code": responseCode,
		"resolved_ips":  resolvedIPs,
		"timestamp":     time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}

func dnsTypeToString(t layers.DNSType) string {
	switch t {
	case layers.DNSTypeA:
		return "A"
	case layers.DNSTypeNS:
		return "NS"
	case layers.DNSTypeCNAME:
		return "CNAME"
	case layers.DNSTypeSOA:
		return "SOA"
	case layers.DNSTypePTR:
		return "PTR"
	case layers.DNSTypeMX:
		return "MX"
	case layers.DNSTypeTXT:
		return "TXT"
	case layers.DNSTypeAAAA:
		return "AAAA"
	case layers.DNSTypeSRV:
		return "SRV"
	case 255: // ANY - IANA numeric value, replaces layers.DNSTypeANY
		return "ANY"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func dnsResponseCodeToString(code layers.DNSResponseCode) string {
	switch code {
	case layers.DNSResponseCodeNoErr:
		return "NOERROR"
	case layers.DNSResponseCodeFormErr:
		return "FORMERR"
	case layers.DNSResponseCodeServFail:
		return "SERVFAIL"
	case layers.DNSResponseCodeNXDomain:
		return "NXDOMAIN"
	case layers.DNSResponseCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", code)
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
