// mapprobe runs only inside the disposable VM; no workstation BPF attachment.
package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func endpoint() string {
	b, e := exec.Command("k3s", "kubectl", "-n", "asservat-lab", "get", "endpointslices", "-l", "kubernetes.io/service-name=sink", "-o", "json").Output()
	must(e)
	var s struct {
		Items []struct {
			Endpoints []struct {
				Addresses  []string
				Conditions struct{ Ready *bool }
			}
		}
	}
	must(json.Unmarshal(b, &s))
	for _, i := range s.Items {
		for _, e := range i.Endpoints {
			if e.Conditions.Ready != nil && *e.Conditions.Ready && len(e.Addresses) > 0 {
				return e.Addresses[0]
			}
		}
	}
	return ""
}
func main() {
	if _, e := os.Stat("/root/ASSERVAT_DISPOSABLE_VM"); e != nil {
		panic("VM guard absent")
	}
	spec, e := ebpf.LoadCollectionSpec("/root/peers.bpf.o")
	must(e)
	c, e := ebpf.NewCollection(spec)
	must(e)
	defer c.Close()
	iface, e := net.InterfaceByName("cni0")
	must(e)
	l, e := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: c.Programs["observe"], Attach: ebpf.AttachTCXEgress})
	must(e)
	defer l.Close()
	info, e := c.Programs["observe"].Info()
	must(e)
	programID, _ := info.ID()
	links := 1
	transmitErrors := 0
	type row struct {
		Generation     uint32
		Peer           string
		Packets        uint64
		StartMS, EndMS int64
	}
	var rows []row
	start := time.Now()
	old := ""
	var g uint32
	var previous *ebpf.Map
	for time.Since(start) < 18*time.Second {
		ip := endpoint()
		targetIP := ip
		if time.Since(start) > 14*time.Second && time.Since(start) < 15*time.Second {
			ip = ""
		}
		if ip != old || g == 0 {
			g++
			m, e := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 64})
			must(e)
			if ip != "" {
				addr := net.ParseIP(ip).To4()
				if addr == nil {
					panic("expected v4 fixture")
				}
				key := binary.LittleEndian.Uint32(addr)
				must(m.Update(key, g, ebpf.UpdateAny))
			}
			must(c.Maps["peers"].Update(uint32(0), m, ebpf.UpdateAny))
			if previous != nil {
				previous.Close()
			}
			previous = m
			old = ip
			rows = append(rows, row{Generation: g, Peer: ip, StartMS: time.Since(start).Milliseconds()})
		}
		if targetIP != "" {
			conn, e := net.Dial("udp", net.JoinHostPort(targetIP, "58888"))
			must(e)
			for i := 0; i < 20; i++ {
				_, e = conn.Write([]byte("ASSERVAT-SYNTHETIC-MAP-PROBE"))
				if e != nil {
					transmitErrors++
				}
			}
			conn.Close()
		}
		time.Sleep(200 * time.Millisecond)
	}
	if previous != nil {
		previous.Close()
	}
	for i := range rows {
		must(c.Maps["counts"].Lookup(rows[i].Generation, &rows[i].Packets))
		rows[i].EndMS = time.Since(start).Milliseconds()
	}
	b, _ := json.MarshalIndent(map[string]any{"programID": programID, "attachments": links, "transmitErrors": transmitErrors, "generations": rows, "limitation": "Kubernetes relist + standalone TCX observer; NOT integrated Gadget emission or production watch/freshness authorization"}, "", "  ")
	fmt.Println(string(b))
	nonempty := 0
	for _, r := range rows {
		if strings.TrimSpace(r.Peer) != "" && r.Packets > 0 {
			nonempty++
		}
	}
	if nonempty < 2 {
		panic("expected traffic under two different actual Service endpoint generations")
	}
}
