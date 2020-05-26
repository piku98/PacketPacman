package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Packet struct {
	IPLayer  IPLayer  `json:iplayer`
	TCPLayer TCPLayer `json:tcplayer`
}

type IPLayer struct {
	SrcIP      string `json:srcip`
	DstIP      string `json:dstip`
	Version    uint8  `json:version`
	IHL        uint8  `json:ihl`
	TOS        uint8  `json:tos`
	Length     uint16 `json:length`
	ID         uint16 `json:id`
	Flags      string `json:flags`
	FragOffset uint16 `json:frag_offeset`
	TTL        uint8  `json:ttl`
}

type TCPLayer struct {
	SrcPort      string `json:srcport`
	DstPost      string `json:dstport`
	Seq          uint32 `json:seq`
	Ack          uint32 `json:ack`
	DataOffset   uint8  `json:data_offset`
	Window       uint16 `json:window`
	Checksum     uint16 `json:checksum`
	Urgent       uint16 `json:urgent`
	HeaderLength int    `json:header_length`
	FlagFIN      bool   `json:flag_fin`
	FlagSYN      bool   `json:flag_sin`
	FlagRST      bool   `json:flag_rst`
	FlagPSH      bool   `json:flag_psh`
	FlagACK      bool   `json:flag_ack`
	FlagURG      bool   `json:flag_urg`
	FlagECE      bool   `json:flag_ece`
	FlagCWR      bool   `json:flag_cwr`
	FlagNS       bool   `json:flag_ns`
}

func main() {
	var wg sync.WaitGroup
	wg.Add(1)

	processJobs := make(chan gopacket.Packet)
	processResults := make(chan []byte)

	networkJobs := make(chan []byte)
	networkResults := make(chan error)

	go processWorker(processJobs, processResults)
	go networkWorker(networkJobs, networkResults)

	handle, err := pcap.OpenLive("wlp2s0", 1024, false, time.Second*1)
	if err != nil {
		panic(err)
	}

	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			processJobs <- packet
		}
		close(processJobs)
	}()

	go func() {
		for json := range processResults {
			networkJobs <- json
		}
		close(networkJobs)
	}()

	go func() {
		for err := range networkResults {
			if err != nil {
				fmt.Println(err)
			}
		}
	}()
	wg.Wait()

}

func processWorker(jobs <-chan gopacket.Packet, results chan<- []byte) {
	for packet := range jobs {
		results <- processPacket(packet)
	}
	close(results)
}

func networkWorker(jobs <-chan []byte, results chan<- error) {
	for bytes := range jobs {
		results <- sendPackets(bytes)
	}
	close(results)
}

func sendPackets(data []byte) error {
	req, _ := http.NewRequest("POST", "http://localhost:4000", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return errors.New(string(body))
	}
	return nil
}

func processPacket(packet gopacket.Packet) []byte {
	var iplayerinterface IPLayer
	var tcplayerinterface TCPLayer
	iplayer := packet.Layer(layers.LayerTypeIPv4)
	if iplayer != nil {
		ip, _ := iplayer.(*layers.IPv4)
		iplayerinterface = IPLayer{
			SrcIP:      ip.SrcIP.String(),
			DstIP:      ip.DstIP.String(),
			Version:    ip.Version,
			IHL:        ip.IHL,
			TOS:        ip.TOS,
			Length:     ip.Length,
			ID:         ip.Id,
			Flags:      ip.Flags.String(),
			FragOffset: ip.FragOffset,
			TTL:        ip.TTL,
		}

	}
	tcplayer := packet.Layer(layers.LayerTypeTCP)
	if tcplayer != nil {
		tcp, _ := tcplayer.(*layers.TCP)

		tcplayerinterface = TCPLayer{
			SrcPort:      tcp.SrcPort.String(),
			DstPost:      tcp.DstPort.String(),
			Seq:          tcp.Seq,
			Ack:          tcp.Ack,
			DataOffset:   tcp.DataOffset,
			Window:       tcp.Window,
			Checksum:     tcp.Checksum,
			Urgent:       tcp.Urgent,
			HeaderLength: len(tcp.Contents),
			FlagFIN:      tcp.FIN,
			FlagSYN:      tcp.SYN,
			FlagRST:      tcp.RST,
			FlagPSH:      tcp.PSH,
			FlagACK:      tcp.ACK,
			FlagURG:      tcp.URG,
			FlagECE:      tcp.ECE,
			FlagCWR:      tcp.CWR,
			FlagNS:       tcp.NS,
		}

	}
	var data struct {
		ProcessedPacket Packet `json:processed_packet`
		RawPacket       string `json:raw_packet`
	}
	data.ProcessedPacket = Packet{
		IPLayer:  iplayerinterface,
		TCPLayer: tcplayerinterface,
	}
	data.RawPacket = packet.String()
	dataJSON, _ := json.Marshal(data)
	return dataJSON

}
