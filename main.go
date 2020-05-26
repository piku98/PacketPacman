package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"sync"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Packet struct {
	IPLayer  IPLayer
	TCPLayer TCPLayer
}

type IPLayer struct {
	SrcIP      string
	DstIP      string
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	ID         uint16
	Flags      string
	FragOffset uint16
	TTL        uint8
}

type TCPLayer struct {
	SrcPort      string
	DstPost      string
	Seq          uint32
	Ack          uint32
	DataOffset   uint8
	Window       uint16
	Checksum     uint16
	Urgent       uint16
	HeaderLength int
	FlagFIN      bool
	FlagSYN      bool
	FlagRST      bool
	FlagPSH      bool
	FlagACK      bool
	FlagURG      bool
	FlagECE      bool
	FlagCWR      bool
	FlagNS       bool
}

type MLServerResponse struct {
	Flag    uint8
	IP      string
	Message string
	Err     error
}

func main() {
	var wg sync.WaitGroup
	wg.Add(1)

	processJobs := make(chan gopacket.Packet)
	processResults := make(chan []byte)

	networkJobs := make(chan []byte)
	networkResults := make(chan MLServerResponse)

	//worker go functions (threads) for processing packet the data. Extracts data from packets in the queue from the channel concurrently.
	//Increase number of these functions depending on the load. In high load conditions 4 or 5 concurrent workers maybe required
	go processWorker(processJobs, processResults)
	go processWorker(processJobs, processResults)

	//worker go functions for handling requests to ML server. Increase number of functions for high load.
	go networkWorker(networkJobs, networkResults)
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
		for resp := range networkResults {
			fmt.Println(resp)
			processResponse(resp)
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

func networkWorker(jobs <-chan []byte, results chan<- MLServerResponse) {
	for bytes := range jobs {
		results <- sendPackets(bytes)
	}
	close(results)
}

func sendPackets(data []byte) MLServerResponse {
	req, _ := http.NewRequest("POST", "http://localhost:4000", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return MLServerResponse{Err: err}
	}
	serverResponse := MLServerResponse{}
	responseBody, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(responseBody, &serverResponse)

	return serverResponse

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
		ProcessedPacket Packet
		RawPacket       string
	}
	data.ProcessedPacket = Packet{
		IPLayer:  iplayerinterface,
		TCPLayer: tcplayerinterface,
	}
	data.RawPacket = packet.String()
	dataJSON, _ := json.Marshal(data)
	return dataJSON

}

func blockIP(IP string) {
	app := "iptables"
	arg0 := "-A"
	arg1 := "INPUT"
	arg2 := "-s"
	arg3 := IP
	arg4 := "-j"
	arg5 := "DROP"
	cmd := exec.Command(app, arg0, arg1, arg2, arg3, arg4, arg5)
	err := cmd.Run()
	if err != nil {
		fmt.Println("command err", err)
	}
}

func processResponse(resp MLServerResponse) {
	//check for errors
	//check flag
	//check ip
	//if flag = 3 call blockIP
	//else if flag = 2 inform user
	//else if flag = 1 all cool
	//log message from the server
}
