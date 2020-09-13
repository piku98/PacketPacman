package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"gitlab.com/grey_scale/packetpacman/tests-and-analysis/clientsidetest.git/model"

	"github.com/google/gopacket/layers"
	"gitlab.com/clientsidetest/model"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"gitlab.com/grey_scale/packetpacman/tests-and-analysis/clientsidetest.git/controllers"
)

<<<<<<< HEAD
=======

}

func processTCPlayer()
{

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


>>>>>>> 1b757a12db0c91303b14f136aea74d9bcf932f0a
type ProcessedAndRawData struct {
	ProcessedPacket model.Packet
	RawPacket       string
}

func main() {
	var wg sync.WaitGroup
	wg.Add(1)

	processPacketJobs := make(chan gopacket.Packet)
	processPacketlevel1Results := make(chan ProcessedAndRawData)
	processPacketlevel2Results := make(chan []byte)

	networkJobs := make(chan []byte)
	networkResults := make(chan controllers.MLServerResponse)

	//worker go functions (threads) for processing packet the data. Extracts data from packets in the queue from the channel concurrently.
	//Increase number of these functions depending on the load. In high load conditions 4 or 5 concurrent workers maybe required
	go processWorker(processPacketJobs, processPacketlevel1Results, processPacketlevel2Results)
	go processWorker(processPacketJobs, processPacketlevel1Results, processPacketlevel2Results)

	//worker go functions for handling requests to ML server. Increase number of functions for high load.
	go networkWorker(networkJobs, networkResults)
	go networkWorker(networkJobs, networkResults)

	handle, err := pcap.OpenLive("eth0", 1024, false, time.Second*1) //support for various interfaces
	if err != nil {
		panic(err)
	}

	go func() {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			processPacketJobs <- packet
		}
		close(processPacketJobs)
	}()

	go func() {
		for packetData := range processPacketlevel1Results {
			networkJobs <- packetData
		}
		close(networkJobs)
	}()

	go func() {
		for json := range processPacketlevel2Results {
			networkJobs <- json
		}
		close(networkJobs)
	}()

	go func() {
		for resp := range networkResults {
			//fmt.Println(resp)
			processResponse(resp)
		}
	}()
	wg.Wait()

}

func processWorker(jobs <-chan gopacket.Packet, processPacketlevel1Results chan<- ProcessedAndRawData, processPacketlevel2Results chan<- []byte) {
	for packet := range jobs {
		data := processPacket(packet)
		processPacketlevel1Results <- data
		dataJSON, _ := json.Marshal(data)
		processPacketlevel2Results <- dataJSON
	}
	close(processPacketlevel1Results)
	close(processPacketlevel2Results)
}

func networkWorker(jobs <-chan []byte, results chan<- controllers.MLServerResponse) {
	for bytes := range jobs {
		results <- controllers.SendPackets(bytes)
	}
	close(results)
}

func processPacket(packet gopacket.Packet) ProcessedAndRawData {
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
	fmt.Println(iplayerinterface.SrcIP)
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
	data := ProcessedAndRawData{
		ProcessedPacket: Packet{
			IPLayer:  iplayerinterface,
			TCPLayer: tcplayerinterface,
		},
		RawPacket: packet.String(),
	}
	return data
<<<<<<< HEAD
=======

}

type MLServerResponse struct {
	Flag    uint8
	IP      string
	Message string
	Err     error
>>>>>>> 1b757a12db0c91303b14f136aea74d9bcf932f0a
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
	//check for error
	//check flag
	//check ip
	//if flag = 3 call blockIP
	//else if flag = 2 inform user
	//else if flag = 1 all cool
	//log message from the server
}
