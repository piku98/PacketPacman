package main

import (
	"fmt"
	"os/exec"
	"sync"

	"gitlab.com/grey_scale/packetpacman/tests-and-analysis/clientsidetest.git/models"

	"github.com/google/gopacket/layers"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"gitlab.com/grey_scale/packetpacman/tests-and-analysis/clientsidetest.git/MLInterface"
	"gitlab.com/grey_scale/packetpacman/tests-and-analysis/clientsidetest.git/controllers"
)

func main() {

	BUFFER_SIZE := 100
	var wg sync.WaitGroup
	wg.Add(1)

	processPacketJobs := make(chan gopacket.Packet, BUFFER_SIZE)
	processPacketlevel1Results := make(chan models.ProcessedAndRawPacketData, BUFFER_SIZE)
	processPacketlevel2Results := make(chan []byte, BUFFER_SIZE)

	level1Jobs := make(chan models.ProcessedAndRawPacketData, BUFFER_SIZE)
	level1Results := make(chan MLInterface.PacketAnalysisResult, BUFFER_SIZE)

	//networkJobs := make(chan []byte)
	//networkResults := make(chan models.MLServerResponse)

	go processWorker(processPacketJobs, processPacketlevel1Results, processPacketlevel2Results)
	go processWorker(processPacketJobs, processPacketlevel1Results, processPacketlevel2Results)

	go levelOneInterface(level1Jobs, level1Results)
	go levelOneInterface(level1Jobs, level1Results)

	//go networkWorker(networkJobs, networkResults)
	//go networkWorker(networkJobs, networkResults)

	handle, err := pcap.OpenLive("wlp2s0", 1600, true, pcap.BlockForever)
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
			level1Jobs <- packetData
		}
		close(level1Jobs)
	}()

	go func() {
		for results := range level1Results {
			fmt.Println(results)
		}
	}()

	/* go func() {
		for json := range processPacketlevel2Results {
			networkJobs <- json
		}
		close(networkJobs)
	}() */

	/* go func() {
		for resp := range networkResults {
			//fmt.Println(resp)
			processResponse(resp)
		}
	}() */
	wg.Wait()

}

func processWorker(jobs <-chan gopacket.Packet, processPacketlevel1Results chan<- models.ProcessedAndRawPacketData, processPacketlevel2Results chan<- []byte) {
	for packet := range jobs {
		data := processPacket(packet)
		processPacketlevel1Results <- data
		//dataJSON, _ := json.Marshal(data)
		//processPacketlevel2Results <- dataJSON
	}
	close(processPacketlevel1Results)
	//close(processPacketlevel2Results)
}

func levelOneInterface(jobs <-chan models.ProcessedAndRawPacketData, results chan<- MLInterface.PacketAnalysisResult) {
	for data := range jobs {
		temp := MLInterface.PacketAnalysisResult{
			SrcIP:  data.ProcessedPacket.IPLayer.SrcIP,
			SrcPrt: data.ProcessedPacket.TCPLayer.SrcPort,
			DstPrt: data.ProcessedPacket.TCPLayer.DstPort,
			Flag:   0,
		}
		results <- temp
	}
	close(results)
}

func networkWorker(jobs <-chan []byte, results chan<- models.MLServerResponse) {
	for bytes := range jobs {
		results <- controllers.SendPackets(bytes)
	}
	close(results)
}

func processPacket(packet gopacket.Packet) models.ProcessedAndRawPacketData {
	var iplayerinterface models.IPLayer
	var tcplayerinterface models.TCPLayer
	iplayer := packet.Layer(layers.LayerTypeIPv4)
	if iplayer != nil {
		ip, _ := iplayer.(*layers.IPv4)
		iplayerinterface = models.IPLayer{
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

		tcplayerinterface = models.TCPLayer{
			SrcPort:      tcp.SrcPort.String(),
			DstPort:      tcp.DstPort.String(),
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
	data := models.ProcessedAndRawPacketData{
		ProcessedPacket: models.Packet{
			IPLayer:  iplayerinterface,
			TCPLayer: tcplayerinterface,
		},
		RawPacket: packet.String(),
	}
	return data
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

func processResponse(resp models.MLServerResponse) {
	//check for error
	//check flag
	//check ip
	//if flag = 3 call blockIP
	//else if flag = 2 inform user
	//else if flag = 1 all cool
	//log message from the server
}
