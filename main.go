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
	
        "gitlab.com/grey_scale/packetpacman/tests-and-analysis/clientsidetest.git/model"
        //"gitlab.com/clientsidetest/model" 
	"github.com/google/gopacket/layers"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)
/*
func processIPlayer(// see type) 
{
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


}
 */

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
	go processWorker(processJobs, processResults) // dynamic creation of new process workers in seperate go routine

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
		results <- processPacket(packet) //member function in struct 
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
	var iplayerinterface model.IPLayer
	var tcplayerinterface model.TCPLayer
	iplayer := packet.Layer(layers.LayerTypeIPv4)
	fmt.Printf("%T", iplayer)
	//if iplayer != nil {processIPlayer(iplayer)}
	tcplayer := packet.Layer(layers.LayerTypeTCP)
	//if tcplayer != nil {processTCPlayer(tcplayer) }
	model.PacketStatus.ProcessedPacket = model.Packet{
		IPLayer:  iplayerinterface,
		TCPLayer: tcplayerinterface,
	}
	model.PacketStatus.RawPacket = packet.String()
	dataJSON, _ := json.Marshal(data)
	return dataJSON

}

type MLServerResponse struct {
	Flag    uint8
	IP      string
	Message string
	Err     error
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
