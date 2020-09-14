package models

type ProcessedAndRawPacketData struct {
	ProcessedPacket Packet
	RawPacket       string
}

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
	DstPort      string
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
