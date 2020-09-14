package MLInterface

import (
	"gitlab.com/grey_scale/packetpacman/tests-and-analysis/clientsidetest.git/models"
)

type MLModel interface {
	Analyze(models.ProcessedAndRawPacketData) (PacketAnalysisResult, error)
}

type TensorflowNN struct {
}

type PP struct {
}

func (t TensorflowNN) Analyze(data models.ProcessedAndRawPacketData) (PacketAnalysisResult, error) {
	temp := PacketAnalysisResult{
		SrcIP:  data.ProcessedPacket.IPLayer.SrcIP,
		SrcPrt: data.ProcessedPacket.TCPLayer.SrcPort,
		DstPrt: data.ProcessedPacket.TCPLayer.DstPort,
		Flag:   0,
	}
	return temp, nil
}

func (p PP) Analyze(data models.ProcessedAndRawPacketData) (PacketAnalysisResult, error) {
	temp := PacketAnalysisResult{
		SrcIP:  data.ProcessedPacket.IPLayer.SrcIP,
		SrcPrt: data.ProcessedPacket.TCPLayer.SrcPort,
		DstPrt: data.ProcessedPacket.TCPLayer.DstPort,
		Flag:   1,
	}
	return temp, nil
}

type PacketAnalysisResult struct {
	SrcIP  string
	SrcPrt string
	DstPrt string
	Flag   uint
}
