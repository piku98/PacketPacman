package MLInterface

import (
	"gitlab.com/grey_scale/packetpacman/tests-and-analysis/clientsidetest.git/models"
)

type Controller struct {
	models []MLModel
}

func (c *Controller) SelectModels(types map[string]int) {
	for key, val := range types {
		for i := 0; i < val; i++ {
			switch key {
			case "tensorflownn":
				tensorflownn := TensorflowNN{}
				c.models = append(c.models, tensorflownn)
			case "pp":
				pp := PP{}
				c.models = append(c.models, pp)
			}
		}
	}
}

func (c *Controller) CommunicationLine(jobs <-chan models.ProcessedAndRawPacketData, results chan<- interface{}) {
	for data := range jobs {

	}
}
