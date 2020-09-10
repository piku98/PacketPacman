package main

import (
	"fmt"
	"io/ioutil"
	"log"

	tf "github.com/tensorflow/tensorflow/tensorflow/go"
)

func main() {
	var (
		graph *tf.Graph
	)
	model, err := ioutil.ReadFile("keras_op_folder/output_model_name.pb")

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	graph = tf.NewGraph()
	if err := graph.Import(model, ""); err != nil {
		fmt.Println(err)
	}

	session, err := tf.NewSession(graph, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	a := make([][18]float32, 1)
	a[0][0] = 0.00892857
	a[0][1] = 0.00016409
	a[0][2] = 0.00892857
	a[0][3] = 0.00658557
	a[0][4] = 0
	a[0][5] = 0.00571745

	tensor, _ := tf.NewTensor(a)

	result, err := session.Run(
		map[tf.Output]*tf.Tensor{
			graph.Operation("puski_input").Output(0): tensor,
		},
		[]tf.Output{
			graph.Operation("outputlayer/Softmax").Output(0),
		},
		nil,
	)

	if err != nil {
		fmt.Printf(err.Error())
		return
	}

	fmt.Println(result[0].Value())

}
