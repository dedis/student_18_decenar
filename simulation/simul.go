package main

import (
	// Service needs to be imported here to be instantiated.
	_ "github.com/nblp/decenarch/service"
	"gopkg.in/dedis/onet.v1/simul"
)

func main() {
	simul.Start()
}
