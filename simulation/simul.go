package main

import (
	// Service needs to be imported here to be instantiated.
	_ "github.com/dedis/student_18_decenar/service"
	"gopkg.in/dedis/onet.v2/simul"
)

func main() {
	simul.Start()
}
