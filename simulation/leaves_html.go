package main

import (
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"

	decenarch "github.com/dedis/student_18_decenar"
	"github.com/dedis/student_18_decenar/service"
	"gopkg.in/dedis/onet.v2/simul/monitor"
)

func init() {
	onet.SimulationRegister("LeavesHTML", NewLeavesHTMLSimulation)
}

type LeavesHTMLSimulation struct {
	onet.SimulationBFTree

	Webpage string
}

// NewLeavesHTMLSimulation returns the new simulation, where all fields are
// initialised using the config-file
func NewLeavesHTMLSimulation(config string) (onet.Simulation, error) {
	es := &LeavesHTMLSimulation{}
	_, err := toml.Decode(config, es)
	if err != nil {
		return nil, err
	}
	return es, nil
}

// Setup creates the tree used for that simulation
func (s *LeavesHTMLSimulation) Setup(dir string, hosts []string) (
	*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000) // last argument indicates port
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

// Node can be used to initialize each node before it will be run
// by the server. Here we call the 'Node'-method of the
// SimulationBFTree structure which will load the roster- and the
// tree-structure to speed up the first round.
func (s *LeavesHTMLSimulation) Node(config *onet.SimulationConfig) error {
	index, _ := config.Roster.Search(config.Server.ServerIdentity.ID)
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	log.Lvl3("Initializing node-index", index)
	return s.SimulationBFTree.Node(config)
}

func (s *LeavesHTMLSimulation) Run(config *onet.SimulationConfig) error {
	size := config.Tree.Size()
	log.Lvl2("Size is:", size, "rounds:", s.Rounds)

	// create new client
	c := decenarch.NewClient()

	// run setup service
	_, err := c.Setup(config.Roster)
	if err != nil {
		log.Error(err)
	}

	// get appropiate service
	service := config.GetService("Decenarch").(*service.Service)
	for round := 0; round < s.Rounds; round++ {
		log.Lvl1("Starting round", round)
		completeRound := monitor.NewTimeMeasure("complete_round")

		// save
		log.Print("Webpage", s.Webpage)
		go service.SaveWebpage(&decenarch.SaveRequest{Url: s.Webpage, Roster: config.Roster})

		// monitor consensus on structured data
		<-service.StructuredConsensusChanStart
		consensusStructuredRound := monitor.NewTimeMeasure("consensus_structured")
		<-service.StructuredConsensusChanStop
		consensusStructuredRound.Record()

		// monitor decryption
		<-service.DecryptChanStart
		decryptRound := monitor.NewTimeMeasure("decrypt")
		<-service.DecryptChanStop
		decryptRound.Record()

		// monitor reconstruction
		<-service.ReconstructChanStart
		reconstructRound := monitor.NewTimeMeasure("reconstruct")
		<-service.ReconstructChanStop
		reconstructRound.Record()

		// monitor signature
		<-service.SignChanStart
		signatureRecord := monitor.NewTimeMeasure("sign")
		<-service.SignChanStop
		signatureRecord.Record()

		// we don't have additional data here
		<-service.AdditionalDataStart
		<-service.AdditionalDataStop

		// record complete round
		<-service.SaveStop
		completeRound.Record()

		time.Sleep(20 * time.Second)
	}

	return nil
}
