package protocol

import (
	"errors"
	"testing"
	"time"

	decenarch "github.com/dedis/student_18_decenar"
	"github.com/dedis/student_18_decenar/lib"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/cothority.v2"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/util/key"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

// variables used to run the test
var website = "http://nibelung.ch/decenarch/100p.html"
var bf []int64 = []int64{1, 0, 0, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0}

var consensusStructuredServiceID onet.ServiceID

type consensusStructuredService struct {
	*onet.ServiceProcessor

	SharedKey kyber.Point
}

func init() {
	new := func(ctx *onet.Context) (onet.Service, error) {
		return &consensusStructuredService{
			ServiceProcessor: onet.NewServiceProcessor(ctx),
		}, nil
	}
	consensusStructuredServiceID, _ = onet.RegisterNewService(NameConsensusStructured, new)
}

func (s *consensusStructuredService) NewProtocol(node *onet.TreeNodeInstance, conf *onet.GenericConfig) (
	onet.ProtocolInstance, error) {

	switch node.ProtocolName() {
	case NameConsensusStructured:
		instance, _ := NewConsensusStructuredProtocol(node)
		protocol := instance.(*ConsensusStructuredState)
		protocol.SharedKey = s.SharedKey
		return protocol, nil
	default:
		return nil, errors.New("Unknown protocol")
	}
}
func TestConsensusStructured(t *testing.T) {
	nodes := []int{3, 5, 7, 15}
	for _, nbrNodes := range nodes {
		log.Lvlf1("Starting consensus for structured data with %d nodes", nbrNodes)
		consensusStructured(t, nbrNodes)
	}
}

func consensusStructured(t *testing.T, nbrNodes int) {
	log.Lvl1("Running", nbrNodes, "nodes")
	local := onet.NewLocalTest(decenarch.Suite)
	defer local.CloseAll()

	nodes, _, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes, true)
	services := local.GetServices(nodes, consensusStructuredServiceID)

	// we don't use DKG to test, but a simple random key
	// note that DKG is tested somewhere else
	pair := key.NewKeyPair(cothority.Suite)

	// assign right key to every service
	for i := range services {
		services[i].(*consensusStructuredService).SharedKey = pair.Public
	}

	instance, _ := services[0].(*consensusStructuredService).CreateProtocol(NameConsensusStructured, tree)
	protocol := instance.(*ConsensusStructuredState)
	protocol.SharedKey = pair.Public
	protocol.Url = "http://nibelung.ch/decenarch/100p.html"
	err := protocol.Start()
	require.Nil(t, err)

	// start the protocol
	err = protocol.Start()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*nbrNodes*2) * time.Millisecond
	select {
	case <-protocol.Finished:
		log.Lvl1("Protocol is terminated")
		// decrypt the encrypted CBF set
		consensus := lib.DecryptIntVector(pair.Private, protocol.EncryptedCBFSet)
		require.Equal(t, multiplyByNbrNodes(bf, nbrNodes), consensus)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

func multiplyByNbrNodes(bf []int64, nbrNodes int) []int64 {
	tmp := make([]int64, len(bf))
	for i := range bf {
		tmp[i] = bf[i] * int64(nbrNodes)
	}

	return tmp
}
