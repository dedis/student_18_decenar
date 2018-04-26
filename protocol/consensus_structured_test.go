package protocol

import (
	"testing"
	"time"

	"github.com/dedis/student_18_decenar/lib"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/cothority.v2"
	"gopkg.in/dedis/kyber.v2/util/key"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

// variables used to run the test
var website = "http://nibelung.ch/decenarch/100p.html"
var bf []int64 = []int64{1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1}

func TestConsensusStructured(t *testing.T) {
	nodes := []int{3, 5, 7}
	for _, nbrNodes := range nodes {
		log.Lvlf1("Starting consensus for structured data with %d nodes", nbrNodes)
		consensusStructured(t, nbrNodes)
	}
}

func consensusStructured(t *testing.T, nbrNodes int) {
	log.Lvl1("Running", nbrNodes, "nodes")
	local := onet.NewLocalTest(cothority.Suite)
	defer local.CloseAll()
	_, _, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes, true)
	log.Lvl3(tree.Dump())

	// create the protocol
	pi, err := local.CreateProtocol(NameConsensusStructured, tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}

	// configure the protocol
	protocol := pi.(*ConsensusStructuredState)

	// define URL
	protocol.Url = "http://nibelung.ch/decenarch/100p.html"

	// we don't use DKG to test, but a simple random key
	// note that DKG is tested somewhere else
	pair := key.NewKeyPair(cothority.Suite)
	protocol.SharedKey = pair.Public

	// set arbitrary threshold
	protocol.Threshold = uint32(nbrNodes - 1)

	// start the protocol
	err = protocol.Start()
	require.Nil(t, err)
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
	for i := range bf {
		bf[i] *= int64(nbrNodes)
	}

	return bf
}
