package protocol

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/cothority.v2"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

func TestDecrypt(t *testing.T) {
	nodes := []int{3, 5, 7}
	for _, nbrNodes := range nodes {
		log.Lvlf1("Starting setupDKG with %d nodes", nbrNodes)
		decrypt(t, nbrNodes)
	}
}

func decrypt(t *testing.T, nbrNodes int) {
	log.Lvl1("Running", nbrNodes, "nodes")
	local := onet.NewLocalTest(cothority.Suite)
	defer local.CloseAll()
	_, _, tree := local.GenBigTree(nbrNodes, nbrNodes, nbrNodes, true)
	log.Lvl3(tree.Dump())

	pi, err := local.CreateProtocol(NameDecrypt, tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := pi.(*Decrypt)
	log.ErrFatal(pi.Start())
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*nbrNodes*2) * time.Millisecond
	select {
	case <-protocol.Finished:
		log.Lvl2("root-node is Done")
		require.NotNil(t, protocol.)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}

}
