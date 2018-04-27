package skipservice

import (
	"testing"
	"time"

	skip "github.com/dedis/student_18_decenar/skip"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/cothority.v2"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
)

func TestService(t *testing.T) {
	local := onet.NewLocalTest(cothority.Suite)
	defer local.CloseAll()
	nodes, roster, _ := local.GenBigTree(3, 3, 1, true)
	s0 := local.GetServices(nodes, serviceID)[0].(*SkipService)
	s1 := local.GetServices(nodes, serviceID)[1].(*SkipService)
	s2 := local.GetServices(nodes, serviceID)[2].(*SkipService)
	services := []*SkipService{s0, s1, s2}

	// create genesis block and create new skipchain
	rootStartResponse, err := s0.SkipRootStartRequest(&skip.SkipRootStartRequest{Roster: roster})
	require.NoError(t, err)
	require.NotNil(t, rootStartResponse.Block)

	// add other servers to skipchain
	for _, s := range services {
		time.Sleep(2 * time.Second)
		log.Lvl4("send SkipStartRequest to:", s.ServerIdentity)
		startResponse, err := s.SkipStartRequest(&skip.SkipStartRequest{Roster: roster, Genesis: rootStartResponse.Block})
		require.NoError(t, err)
		require.NotNil(t, startResponse)
	}

	// add data to the skipchainS

}
