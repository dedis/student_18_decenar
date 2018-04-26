package skipservice

import (
	"testing"

	decenarch "github.com/dedis/student_18_decenar"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/cothority.v2"
	"gopkg.in/dedis/onet.v2"
)

func TestService(t *testing.T) {
	local := onet.NewLocalTest(cothority.Suite)
	defer local.CloseAll()
	nodes, roster, _ := local.GenBigTree(3, 3, 1, true)
	s0 := local.GetServices(nodes, serviceID)[0].(*SkipService)
	s1 := local.GetServices(nodes, serviceID)[1].(*SkipService)
	s2 := local.GetServices(nodes, serviceID)[2].(*SkipService)
	services := []*SkipService{s0, s1, s2}
	_ = services

	// create genesis block and create new skichain
	rootStartResponse, err := s0.SkipRootStartRequest(&decenarch.SkipRootStartRequest{Roster: roster})
	require.NoError(t, err)
	require.NotNil(t, rootStartResponse.Block)

}
