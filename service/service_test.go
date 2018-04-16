package service

import (
	"testing"

	"gopkg.in/dedis/cothority.v2"
	"gopkg.in/dedis/onet.v2"

	"github.com/dedis/student_18_decenar"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	local := onet.NewLocalTest(cothority.Suite)
	defer local.CloseAll()
	nodes, roster, _ := local.GenBigTree(3, 3, 1, true)
	s0 := local.GetServices(nodes, serviceID)[0].(*Service)
	s1 := local.GetServices(nodes, serviceID)[1].(*Service)
	s2 := local.GetServices(nodes, serviceID)[2].(*Service)
	services := []*Service{s0, s1, s2}

	// setup
	replySetup, err := s0.Setup(&decenarch.SetupRequest{Roster: roster})
	if err != nil {
		panic(err)
	}
	require.NotNil(t, replySetup.Key)
	for _, s := range services {
		require.Equal(t, replySetup.Key, s.key())
	}
}
