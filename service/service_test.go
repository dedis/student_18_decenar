package service

import (
	"testing"
	"time"

	"gopkg.in/dedis/cothority.v2"
	"gopkg.in/dedis/onet.v2"

	decenarch "github.com/dedis/student_18_decenar"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	local := onet.NewLocalTest(cothority.Suite)
	defer local.CloseAll()
	nodes, roster, _ := local.GenBigTree(6, 6, 1, true)
	s0 := local.GetServices(nodes, serviceID)[0].(*Service)
	s1 := local.GetServices(nodes, serviceID)[1].(*Service)
	s2 := local.GetServices(nodes, serviceID)[2].(*Service)
	s3 := local.GetServices(nodes, serviceID)[3].(*Service)
	s4 := local.GetServices(nodes, serviceID)[4].(*Service)
	s5 := local.GetServices(nodes, serviceID)[5].(*Service)
	services := []*Service{s0, s1, s2, s3, s4, s5}

	// setup
	setupResponse, err := s0.Setup(&decenarch.SetupRequest{Roster: roster})
	require.Nil(t, err)
	require.NotNil(t, setupResponse.Key)

	for _, s := range services {
		time.Sleep(100 * time.Millisecond)
		require.True(t, setupResponse.Key.Equal(s.key()))
	}

	// save web page
	saveResponse, err := s0.SaveWebpage(&decenarch.SaveRequest{Roster: roster, Url: "http://nibelung.ch/decenarch/100p.html"})
	require.Nil(t, err)
	require.NotNil(t, saveResponse)
}
