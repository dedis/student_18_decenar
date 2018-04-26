package service

import (
	"testing"
	"time"

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

	//	// decryption phase
	//	set0 := []int64{0, 2, 1, 0}
	//	sets := [][]int64{set0, set0, set0}
	//
	//	// encrypt sets
	//	encryptedSets := make([]*lib.CipherVector, 0)
	//	for i, set := range sets {
	//		// proof is tested somewhere else
	//		es, _ := lib.EncryptIntVector(services[i].key(), set)
	//		encryptedSets = append(encryptedSets, es)
	//	}
	//
	//	// add sets
	//	for _, set := range encryptedSets[1:] {
	//		encryptedSets[0].Add(*encryptedSets[0], *set)
	//	}
	//
	//	// get partials
	//	partials, err := s0.decrypt(tree, encryptedSets[0])
	//	if err != nil {
	//		panic(err)
	//	}
	//	_ = partials

}
