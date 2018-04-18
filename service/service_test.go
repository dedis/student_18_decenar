package service

import (
	"testing"
	"time"

	"gopkg.in/dedis/cothority.v2"
	"gopkg.in/dedis/onet.v2"

	"github.com/dedis/student_18_decenar"
	"github.com/dedis/student_18_decenar/lib"
	"github.com/stretchr/testify/require"
)

func TestService(t *testing.T) {
	local := onet.NewLocalTest(cothority.Suite)
	defer local.CloseAll()
	nodes, roster, tree := local.GenBigTree(3, 3, 1, true)
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
		time.Sleep(100 * time.Millisecond)
		require.True(t, replySetup.Key.Equal(s.key()))
	}

	// decryption phase
	set0 := []int64{0, 2, 1, 0}
	sets := [][]int64{set0, set0, set0}

	// encrypt sets
	encryptedSets := make([]*lib.CipherVector, 0)
	for i, set := range sets {
		encryptedSets = append(encryptedSets, lib.EncryptIntVector(services[i].key(), set))
	}

	// add sets
	for _, set := range encryptedSets[1:] {
		encryptedSets[0].Add(*encryptedSets[0], *set)
	}

	// get partials
	partials, err := s0.decrypt(tree, encryptedSets[0])
	if err != nil {
		panic(err)
	}

	// reconstruct
	reconstructed := s2.reconstruct(partials)
	require.Equal(t, []int64{0, 6, 3, 0}, reconstructed)

}
