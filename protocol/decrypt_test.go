package protocol

import (
	"errors"
	"testing"
	"time"

	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"

	"github.com/dedis/student_18_decenar/lib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gopkg.in/dedis/cothority.v2"
)

var decryptServiceID onet.ServiceID

type decryptService struct {
	*onet.ServiceProcessor

	secret *lib.SharedSecret
}

func init() {
	new := func(ctx *onet.Context) (onet.Service, error) {
		return &decryptService{
			ServiceProcessor: onet.NewServiceProcessor(ctx),
		}, nil
	}
	decryptServiceID, _ = onet.RegisterNewService(NameDecrypt, new)
}

func (s *decryptService) NewProtocol(node *onet.TreeNodeInstance, conf *onet.GenericConfig) (
	onet.ProtocolInstance, error) {

	switch node.ProtocolName() {
	case NameDecrypt:
		instance, _ := NewDecrypt(node)
		decrypt := instance.(*Decrypt)
		decrypt.Secret = s.secret
		return decrypt, nil
	default:
		return nil, errors.New("Unknown protocol")
	}
}

func TestDecryptProtocol(t *testing.T) {
	for _, nodes := range []int{3, 5, 7, 11} {
		log.Lvl1("Starting protocol Decrypt protocol with", nodes, "nodes")
		runDecrypt(t, nodes)
	}
}

func runDecrypt(t *testing.T, n int) {
	local := onet.NewLocalTest(cothority.Suite)
	defer local.CloseAll()

	nodes, _, tree := local.GenBigTree(n, n, n, true)
	services := local.GetServices(nodes, decryptServiceID)

	dkgs, _ := lib.DKGSimulate(n, n-1)
	shared, _ := lib.NewSharedSecret(dkgs[0])
	key := shared.X

	// compute threshold
	threshold := int32(n - (n-1)/3)

	// encrypt random vector. Note that proof is tested somewhere else
	cipher, _ := lib.EncryptIntVector(key, []int64{0, 1, 0})

	for i := range services {
		services[i].(*decryptService).secret, _ = lib.NewSharedSecret(dkgs[i])
	}

	instance, _ := services[0].(*decryptService).CreateProtocol(NameDecrypt, tree)
	decrypt := instance.(*Decrypt)
	decrypt.Secret, _ = lib.NewSharedSecret(dkgs[0])
	decrypt.EncryptedCBFSet = cipher
	decrypt.Threshold = threshold
	decrypt.Start()

	select {
	case <-decrypt.Finished:
		partials := decrypt.Partials
		require.Equal(t, int(threshold), len(partials))
	case <-time.After(60 * time.Second):
		assert.True(t, false)
	}
}
