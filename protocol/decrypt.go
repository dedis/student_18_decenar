package protocol

import (
	"errors"
	"sync"
	"time"

	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/network"

	"github.com/dedis/onet/log"
	decenarch "github.com/dedis/student_18_decenar"
	"github.com/dedis/student_18_decenar/lib"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/proof/dleq"
)

// NameReconstruct is the protocol identifier string.
const NameDecrypt = "decrypt"

// Decrypt is the core structure of the protocol.
type Decrypt struct {
	*onet.TreeNodeInstance
	Threshold int32 // how many replies are needed to re-create the secret
	Failures  int   // how many failures occured so far

	Secret          *lib.SharedSecret // secret is the private key share from the DKG.
	EncryptedCBFSet *lib.CipherVector // election to be decrypted.

	Partials map[int][]kyber.Point // parials to return
	Finished chan bool             // flag to signal protocol termination.
	Received chan bool             // flag to signal that the conode received the encrypted filter
	doneOnce sync.Once
	timeout  *time.Timer
	mutex    sync.Mutex
}

func init() {
	network.RegisterMessages(PromptDecrypt{}, SendPartial{})
	onet.GlobalProtocolRegister(NameDecrypt, NewDecrypt)
}

// NewDecrypt initializes the protocol object and registers all the handlers.
func NewDecrypt(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	d := &Decrypt{
		TreeNodeInstance: n,
		Finished:         make(chan bool),
		Received:         make(chan bool),
		Partials:         make(map[int][]kyber.Point),
	}

	err := d.RegisterHandlers(d.HandlePrompt, d.HandlePartial)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// Start is called on the root node prompting it to send itself a Prompt message.
func (d *Decrypt) Start() error {
	log.Lvl3("Starting decrypt protocol")
	// set timeout
	d.timeout = time.AfterFunc(10*time.Hour, func() {
		log.Lvl1("decrypt protocol timeout")
		d.finish(false)
	})

	// broadcast request
	errs := d.Broadcast(&PromptDecrypt{
		EncryptedCBFSet: d.EncryptedCBFSet,
	})
	if len(errs) > int(d.Threshold) {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return errors.New("too many nodes failed in broadcast")
	}

	return nil
}

// HandlePrompt retrieves the mixes, verifies them and performs a partial decryption
// on the last mix before appending it to the election skipchain.
func (d *Decrypt) HandlePrompt(prompt MessagePromptDecrypt) error {
	log.Lvl3(d.Name() + ": sending partials to root")
	defer d.Done()

	// store encrypted CBF set for later verification
	d.EncryptedCBFSet = prompt.EncryptedCBFSet

	// partially decrypt
	partials, proofs := d.getPartials(prompt.EncryptedCBFSet)

	// we can store encrypted filter
	d.Received <- true

	// send partials to root
	msg := &SendPartial{
		Partials:       partials,
		Proofs:         proofs,
		PublicKeyShare: decenarch.Suite.Point().Mul(d.Secret.V, nil),
	}
	return d.SendTo(d.Root(), msg)
}

// HandlePartial
func (d *Decrypt) HandlePartial(reply MessageSendPartial) error {
	log.Lvl3(d.ServerIdentity().Address, "got partials from", reply.Name(), "partials", len(d.Partials))
	// handle the case in which a conode refuses to send its partial
	if reply.Partials == nil {
		log.Lvl1("Node", reply.ServerIdentity, "refused to reply")
		d.Failures++
		if d.Failures > len(d.Roster().List)-int(d.Threshold) {
			log.Lvl2(reply.ServerIdentity, "couldn't get enough shares")
			d.finish(false)
		}
		return nil
	}

	// verify the proofs of the partials
	base := decenarch.Suite.Point().Base()
	for i, p := range reply.Proofs {
		c := &(*d.EncryptedCBFSet)[i]
		ver := p.Verify(decenarch.Suite, base, c.K, reply.PublicKeyShare, decenarch.Suite.Point().Sub(c.C, reply.Partials[i]))
		if ver != nil {
			log.Print("Failed")
			log.Lvl1("Node", reply.ServerIdentity, "sended invalid partials")
			d.Failures++
			if d.Failures > len(d.Roster().List)-int(d.Threshold) {
				log.Lvl2(reply.ServerIdentity, "couldn't get enough shares")
				d.finish(false)
			}
			return nil
		}
	}

	// finally add the partials of the user
	d.mutex.Lock()
	d.Partials[reply.RosterIndex] = reply.Partials
	d.mutex.Unlock()

	// if enough shares from children, add partials of root
	if len(d.Partials) >= int(d.Threshold-1) {
		// we don't need the proofs of the leader
		d.mutex.Lock()
		d.Partials[d.Index()], _ = d.getPartials(d.EncryptedCBFSet)
		d.mutex.Unlock()
		d.finish(true)
	}

	return nil
}

// finish terminates the protocol within onet.
func (d *Decrypt) finish(result bool) {
	d.timeout.Stop()
	select {
	case d.Finished <- result:
		// decrypt protocol suceeded
	default:
		// source https://github.com/dedis/cothority/blob/master/ocs/protocol/ocs.go
		// would have blocked because some other call to finish()
		// beat us.
	}
	d.doneOnce.Do(func() { d.Done() })
}

// getPartials
func (d *Decrypt) getPartials(cipher *lib.CipherVector) ([]kyber.Point, []*dleq.Proof) {
	partials := make([]kyber.Point, len(*cipher))
	proofs := make([]*dleq.Proof, len(*cipher))
	base := decenarch.Suite.Point().Base()
	var wg sync.WaitGroup
	if lib.PARALLELIZE {
		for i := 0; i < len(*cipher); i = i + lib.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < lib.VPARALLELIZE && (j+i < len(*cipher)); j++ {
					c := &(*cipher)[i+j]
					partials[i+j] = lib.DecryptPoint(d.Secret.V, lib.CipherText{K: c.K, C: c.C})
					p, _, _, _ := dleq.NewDLEQProof(decenarch.Suite, base, c.K, d.Secret.V)
					proofs[i+j] = p
				}
				defer wg.Done()
			}(i)

		}
		wg.Wait()
	} else {
		for i, c := range *cipher {
			partials[i] = lib.DecryptPoint(d.Secret.V, lib.CipherText{K: c.K, C: c.C})
			p, _, _, _ := dleq.NewDLEQProof(decenarch.Suite, base, c.K, d.Secret.V)
			proofs[i] = p
		}
	}

	return partials, proofs
}
