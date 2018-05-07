package protocol

import (
	"errors"
	"sync"
	"time"

	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/network"

	"github.com/dedis/onet/log"
	"github.com/dedis/student_18_decenar/lib"
	"gopkg.in/dedis/kyber.v2"
)

// NameReconstruct is the protocol identifier string.
const NameDecrypt = "decrypt"

// Decrypt is the core structure of the protocol.
type Decrypt struct {
	*onet.TreeNodeInstance
	Threshold int32 // How many replies are needed to re-create the secret
	Failures  int   // How many failures occured so far

	Secret          *lib.SharedSecret // Secret is the private key share from the DKG.
	EncryptedCBFSet *lib.CipherVector // Election to be decrypted.

	Partials map[int][]kyber.Point // Parials to return
	Finished chan bool             // Flag to signal protocol termination.
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
		Finished:         make(chan bool, 1),
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
	d.timeout = time.AfterFunc(10*time.Minute, func() {
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

	// partially decrypt
	partials := d.getPartials(prompt.EncryptedCBFSet)

	// send partials to root
	return d.SendTo(d.Root(), &SendPartial{partials})
}

// HandlePartial
func (d *Decrypt) HandlePartial(reply MessageSendPartial) error {
	// handle the case in which a conode refuses to send its partial
	if reply.Partial == nil {
		log.Lvl1("Node", reply.ServerIdentity, "refused to reply")
		d.Failures++
		if d.Failures > len(d.Roster().List)-int(d.Threshold) {
			log.Lvl2(reply.ServerIdentity, "couldn't get enough shares")
			d.finish(false)
		}
		return nil
	}

	log.LLvl3(d.ServerIdentity().Address, "got partials from", reply.Name(), "partials", len(d.Partials), "threshold", int(d.Threshold-1))
	d.mutex.Lock()
	d.Partials[reply.RosterIndex] = reply.Partial
	if len(d.Partials) >= int(d.Threshold-1) {
		d.Partials[d.Index()] = d.getPartials(d.EncryptedCBFSet)
		d.finish(true)
	}
	d.mutex.Unlock()

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
func (d *Decrypt) getPartials(cipher *lib.CipherVector) []kyber.Point {
	partials := make([]kyber.Point, len(*cipher))
	for i, c := range *cipher {
		partials[i] = lib.DecryptPoint(d.Secret.V, lib.CipherText{K: c.K, C: c.C})
	}

	return partials
}
