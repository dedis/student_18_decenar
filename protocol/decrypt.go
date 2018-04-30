package protocol

import (
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
	Threshold uint32 // How many replies are needed to re-create the secret
	Failures  int    // How many failures occured so far

	Secret          *lib.SharedSecret // Secret is the private key share from the DKG.
	EncryptedCBFSet *lib.CipherVector // Election to be decrypted.

	Partials map[int][]kyber.Point // Parials to return
	Finished chan bool             // Flag to signal protocol termination.

	nextNodeInCircuit *onet.TreeNode // Next node in the circuit
}

func init() {
	network.RegisterMessages(PromptDecrypt{}, SendPartial{})
	onet.GlobalProtocolRegister(NameDecrypt, NewDecrypt)
}

// NewDecrypt initializes the protocol object and registers all the handlers.
func NewDecrypt(node *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	decrypt := &Decrypt{TreeNodeInstance: node, Finished: make(chan bool, 1), Partials: make(map[int][]kyber.Point)}

	// determine next node
	var nodeList = node.Tree().List()
	for i, n := range nodeList {
		if node.TreeNode().Equal(n) {
			// last node will be root
			decrypt.nextNodeInCircuit = nodeList[(i+1)%len(nodeList)]
			break
		}
	}

	decrypt.RegisterHandlers(decrypt.HandlePrompt, decrypt.HandlePartial)
	return decrypt, nil
}

// Start is called on the root node prompting it to send itself a Prompt message.
func (d *Decrypt) Start() error {
	errors := d.Broadcast(&PromptDecrypt{d.EncryptedCBFSet})
	if errors != nil {
		return errors[0]
	}

	return nil
}

// HandlePrompt retrieves the mixes, verifies them and performs a partial decryption
// on the last mix before appending it to the election skipchain.
func (d *Decrypt) HandlePrompt(prompt MessagePromptDecrypt) error {
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
		log.Lvl2("Node", reply.ServerIdentity, "refused to reply")
		d.Failures++
		if d.Failures > len(d.Roster().List)-int(d.Threshold) {
			log.Lvl2(reply.ServerIdentity, "couldn't get enough shares")
			d.finish(false)
		}
		return nil
	}

	d.Partials[reply.RosterIndex] = reply.Partial
	if len(d.Partials) >= int(d.Threshold-1) {
		d.Partials[d.Index()] = d.getPartials(d.EncryptedCBFSet)
		d.finish(true)
	}

	return nil
}

// finish terminates the protocol within onet.
func (d *Decrypt) finish(result bool) {
	d.Done()
	d.Finished <- result
}

// getPartials
func (d *Decrypt) getPartials(cipher *lib.CipherVector) []kyber.Point {
	partials := make([]kyber.Point, len(*cipher))
	for i, c := range *cipher {
		partials[i] = lib.DecryptPoint(d.Secret.V, lib.CipherText{K: c.K, C: c.C})
	}

	return partials
}
