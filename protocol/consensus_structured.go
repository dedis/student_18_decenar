package protocol

/*
The `NewProtocol` method is used to define the protocol and to register
the handlers that will be called if a certain type of message is received.
The handlers will be treated according to their signature.

The protocol-file defines the actions that the protocol needs to do in each
step. The root-node will call the `Start`-method of the protocol. Each
node will only use the `Handle`-methods, and not call `Start` again.
*/

import (
	"errors"
	"net/http"
	urlpkg "net/url"
	"regexp"

	"golang.org/x/net/html"

	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/sign/schnorr"

	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"

	"github.com/dedis/student_18_decenar/lib"
)

func init() {
	network.RegisterMessage(SaveAnnounceStructured{})
	network.RegisterMessage(SaveReplyStructured{})
	network.RegisterMessage(CompleteProofsAnnounce{})
	onet.GlobalProtocolRegister(NameConsensusStructured, NewConsensusStructuredProtocol)
}

// SaveLocalState holds the local state of a node when it runs the SaveProtocol
type ConsensusStructuredState struct {
	*onet.TreeNodeInstance
	Phase       SavePhase
	Errs        []error
	Url         string
	ContentType string
	SharedKey   kyber.Point

	LocalTree *html.Node

	ParametersCBF            []uint
	CountingBloomFilter      *lib.CBF
	EncryptedCBFSet          *lib.CipherVector
	EncryptedCBFSetSignature []byte

	CompleteProofs       lib.CompleteProofs
	CompleteProofsToSend lib.CompleteProofs

	Finished chan bool
}

// NewSaveProtocol initialises the structure for use in one round
func NewConsensusStructuredProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("Creating NewConsensusStructuredProtocolProtocol")
	t := &ConsensusStructuredState{
		TreeNodeInstance: n,
		Url:              "",
		Finished:         make(chan bool),
	}
	for _, handler := range []interface{}{t.HandleAnnounce, t.HandleReply, t.HandleCompleteProofs} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}

	// we need big messages
	network.MaxPacketSize = network.Size(1000 * 1024 * 1024)
	return t, nil
}

// Start sends the Announce-message to all children. This function is executed
// only by the leader, i.e. root of the tree
func (p *ConsensusStructuredState) Start() error {
	log.Lvl3("Starting SaveLocalState")

	// get tree for the root
	tree, err := p.GetLocalHTMLData()
	if err != nil {
		log.Error("Error in save protocol Start():", err)
		return err
	}
	p.LocalTree = tree

	// compute and store CBF parameters
	paramCBF := lib.GetOptimalCBFParametersToSend(tree)
	p.ParametersCBF = castParametersCBF(paramCBF)

	// send announcement to all conodes
	errs := p.Broadcast(&SaveAnnounceStructured{
		Url:           p.Url,
		ParametersCBF: paramCBF,
	})
	if len(errs) > 0 {
		return lib.ConcatenateErrors(errs)
	}

	return nil
}

// HandleAnnounce is the message going down the tree
//
// Note: this function must be read as multiple functions with a common
// begining and end but each time a different 'case'. Each one can be
// considered as an independant function.
func (p *ConsensusStructuredState) HandleAnnounce(msg StructSaveAnnounceStructured) error {
	log.Lvl4("Handling", p)
	log.Lvl4("And the message", msg)
	p.Url = msg.SaveAnnounceStructured.Url

	// get local version of the webpage
	tree, err := p.GetLocalHTMLData()
	if err != nil {
		log.Error("Error in save protocol HandleAnnounce():", err)
		return err
	}
	p.LocalTree = tree

	// get CBF parameters
	p.ParametersCBF = castParametersCBF(msg.SaveAnnounceStructured.ParametersCBF)

	// if we are in a leaf, we start the bottom-up part of the protocol
	if p.IsLeaf() {
		resp := StructSaveReplyStructured{
			p.TreeNode(),
			SaveReplyStructured{
				Url:  msg.SaveAnnounceStructured.Url,
				Errs: p.Errs},
		}
		return p.HandleReply([]StructSaveReplyStructured{resp})
	}

	return nil
}

// HandleReply is the message going up the tree
//
// Note: this function must be read as multiple functions with a common
// begining and end but each time a different 'case'. Each one can be
// considered as an independant function.
func (p *ConsensusStructuredState) HandleReply(reply []StructSaveReplyStructured) error {
	log.Lvl4("Handling Save Reply", p)
	log.Lvl4("And the replies", reply)
	// compute and aggregate CBF
	err := p.AggregateCBF(p.LocalTree, reply)
	if err != nil {
		return err
	}

	// aggregate errors
	p.AggregateErrors(reply)

	if !p.IsRoot() {
		log.Lvl4("Sending Consensus to Parent")
		resp := SaveReplyStructured{
			Url: p.Url,

			Errs: p.Errs,

			EncryptedCBFSet: p.EncryptedCBFSet,

			CompleteProofs: p.CompleteProofs,
		}
		return p.SendToParent(&resp)
	}

	log.Lvl4("Consensus reach root, now send complete proofs to all conodes")
	errs := p.Broadcast(&CompleteProofsAnnounce{p.CompleteProofs})
	if len(errs) > 0 {
		return lib.ConcatenateErrors(errs)
	}

	// root is done
	p.Finished <- true

	return nil
}

// HandleCompleteProofs is responsible for storing the complete proofs received
// from root, which is responsible for aggregating and sending them
func (p *ConsensusStructuredState) HandleCompleteProofs(cp StructCompleteProofsAnnounce) error {
	defer p.Done()

	// get complete proofs from root
	p.CompleteProofsToSend = cp.CompleteProofs

	// communicate termination of the protocol
	p.Finished <- true
	return nil
}

// GetLocalHTMLData retrieve the data from the p.Url and handle it to make it
// either a *html.Node tree or a signed hash.  If the returned *html.Node tree is
// not nil, then the map is. Else, it is the other way around.  If both
// returned value are nil, then an error occured.
func (p *ConsensusStructuredState) GetLocalHTMLData() (*html.Node, error) {
	// get data
	resp, realUrl, err := getRemoteData(p.Url)
	if err != nil {
		log.Lvl1("Error! Impossible to retrieve remote data.")
		return nil, err
	}
	p.Url = realUrl
	defer resp.Body.Close()
	// apply procedure according to data type
	contentTypes := resp.Header.Get(http.CanonicalHeaderKey("Content-Type"))
	p.ContentType = contentTypes
	if b, e := regexp.MatchString("text/html", contentTypes); b && e == nil && resp.StatusCode == 200 {
		// procedure for html files (tree-consensus)
		htmlTree, htmlErr := html.Parse(resp.Body)
		if htmlErr != nil {
			log.Lvl1("Error: Impossible to parse html code!")
			return nil, htmlErr
		}
		return htmlTree, nil
	}

	return nil, errors.New("No HTML data")
}

// getRemoteData take a url and return: - the http response corresponding to
// the url - the un-alias url corresponding to the response (id est the path to
// the file on the remote server) - the url structure associated (see net/url
// Url struct) - an error status
func getRemoteData(url string) (*http.Response, string, error) {
	getResp, getErr := http.Get(url)
	if getErr != nil {
		return nil, "", getErr
	}

	realUrl := getResp.Request.URL.String()

	_, urlErr := urlpkg.Parse(realUrl)
	if urlErr != nil {
		getResp.Body.Close()
		return nil, "", urlErr
	}

	return getResp, realUrl, getErr
}

// AggregateErrors put all the errors contained in the children reply inside
// the SaveLocalState p field p.Errs. It allows the current protocol to
// transmit the errors from its children to its parent.
func (p *ConsensusStructuredState) AggregateErrors(reply []StructSaveReplyStructured) {
	for _, r := range reply {
		p.Errs = append(p.Errs, r.Errs...)
	}
}

// AggregateCBF compute the local CBF of the node, add the random CBF if the
// node is not root and remove the newZero CBF is the node is root. Moreover,
// the parant nodes aggregate the results of the children if the signature for
// the CBF set is valid. If the signature is not valid, the child's
// contribution is not taken into account and the verification error is added
// to p.Errs, but the function does not return error in this case.
func (p *ConsensusStructuredState) AggregateCBF(locTree *html.Node, reply []StructSaveReplyStructured) error {
	// get public key of this node as string
	pubKeyString := p.Public().String()

	// get parameters CBF
	param := p.ParametersCBF

	// fill filter with local data
	p.CountingBloomFilter = lib.NewFilledBloomFilter(param, locTree)
	log.Lvl4("Filled CBF for node", p.ServerIdentity().Address, "is", p.CountingBloomFilter)

	// initialize local proof with useful fields
	p.CompleteProofs = make(lib.CompleteProofs)
	p.CompleteProofs[pubKeyString] = &lib.CompleteProof{
		Roster:      p.Roster(),
		TreeMarshal: p.Tree().MakeTreeMarshal(),
		PublicKey:   p.Public(),
		TreeNodeID:  p.TreeNode().ID,
	}

	// encrypt set of the filter using the collective DKG key and prove
	// that the set contains only zeros and ones
	localBloomEncrypted, proof := lib.EncryptIntVector(p.SharedKey, p.CountingBloomFilter.Set)
	localBloomEncryptedToBytes, _ := localBloomEncrypted.ToBytes()
	p.CompleteProofs[pubKeyString].CipherVectorProof = proof
	p.CompleteProofs[pubKeyString].EncryptedBloomFilter = localBloomEncryptedToBytes

	// aggregate children contributions after checking the signature
	childrenContributions := make(map[string][]byte)
	childrenContributions[pubKeyString] = localBloomEncryptedToBytes
	p.EncryptedCBFSet = localBloomEncrypted
	if !p.IsLeaf() {
		for _, r := range reply {
			// convert child contribution to bytes
			bytesEncryptedBloomFilter, _ := r.EncryptedCBFSet.ToBytes()
			// aggregate children proofs with local proof
			for conode, proof := range r.CompleteProofs {
				// set the child encrypted CBF for the
				// ciphervector proof as the received encrypted
				// bloom filter, since we use a tree of height
				// one. Note that this should be modified if we want to use a tree of height > 1
				proof.EncryptedBloomFilter = bytesEncryptedBloomFilter

				// store the child proof
				p.CompleteProofs[conode] = proof
			}

			// aggregate encrypted CBF set after content proof and
			// signature verification
			bytesEncryptedSet, _ := r.EncryptedCBFSet.ToBytes()
			hashed := p.Suite().(kyber.HashFactory).Hash().Sum(bytesEncryptedSet)
			conodeKey := r.TreeNode.ServerIdentity.Public.String()
			vErr := schnorr.Verify(p.Suite(), r.TreeNode.ServerIdentity.Public, hashed, r.CompleteProofs[conodeKey].EncryptedCBFSetSignature)
			if vErr == nil && p.CompleteProofs[conodeKey].CipherVectorProof.VerifyCipherVectorProof(r.EncryptedCBFSet) {
				log.Lvl4("Valid encrypted CBF set signature for node", r.ServerIdentity.Address)
				childrenContributions[r.TreeNode.ServerIdentity.Public.String()], _ = r.EncryptedCBFSet.ToBytes()
				p.EncryptedCBFSet.Add(*p.EncryptedCBFSet, *r.EncryptedCBFSet)
			} else {
				log.Lvl1("Invalid signature or content proof for node", r.ServerIdentity.Address)
				p.Errs = append(p.Errs, vErr)
			}
		}
	}

	// store sum of all contributions plus the local contribution of the conode
	bytesEncrypted, length := p.EncryptedCBFSet.ToBytes()

	// add local aggregation proof
	// we add this proof also for the leaves because we use it to
	// communicate to the signing protocol the encrypted CBF set
	p.CompleteProofs[pubKeyString].AggregationProof = lib.CreateAggregationiProof(childrenContributions, bytesEncrypted, length)

	// add signature of encrypted CBF set the proof material of this
	// conode. The signature should be added here because we have to take
	// into account the addition for the non leaf nodes. If the node isn't
	// a leaf, we skip the addition part, so no problem in signing the
	// encrypted Bloom filter here
	sig, err := p.signEncryptedCBFSet()
	if err != nil {
		return err
	}
	p.CompleteProofs[pubKeyString].EncryptedCBFSetSignature = sig

	return nil
}

// signEncryptedCBFSet sign the ciphertext of a CBF set with the private key of
// the node represented by p. An error is returned if something go wrong while
// signing. Here we have to use the encrypt-then-sign paradigm, because the
// single encrypted CBF set are never decrypted and since we use an additive
// homomorphic scheme, we have to be sure that the ciphertext is not modifies
// by an attacker, e.g. by multiplying it by a scalar
func (p *ConsensusStructuredState) signEncryptedCBFSet() ([]byte, error) {
	if p.EncryptedCBFSet == nil {
		return nil, errors.New("Trying to sign a nil encrypted CBF set")
	}

	bytesEncryptedSet, _ := p.EncryptedCBFSet.ToBytes()
	hashed := p.Suite().(kyber.HashFactory).Hash().Sum(bytesEncryptedSet)
	sig, err := schnorr.Sign(p.Suite(), p.Private(), hashed)
	if err != nil {
		log.Lvl1("Error! Impossible to sign encrypted CBF set", err)
		p.Errs = append(p.Errs, err)
		return nil, err
	}
	log.Lvl4("Encryted CBF set", p.EncryptedCBFSet, "for node", p.ServerIdentity().Address, "signed with signature", sig)
	return sig, nil
}

// castParametersCBF from uint64 to uint, since uint64 is needed to send the
// paramters across the conodes
func castParametersCBF(param []uint64) []uint {
	return []uint{uint(param[0]), uint(param[1])}
}
