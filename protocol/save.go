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
	"bytes"
	"encoding/base64"
	"errors"
	"io/ioutil"
	"math"
	"net/http"
	urlpkg "net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"

	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/sign/schnorr"
	"gopkg.in/dedis/kyber.v2/util/random"

	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

func init() {
	network.RegisterMessage(SaveAnnounce{})
	network.RegisterMessage(SaveReply{})
	onet.GlobalProtocolRegister(SaveName, NewSaveProtocol)
}

// SaveLocalState holds the local state of a node when it runs the SaveProtocol
type SaveLocalState struct {
	*onet.TreeNodeInstance
	Phase       SavePhase
	Errs        []error
	Url         string
	ContentType string
	Threshold   int32

	LocalTree    *AnonNode
	LocalTreeSig []byte
	LocSeen      []bool
	LocSig       []byte
	SeenMap      map[string][]bool
	SeenSig      map[string][]byte

	MasterHash map[string]map[kyber.Point][]byte

	PlainNodes map[string]html.Node
	PlainData  map[string][]byte

	ParametersCBF       []uint
	RandomEncryptedCBF  []byte
	CountingBloomFilter *CBF

	MsgToSign  chan []byte
	StringChan chan string

	RefTreeChan chan []ExplicitNode
	SeenMapChan chan map[string][]byte
	SeenSigChan chan map[string][]byte
}

// NewSaveProtocol initialises the structure for use in one round
func NewSaveProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("Creating NewSaveProtocol")
	t := &SaveLocalState{
		TreeNodeInstance: n,
		Url:              "",
		Phase:            NilPhase,
		PlainNodes:       make(map[string]html.Node),
		PlainData:        make(map[string][]byte),
		SeenMap:          make(map[string][]bool),
		SeenSig:          make(map[string][]byte),
		MsgToSign:        make(chan []byte),
		StringChan:       make(chan string),
		RefTreeChan:      make(chan []ExplicitNode),
		SeenMapChan:      make(chan map[string][]byte),
		SeenSigChan:      make(chan map[string][]byte),
	}
	for _, handler := range []interface{}{t.HandleAnnounce, t.HandleReply} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}
	return t, nil
}

// Start sends the Announce-message to all children. This function is executed only
// by the leader, i.e. root, of the tree
func (p *SaveLocalState) Start() error {
	log.Lvl3("Starting SaveLocalState")
	p.Phase = Consensus
	tree, hash, err := p.GetLocalData()
	if err != nil {
		log.Error("Error in save protocol Start():", err)
		return err
	}
	p.MasterHash = hash
	paramCBF := GetOptimalCBFParametersToSend(tree)
	randomCBFs, err := p.generateRandomCBF(paramCBF)
	if err != nil {
		log.Error("Error in save protocol Start():", err)
		return err
	}
	return p.HandleAnnounce(StructSaveAnnounce{
		p.TreeNode(),
		SaveAnnounce{
			Url:                 p.Url,
			Phase:               Consensus,
			MasterHash:          p.MasterHash,
			ParametersCBF:       paramCBF,
			RandomEncryptedCBFs: randomCBFs,
		},
	})
}

// HandleAnnounce is the message going down the tree
//
// Note: this function must be read as multiple functions with a common begining
// and end but each time a different 'case'. Each one can be considered as an
// independant function.
func (p *SaveLocalState) HandleAnnounce(msg StructSaveAnnounce) error {
	log.Lvl4("Handling", p)
	log.Lvl4("And the message", msg)
	p.Phase = msg.SaveAnnounce.Phase
	p.Url = msg.SaveAnnounce.Url
	switch msg.SaveAnnounce.Phase {
	case NilPhase:
		log.Lvl1("NilPhase passed by", p, "msg:", msg)
		err := errors.New("NilPhase should not be announceable")
		resp := StructSaveReply{
			p.TreeNode(),
			SaveReply{
				Phase: msg.SaveAnnounce.Phase,
				Url:   msg.SaveAnnounce.Url,
				Errs:  []error{err},
			},
		}
		defer p.HandleReply([]StructSaveReply{resp})
		return err
	case Consensus:
		log.Lvl4("Consensus Phase")
		// retrieve data again because the Start() function is run only by root
		// and all the nodes need the three and the hash
		tree, _, err := p.GetLocalData()
		if err != nil {
			log.Error("Error in save protocol HandleAnnounce(msg Struct save Announce:)", err)
		}
		p.LocalTree = tree
		p.MasterHash = msg.SaveAnnounce.MasterHash
		// get the CBF's parameters computed by the root
		// TODO maybe to a function here
		p.ParametersCBF = []uint{uint(msg.SaveAnnounce.ParametersCBF[0]), uint(msg.SaveAnnounce.ParametersCBF[1])}
		// take the random and encrypted CBF of this node
		p.RandomEncryptedCBF = msg.SaveAnnounce.RandomEncryptedCBFs[p.Public().String()]
		if !p.IsLeaf() {
			return p.SendToChildren(&msg.SaveAnnounce)
		} else {
			resp := StructSaveReply{
				p.TreeNode(),
				SaveReply{
					Phase:      msg.SaveAnnounce.Phase,
					Url:        msg.SaveAnnounce.Url,
					MasterHash: msg.SaveAnnounce.MasterHash,
					Errs:       p.Errs},
			}
			return p.HandleReply([]StructSaveReply{resp})
		}
	case RequestMissingData:
		log.Lvl4("RequestMissingData Phase with", p)
		p.MasterHash = msg.SaveAnnounce.MasterHash
		if p.MasterHash != nil && len(p.MasterHash) > 0 {
			requestedHash := getRequestedMissingHash(p)
			if _, ok := p.PlainData[requestedHash]; !ok {
				if !p.IsLeaf() {
					return p.SendToChildren(msg)
				}
			}
		}
		// arriving here means either that:
		// * node has requested plaintext data
		// * node is a leaf so it has no more children to ask for data
		// * node refused to reveal plaintext data because of invalid signatures
		resp := StructSaveReply{
			p.TreeNode(),
			SaveReply{
				Phase:      p.Phase,
				Url:        p.Url,
				MasterHash: p.MasterHash,
				Errs:       p.Errs},
		}
		return p.HandleReply([]StructSaveReply{resp})
	case CoSigning:
		// PHASE COSIGNING
		// For the moment, we use the Cosi API at service level
	case SkipchainSaving:
		// PHASE SKIPCHAIN SAVING
		// For the moment, we use the Cosi API at service level
	case End:
		log.Lvl4("End Phase")
		p.SendToChildren(&msg.SaveAnnounce)
	default:
		log.Lvl1("Unknown phase passed by", p, "msg:", msg)
		err := errors.New("Unknown Phase")
		resp := StructSaveReply{
			p.TreeNode(),
			SaveReply{
				Phase: msg.SaveAnnounce.Phase,
				Url:   msg.SaveAnnounce.Url,
				Errs:  []error{err}},
		}
		defer p.HandleReply([]StructSaveReply{resp})
		return err
	}
	return nil
}

// HandleReply is the message going up the tree
//
// Note: this function must be read as multiple functions with a common begining
// and end but each time a different 'case'. Each one can be considered as an
// independant function.
func (p *SaveLocalState) HandleReply(reply []StructSaveReply) error {
	log.Lvl4("Handling Save Reply", p)
	log.Lvl4("And the replies", reply)
	switch p.Phase {
	case NilPhase:
		log.Lvl1("NilPhase passed by", p)
		defer p.Done()
		return errors.New("NilPhase should not be replyable")
	case Consensus:
		log.Lvl4("Consensus Reply Phase")
		locTree, locHash, locErr := p.GetLocalData()
		if locErr != nil {
			log.Lvl1("Error! Impossible to get local data", locErr)
			p.Errs = append(p.Errs, locErr)
		}
		p.AggregateUnstructData(locHash, reply)
		p.AggregateCBF(locTree, reply)
		CBFSetSig, err := p.signCBFSet()
		if err != nil {
			return err
		}
		if p.IsRoot() {
			log.Lvl4("Consensus reach root. Passing to next phase")
			// consensus on unstructured data
			if p.MasterHash != nil && len(p.MasterHash) > 0 {
				msMap, msErr := getMostSignedHash(p, p.MasterHash)
				if msErr != nil {
					p.Errs = append(p.Errs, msErr)
				}
				p.MasterHash = msMap
			}
			// pass to next phase, RequestMissingData
			p.Phase = RequestMissingData
			msg := SaveAnnounce{
				Phase:      p.Phase,
				Url:        p.Url,
				MasterHash: p.MasterHash,
			}
			p.HandleAnnounce(StructSaveAnnounce{p.TreeNode(), msg})
		} else {
			log.Lvl4("Sending Consensus to Parent")
			resp := SaveReply{
				Phase: p.Phase,
				Url:   p.Url,

				MasterHash: p.MasterHash,

				Errs: p.Errs,

				CBFSet:    p.CountingBloomFilter.GetSet(),
				CBFSetSig: CBFSetSig,
			}
			if resp.CBFSet == nil {
				resp.CBFSet = []byte("")
			}
			return p.SendTo(p.Parent(), &resp)
		}
	case RequestMissingData:
		log.Lvl4("RequestMissingData Reply Phase")
		p.AggregateErrors(reply)
		var requestedHash string
		if p.MasterHash != nil && len(p.MasterHash) > 0 {
			requestedHash = getRequestedMissingHash(p)
			for _, r := range reply {
				if plain, ok := r.RequestedData[requestedHash]; ok {
					hashedData := p.Suite().(kyber.HashFactory).Hash().Sum(plain)
					if base64.StdEncoding.EncodeToString(hashedData) == requestedHash {
						p.PlainData[requestedHash] = plain
					}
				}
			}
		}

		if p.IsRoot() {
			p.StringChan <- p.Url
			p.StringChan <- p.ContentType
			if p.LocalTree != nil {
				p.MsgToSign <- p.BuildCBFConsensusHtmlPage()
			} else if p.MasterHash != nil && len(p.MasterHash) > 0 {
				p.MsgToSign <- p.PlainData[requestedHash]
			}
			// announce the end of the process
			msg := SaveAnnounce{
				Phase: End,
				Url:   p.Url}
			return p.HandleAnnounce(StructSaveAnnounce{p.TreeNode(), msg})
		} else {
			requestedDataMap := make(map[string][]byte)
			requestedDataMap[requestedHash] = p.PlainData[requestedHash]
			resp := SaveReply{
				Phase:         p.Phase,
				Url:           p.Url,
				Errs:          p.Errs,
				MasterHash:    p.MasterHash,
				RequestedData: requestedDataMap}
			return p.SendTo(p.Parent(), &resp)
		}
	case CoSigning:
		// PHASE COSIGNING
		// For the moment, we use the Cosi API at service level
	case SkipchainSaving:
		// PHASE SKIPCHAIN SAVING
		// For the moment, we use the Skipchain API at service level
	case End:
		// PHASE END
		log.Lvl4("End Reply Phase")
		log.Lvl1("Node is done")
		defer p.Done()
		if !p.IsRoot() {
			resp := SaveReply{
				Phase: End,
				Url:   p.Url,
			}
			return p.SendTo(p.Parent(), &resp)
		}
		return nil
	default:
		log.Lvl1("Unknown phase passed by", p)
		defer p.Done()
		return errors.New("Unknown Phase")

	}
	defer p.Done()
	return nil
}

// GetLocalData retrieve the data from the p.Url and handle it to make it either a AnonNodes tree
// or a signed hash.
// If the returned *AnonNode tree is not nil, then the map is. Else, it is the other way around.
// If both returned value are nil, then an error occured.
func (p *SaveLocalState) GetLocalData() (*AnonNode, map[string]map[kyber.Point][]byte, error) {
	// get data
	resp, realUrl, _, err := getRemoteData(p.Url)
	if err != nil {
		log.Lvl1("Error! Impossible to retrieve remote data.")
		return nil, nil, err
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
			return nil, nil, htmlErr
		}
		anonRoot := htmlToAnonTree(p, htmlTree)
		return anonRoot, nil, nil
	}

	// procedure for all other files (consensus on whole hash)
	rawData, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		log.Lvl1("Error: Impossible to read http request body!")
		return nil, nil, readErr
	}
	hashedData := p.Suite().(kyber.HashFactory).Hash().Sum(rawData)
	locHashKey := base64.StdEncoding.EncodeToString(hashedData)
	sig, sigErr := schnorr.Sign(p.Suite(), p.Private(), []byte(locHashKey))
	if sigErr != nil {
		log.Lvl1("Error: Impossible to sign data!")
		return nil, nil, sigErr
	}
	localHash := make(map[string]map[kyber.Point][]byte)
	localHash[locHashKey] = make(map[kyber.Point][]byte)
	localHash[locHashKey][p.Public()] = sig
	// save plaintext data locally
	p.PlainData[locHashKey] = rawData

	return nil, localHash, nil
}

// getRemoteData take a url and return:
// - the http response corresponding to the url
// - the un-alias url corresponding to the response (id est the path to the file on
// the remote server)
// - the url structure associated (see net/url Url struct)
// - an error status
func getRemoteData(url string) (*http.Response, string, *urlpkg.URL, error) {
	getResp, getErr := http.Get(url)
	if getErr != nil {
		return nil, "", nil, getErr
	}

	realUrl := getResp.Request.URL.String()

	urlStruct, urlErr := urlpkg.Parse(realUrl)
	if urlErr != nil {
		getResp.Body.Close()
		return nil, "", nil, urlErr
	}

	return getResp, realUrl, urlStruct, getErr
}

// htmlToAnonTree turn an tree composed of *html.Node to the corresponding tree
// composed of *AnonNode
func htmlToAnonTree(p *SaveLocalState, root *html.Node) *AnonNode {
	var queue []*html.Node
	var curr *html.Node
	discovered := make(map[*html.Node]*AnonNode)
	queue = append(queue, root)
	for len(queue) != 0 {
		curr = queue[0]
		queue = queue[1:]
		if _, ok := discovered[curr]; !ok {
			an := htmlToAnonNode(p, curr)
			discovered[curr] = an
			if curr.Parent != nil {
				discovered[curr.Parent].AppendChild(an)
			}
			for n := curr.FirstChild; n != nil; n = n.NextSibling {
				queue = append(queue, n)
			}
		}
	}
	return discovered[root]
}

// htmlToAnonNode take a SaveLocalState p and a pointer to html node hn as input
// and output the *AnonNode corresponding to hn.
// The SaveLocalState is used in the signing process of the *AnonNode and to store
// the node locally as plaintext.
func htmlToAnonNode(p *SaveLocalState, hn *html.Node) *AnonNode {
	var anonNode *AnonNode = &AnonNode{}
	hashedData := hashHtmlData(p, hn)
	anonNode.HashedData = hashedData
	anonNode.Seen = true

	// save node locally (only its data are relevant, not its position)
	p.PlainNodes[hashedData] = *hn

	return anonNode
}

// hashHtmlData turn the data fields of the html node hn into a hash.
// The "data fields" are all the attributes of an html Nodes except the ones
// related to its position in the html tree. Furthermore, the list hn.Attr is
// sorted before the hashing process.
func hashHtmlData(p *SaveLocalState, hn *html.Node) string {
	if hn == nil {
		return ""
	}

	// we sort attribute in order to have deterministic hash
	var attrList []string = make([]string, 0)
	for _, a := range hn.Attr {
		attrList = append(attrList, a.Namespace+a.Key+a.Val)
	}
	sort.Sort(sort.StringSlice(attrList))

	data := []byte(hn.Namespace + hn.Data + strings.Join(attrList, ""))
	hashedData := p.Suite().(kyber.HashFactory).Hash().Sum(data)

	return base64.StdEncoding.EncodeToString(hashedData)
}

// AggregateErrors put all the errors contained in the children reply inside
// the SaveLocalState p field p.Errs. It allows the current protocol to transmit
// the errors from its children to its parent.
func (p *SaveLocalState) AggregateErrors(reply []StructSaveReply) {
	for _, r := range reply {
		p.Errs = append(p.Errs, r.Errs...)
	}
}

func (p *SaveLocalState) AggregateCBF(locTree *AnonNode, reply []StructSaveReply) error {
	// This method is only for structured data
	if p.LocalTree != nil {
		param := p.ParametersCBF
		// fill filter with local data
		p.CountingBloomFilter = NewFilledBloomFilter(param, locTree)
		var randomCBF *CBF
		var err error
		if !p.IsRoot() {
			// decrypt random vector, where the public key is the root public key
			randomCBF, err = Decrypt(p.Suite(), p.Private(), p.Root().ServerIdentity.Public, p.RandomEncryptedCBF, param)
			if err != nil {
				return err
			}
		} else {
			randomCBF = &CBF{Set: p.RandomEncryptedCBF, M: param[0], K: param[1]}
		}
		// merge random CBF with local CBF
		p.CountingBloomFilter.Merge(randomCBF)

		if !p.IsLeaf() {
			// aggregate all the children's reply
			for _, r := range reply {
				verificationErr := schnorr.Verify(p.Suite(), r.TreeNode.ServerIdentity.Public, r.CBFSet, r.CBFSetSig)
				if verificationErr == nil {
					p.CountingBloomFilter.MergeSet(r.CBFSet)
				}
			}
		}
	}

	return nil
}

func (p *SaveLocalState) signCBFSet() ([]byte, error) {
	if p.CountingBloomFilter == nil {
		return []byte(""), nil
	}
	set := p.CountingBloomFilter.GetSet()
	sig, err := schnorr.Sign(p.Suite(), p.Private(), set)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// AggregateUnstructData take locHash, the hash of the data signed by the current
// node and reply the replies of the node's children. It verifies and signs the
// p.MasterHash with the signatures of both the nodes and its chidren.
func (p *SaveLocalState) AggregateUnstructData(locHash map[string]map[kyber.Point][]byte, reply []StructSaveReply) {
	if p.MasterHash != nil && len(p.MasterHash) > 0 {
		for img, sigmap := range locHash {
			for srv, sig := range sigmap {
				vErr := schnorr.Verify(
					p.Suite(),
					srv,
					[]byte(img),
					sig)
				if vErr == nil {
					if _, ok := p.MasterHash[img]; !ok {
						p.MasterHash[img] =
							make(map[kyber.Point][]byte)
					}
					p.MasterHash[img][p.Public()] = sig
				}
			}
		}
		for _, r := range reply {
			for img, sigmap := range r.SaveReply.MasterHash {
				for srv, sig := range sigmap {
					vErr := schnorr.Verify(
						p.Suite(),
						srv,
						[]byte(img),
						sig)
					if vErr == nil {
						if _, ok := p.MasterHash[img]; !ok {
							p.MasterHash[img] =
								make(map[kyber.Point][]byte)
						}
						p.MasterHash[img][srv] = sig
					}
				}
			}
		}
	}
}

// generateRandomCBF generates random and encrypted CBFs for all the conodes, except root.
// For root, we generate a CBF such that all the "columns" of all the random CBFs, so
// the CBFs of the conodes and the CBF of the root, sum up to newZero. Note that only
// root can executed this function (we insert an if/else condition to enforce this)
func (p *SaveLocalState) generateRandomCBF(param64 []uint64) (map[string][]byte, error) {
	// this is used to make the code generic even when handling
	// additional data, i.e. css and images
	if param64 == nil {
		return nil, nil
	}

	if p.IsRoot() {
		// cast param to uint
		param := []uint{uint(param64[0]), uint(param64[1])}
		// allocate maps
		randomCBFs := make(map[string]*CBF)
		randomEncryptedCBFs := make(map[string][]byte)

		// define constants
		bitLen := uint(3) // TODO use a constant?
		conodes := len(p.Roster().List)
		newZero := byte(conodes*(int(math.Pow(float64(2), float64(bitLen)))-1) + conodes)

		// create a random and encrypted CBF for all the conodes except for root
		for _, kp := range (p.Roster()).Publics() {
			// skip root, note that we are sure that the roos
			// is executing this function
			if kp.Equal(p.TreeNode().ServerIdentity.Public) {
				continue
			}
			// generate random counting Bloom filter
			randomCBF := NewBloomFilter(param)
			for i := range randomCBF.GetSet() {
				randomCBF.SetByte(uint(i), random.Bits(3, false, p.Suite().RandomStream())[0])
			}
			randomCBFs[kp.String()] = randomCBF

			// encrypt the CBF using DH to seed AES
			encodedCipherText, err := randomCBF.Encrypt(p.Suite(), p.Private(), kp)
			if err != nil {
				return nil, err
			}

			// encode the ciphertext and add to the map
			randomEncryptedCBFs[kp.String()] = encodedCipherText
		}

		// now create the CBF for the root of the tree, by making all the "columns" of
		// all the random CBFs summing up to newZero.
		// Note that param[0] = m, the number of buckets in the CBF
		rootCBF := NewBloomFilter(param)
		for i := uint(0); i < param[0]; i++ {
			var sum byte
			for _, cbf := range randomCBFs {
				sum += cbf.GetByte(i)
			}
			val := newZero - sum
			rootCBF.SetByte(i, val)
		}
		randomCBFs[p.TreeNode().ServerIdentity.Public.String()] = rootCBF
		// return the root vector in the randomEncryptedCBFs map, even if it's not encrypted
		randomEncryptedCBFs[p.TreeNode().ServerIdentity.Public.String()] = rootCBF.GetSet()

		return randomEncryptedCBFs, nil
	}

	return nil, errors.New("Only root should generate the random encrypted counting Bloom filters")
}

// getMostSignedHash returns a new map containing only the entry of the map
// where the number of signature is the highest.
// If hashmap is nil, it returns nil.
// If no entry are under p.Threshold, it returns a non-nil error.
//
// Warning: the signatures verification must be done BEFORE using this function.
// No signatures verification are done here.
func getMostSignedHash(p *SaveLocalState, hashmap map[string]map[kyber.Point][]byte) (map[string]map[kyber.Point][]byte, error) {
	if hashmap == nil {
		return nil, nil
	}

	var maxImgH string = ""
	for imgH, sigs := range hashmap {
		if maxImgH == "" {
			maxImgH = imgH
		}
		l := len(sigs)
		if l >= int(p.Threshold) && l >= len(hashmap[maxImgH]) {
			maxImgH = imgH
		}
	}
	if len(hashmap[maxImgH]) < int(p.Threshold) {
		return nil, errors.New("No sufficient consensus for data")
	}
	maxMap := make(map[string]map[kyber.Point][]byte)
	maxMap[maxImgH] = hashmap[maxImgH]
	return maxMap, nil
}

// getRequestedMissingHash should be used only during the RequestMissingData
// phase. It outputs the hash of the data requested by the root.
// A hash is produced only if the number of verified signature is higher than
// the node threshold.
func getRequestedMissingHash(p *SaveLocalState) string {
	var missingHash string
	for dataH, sigs := range p.MasterHash {
		if len(sigs) >= int(p.Threshold) {
			verifiedSig := 0
			for srv, sig := range sigs {
				vErr := schnorr.Verify(
					p.Suite(),
					srv,
					[]byte(dataH),
					sig)
				if vErr != nil {
					p.Errs = append(p.Errs, vErr)
				}
				verifiedSig += 1
			}
			if verifiedSig >= int(p.Threshold) {
				missingHash = dataH
				break
			}
		}
	}
	return missingHash
}

func (p *SaveLocalState) BuildCBFConsensusHtmlPage() []byte {
	log.Lvl4("Begin building consensus html page")
	// TODO: this should be moved somewhere else
	threshold := byte(2)
	anonRoot := p.LocalTree

	var queue []*AnonNode
	var curr *AnonNode
	discovered := make(map[*AnonNode]*html.Node)
	queue = append(queue, anonRoot)
	for len(queue) != 0 {
		curr = queue[0]
		queue = queue[1:]
		if _, ok := discovered[curr]; !ok {
			html := p.PlainNodes[curr.HashedData]
			if curr.FirstChild == nil { // it is a leaf
				if p.CountingBloomFilter.Count([]byte(curr.HashedData))-byte(24) >= threshold {
					discovered[curr] = &html
				}
			} else {
				discovered[curr] = &html
			}
			for n := curr.FirstChild; n != nil; n = n.NextSibling {
				queue = append(queue, n)
			}
		}
	}

	// convert *html.Nodes tree to an html page
	var page bytes.Buffer
	err := html.Render(&page, discovered[anonRoot])
	if err != nil {
		return nil
	}
	return page.Bytes()
}
