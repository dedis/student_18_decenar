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

	MasterTree    *AnonNode
	MasterTreeSig []byte
	LocSeen       []bool
	LocSig        []byte
	SeenMap       map[string][]bool
	SeenSig       map[string][]byte

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
	masterTree, masterHash, err := p.GetLocalData()
	if err != nil {
		log.Error("Error in save protocol Start():", err)
		return err
	}
	p.MasterTree = masterTree
	p.MasterHash = masterHash
	explicitTree := convertToExplicitTree(p.MasterTree)
	p.LocSeen = getSeenFromExplicitTree(explicitTree)
	sig, sErr := createLocalSig(p, explicitTree)
	if sErr != nil {
		log.Fatal("Error in save protocol Start():", sErr)
	}
	paramCBF := GetOptimalCBFParametersToSend(masterTree)
	var randomCBFs map[string][]byte
	if masterTree != nil {
		// TODO: mybe not in the if, verify how to deal with AD
		randomCBFs, err = p.generateRandomCBF(paramCBF)
		if err != nil {
			log.Error("Error in save protocol Start():", err)
			return err
		}
	}
	log.Lvl4("Send Explicit Tree to service")
	p.RefTreeChan <- explicitTree
	return p.HandleAnnounce(StructSaveAnnounce{
		p.TreeNode(),
		SaveAnnounce{
			Url:                 p.Url,
			Phase:               Consensus,
			MasterTree:          explicitTree,
			MasterTreeSig:       sig,
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
				Errs:  []error{err}},
		}
		defer p.HandleReply([]StructSaveReply{resp})
		return err
	case Consensus:
		log.Lvl4("Consensus Phase")
		p.MasterTree = convertToAnonTree(msg.SaveAnnounce.MasterTree)
		p.MasterTreeSig = msg.SaveAnnounce.MasterTreeSig
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
					Phase:         msg.SaveAnnounce.Phase,
					Url:           msg.SaveAnnounce.Url,
					MasterTree:    msg.SaveAnnounce.MasterTree,
					MasterTreeSig: msg.SaveAnnounce.MasterTreeSig,
					MasterHash:    msg.SaveAnnounce.MasterHash,
					Errs:          p.Errs},
			}
			return p.HandleReply([]StructSaveReply{resp})
		}
	case RequestMissingData:
		log.Lvl4("RequestMissingData Phase with", p)
		p.MasterTree = convertToAnonTree(msg.SaveAnnounce.MasterTree)
		p.MasterHash = msg.SaveAnnounce.MasterHash
		if p.MasterTree != nil {
			// The root started the protocol and produced
			// the master tree so a RequestMissingData phase
			// is not necessary.
		}
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
				MasterTree: convertToExplicitTree(p.MasterTree),
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
		msg.SaveAnnounce.MasterTreeSig = []byte("") // TODO: MasterTreeSig should be optional in the message, using pointer
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
		p.AggregateStructData(locTree, reply)
		p.AggregateUnstructData(locHash, reply)
		p.AggregateCBF(locTree, reply)
		CBFSetSig, err := p.signCBFSet()
		if err != nil {
			return err
		}
		if p.IsRoot() {
			log.Lvl4("Consensus reach root. Passing to next phase")
			// consensus on structured data
			var consensusRoot *AnonNode
			if p.MasterTree != nil {
				validSeen, _, valErr := getValidOnlySeenSig(p)
				if valErr != nil {
					p.Errs = append(p.Errs, valErr)
				}
				consRoot, consErr := createConsensusTree(p, validSeen)
				if consErr != nil {
					p.Errs = append(p.Errs, consErr)
				}
				consensusRoot = consRoot
			}
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
				Phase:         p.Phase,
				Url:           p.Url,
				MasterTree:    convertToExplicitTree(consensusRoot),
				MasterTreeSig: nil,
				MasterHash:    p.MasterHash,
			}
			p.HandleAnnounce(StructSaveAnnounce{p.TreeNode(), msg})
		} else {
			log.Lvl4("Sending Consensus to Parent")
			resp := SaveReply{
				Phase: p.Phase,
				Url:   p.Url,

				MasterTree:    convertToExplicitTree(p.MasterTree),
				MasterTreeSig: p.MasterTreeSig,
				SeenMap:       seenmapBoolToByte(p.SeenMap),
				SigMap:        p.SeenSig,

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

		if p.MasterTree != nil {
			// It is assumed that the root node does not require any
			// data when the latter is structured.
		}
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
			if p.MasterTree != nil {
				p.MsgToSign <- p.BuildCBFConsensusHtmlPage()
			} else if p.MasterHash != nil && len(p.MasterHash) > 0 {
				p.MsgToSign <- p.PlainData[requestedHash]
			}
			p.SeenMapChan <- seenmapBoolToByte(p.SeenMap)
			p.SeenSigChan <- p.SeenSig
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
				MasterTree:    convertToExplicitTree(p.MasterTree),
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
		prunedHtmlTree := htmlTree
		anonRoot := htmlToAnonTree(p, prunedHtmlTree)
		return anonRoot, nil, nil
	} else {
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
	return nil, nil, errors.New("Cannot handle data!")
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

// getSeenFromExplicitTree extract the Seen field from each ExplicitNode and put
// it in an array.
func getSeenFromExplicitTree(et []ExplicitNode) []bool {
	var seen []bool = make([]bool, len(et))
	for i := 0; i < len(seen); i++ {
		seen[i] = (et[i]).Seen
	}
	return seen
}

// createLocalSig creates the signature of the local conode associated with the
// partial tree seen by the conode. The masterTree is the reference tree.
// It also involves p.LocSeen as seen. It is an array where seen[i] = true iff
// masterTree[i] has been seen locally by the conode.
func createLocalSig(p *SaveLocalState, masterTree []ExplicitNode) ([]byte, error) {
	seen := p.LocSeen
	if len(masterTree) != len(seen) {
		return nil, errors.New("createLocalSig - not all nodes were tagged")
	}
	hashToSign, hErr := getExplicitSeenHash(p, masterTree, seen)
	if hErr != nil {
		return nil, hErr
	}
	sig, sigErr := schnorr.Sign(p.Suite(), p.Private(), hashToSign)
	if sigErr != nil {
		return nil, sigErr
	}
	return sig, nil
}

// getExplicitSeenHash take an explicit tree en and an array seen where
// seen[i] = true iff the conode has seen en[i] on its locally retrieved webdata
// else, seen[i] = false.
// It creates a hash of the tree represented as a byte array of the hashed data
// followed by the index of the children if the node is seen or a 0 if not.
func getExplicitSeenHash(p *SaveLocalState, en []ExplicitNode, seen []bool) ([]byte, error) {
	if len(en) != len(seen) {
		return nil, errors.New("createLocalSig - not all nodes were tagged")
	}
	var data []byte = make([]byte, 0)
	emptyNode := byte(0)
	for idx, node := range en {
		if seen[idx] {
			data = append(data, []byte(node.HashedData)...)
			for _, child := range node.Children {
				data = append(data, byte(child))
			}
		} else {
			data = append(data, emptyNode)
		}
	}
	hash := p.Suite().(kyber.HashFactory).Hash().Sum(data)
	return hash, nil
}

// setLocalSeenAndSign compares a slave tree define by its root salveRoot and a
// master tree defined by its root masterRoot. It adds the signature of the
// conode server on all the nodes of the master tree that can be associated
// with a node of the slave tree.
func setLocalSeenAndSign(p *SaveLocalState, slaveRoot *AnonNode, masterRoot *AnonNode) error {
	// compare salveTree and masterTree and mark the master
	unseenWholeTree(masterRoot)
	masterPaths := masterRoot.ListPaths()
	slavePaths := slaveRoot.ListPaths()

	mostLeftMasterSignedPathIdx := -1
	mostLeftSlaveSignedPathIdx := -1
	for i, slavep := range slavePaths {
		for j, masterp := range masterPaths {
			if j > mostLeftMasterSignedPathIdx {
				sameLength := len(slavep) == len(masterp)
				similarCommonAncestor := true
				if mostLeftSlaveSignedPathIdx >= 0 && mostLeftMasterSignedPathIdx >= 0 {
					sH, sCA := commonAncestor(
						slavep,
						slavePaths[mostLeftSlaveSignedPathIdx])
					mH, mCA := commonAncestor(
						masterp,
						masterPaths[mostLeftMasterSignedPathIdx])
					if sH < 0 || mH < 0 {
						return errors.New("Two paths on same tree do not share a root")
					}
					similarCommonAncestor = (sH == mH) && sCA.IsSimilarTo(mCA)
					similarCommonAncestor = (sH == mH) &&
						(sCA.HashedData == mCA.HashedData)

				}
				if sameLength && similarCommonAncestor {
					var simNodes bool = true
					for k := 0; k < len(slavep); k++ {
						simTest := masterp[k].HashedData == slavep[k].HashedData
						if !simTest {
							simNodes = false
							break
						}
					}
					if simNodes {
						// we mark all the nodes of masterPaths[j] as seen
						for nIdx := 0; nIdx < len(masterp); nIdx++ {
							masterp[nIdx].Seen = true
						}
						mostLeftMasterSignedPathIdx = j
						mostLeftSlaveSignedPathIdx = i
					}
					// if we found a match, skip the left master paths
					if mostLeftMasterSignedPathIdx == j {
						break
					}
				}
			}
		}
	}
	// create p.LocSeen
	masterExplicit := convertToExplicitTree(masterRoot)
	seen := getSeenFromExplicitTree(masterExplicit)
	p.LocSeen = seen
	// create p.LocSig
	sig, sigErr := createLocalSig(p, masterExplicit)
	if sigErr != nil {
		return sigErr
	}
	p.LocSig = sig
	return nil
}

// unseenWholeTree takes the root of an AnonTree and put all the Seen fields
// of all the nodes to false.
func unseenWholeTree(root *AnonNode) {
	var stack []*AnonNode
	var discovered map[*AnonNode]bool = make(map[*AnonNode]bool)
	var curr *AnonNode
	stack = append(stack, root)
	for len(stack) != 0 {
		l := len(stack)
		curr = stack[l-1]
		stack = stack[:l-1]
		if !discovered[curr] {
			discovered[curr] = true
			curr.Seen = false
			for n := curr.FirstChild; n != nil; n = n.NextSibling {
				stack = append(stack, n)
			}
		}
	}
}

// AggregateErrors put all the errors contained in the children reply inside
// the SaveLocalState p field p.Errs. It allows the current protocol to transmit
// the errors from its children to its parent.
func (p *SaveLocalState) AggregateErrors(reply []StructSaveReply) {
	for _, r := range reply {
		p.Errs = append(p.Errs, r.Errs...)
	}
}

// AggregateStructData take locTree the tree computed locally by the node and
// reply the replies of the node's children. It add the localTree signatures and
// the children's tree signatures inside the master tree that will be send to
// the node's parent.
func (p *SaveLocalState) AggregateStructData(locTree *AnonNode, reply []StructSaveReply) {
	if p.MasterTree != nil {
		// create local result
		masterRoot := p.MasterTree
		sigErr := setLocalSeenAndSign(p, locTree, masterRoot)
		if sigErr != nil {
			log.Lvl1("Error! Impossible to sign master tree", sigErr)
			p.Errs = append(p.Errs, sigErr)
		}
		// aggregate children reply with local data (no signature verification)
		for _, r := range reply {
			for kp, seen := range seenmapByteToBool(r.SeenMap) {
				p.SeenMap[kp] = seen
			}
			for kp, sig := range r.SigMap {
				p.SeenSig[kp] = sig
			}
		}
		// add local result to aggregated result
		p.SeenMap[p.Public().String()] = p.LocSeen
		p.SeenSig[p.Public().String()] = p.LocSig
	}
}

func (p *SaveLocalState) AggregateCBF(locTree *AnonNode, reply []StructSaveReply) error {
	// This method is only for structured data
	if p.MasterTree != nil {
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

// getValidOnlySeenSig verifies all the signatures involved in the consensus
// protocol. More precisely,
//     - the signature associated to the MasterTree : p.MasterTreeSig
//     - the couple (seen,signature) for each of p.SeenMap, p.SennSig
// and return a seen map and a signature map that contains only valid signatures
// also, an error is returned if the signature of the masterTree is invalid.
func getValidOnlySeenSig(p *SaveLocalState) (map[kyber.Point][]bool, map[kyber.Point][]byte, error) {
	// verify mastertree signature
	masterExplicit := convertToExplicitTree(p.MasterTree)
	allSeen := make([]bool, len(masterExplicit))
	for i, _ := range allSeen {
		allSeen[i] = true
	}
	masterHash, mhErr := getExplicitSeenHash(p, masterExplicit, allSeen)
	if mhErr != nil {
		return nil, nil, mhErr
	}
	vMErr := schnorr.Verify(
		p.Suite(),
		p.Root().ServerIdentity.Public,
		masterHash,
		p.MasterTreeSig)
	if vMErr != nil {
		return nil, nil, vMErr
	}
	// verify only signature related to the roster
	validSeen := make(map[kyber.Point][]bool)
	validSig := make(map[kyber.Point][]byte)
	for _, kp := range (p.Roster()).Publics() {
		if seen, ok := p.SeenMap[kp.String()]; ok {
			if sig, sok := p.SeenSig[kp.String()]; sok {
				slaveHash, shErr := getExplicitSeenHash(p, masterExplicit, seen)
				if shErr == nil {
					vsErr := schnorr.Verify(
						p.Suite(),
						kp,
						slaveHash,
						sig)
					if vsErr == nil {
						log.Lvl4("Valid seen signature for", kp)
						validSeen[kp] = seen
						validSig[kp] = sig
					} else {
						log.Lvl1("Invalid seen signature for", kp)
					}
				} else {
					log.Lvl1("Impossible to hash with seen:", kp)
				}
			} else {
				log.Lvl1("A conode did send seen but no signature:", kp)
			}
		} else {
			log.Lvl1("A conode did not send a seen array:", kp)
		}
	}
	return validSeen, validSig, nil
}

// createConsensusTree create the tree that is the consensus found. It takes the
// all the valid/verified seen array received form children
// (including its own root result) and return an *AnonNode root of the tree
// containing only below threshold nodes.
//
// Warning : the signatures verification must be done BEFORE using this
// function. No signature verification are done here.
//
// Note : This function is highly linked with the setLocalSeenAndSign function
// a change in the latter probably means a change in this one.
func createConsensusTree(p *SaveLocalState, validSeen map[kyber.Point][]bool) (*AnonNode, error) {
	unseenWholeTree(p.MasterTree)
	explicitMaster := convertToExplicitTree(p.MasterTree)
	aggregateSeen := make([]int, len(explicitMaster))
	for _, seen := range validSeen {
		for idx, val := range seen {
			if val {
				aggregateSeen[idx] += 1
			}
		}
	}
	for idx := 0; idx < len(explicitMaster); idx++ {
		if int(aggregateSeen[idx]) >= int(p.Threshold) {
			explicitMaster[idx].Seen = true
		} else {
			explicitMaster[idx].Seen = false
		}
	}
	root := convertToAnonTree(explicitMaster)
	for setChanged := true; setChanged; {
		leaves := root.ListLeaves()
		setChanged = false
		for _, leaf := range leaves {
			if !leaf.Seen {
				setChanged = true
				var parent *AnonNode = leaf.Parent
				var child *AnonNode = leaf
				parent.RemoveChild(child)
			}
		}
	}

	return root, nil
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
	anonRoot := p.MasterTree

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

// seenmapBoolToByte turns the p.SeenMap that contains the html nodes seen by the
// conode as a boolean list into a byte list where true~byte(1), false~byte(0)
// to make it network friendly.
func seenmapBoolToByte(boolseen map[string][]bool) map[string][]byte {
	bySeen := make(map[string][]byte)
	for key, bs := range boolseen {
		bySeen[key] = make([]byte, len(bs))
		for idx, b := range bs {
			if b {
				bySeen[key][idx] = byte(1)
			} else {
				bySeen[key][idx] = byte(0)
			}
		}
	}
	return bySeen
}

// seenmapByteToBool turns the network received SeenMap of a distant conode into
// a boolean list to make it compatible with the locally computed p.SeenMap used to
// define which html nodes had been seen by the local conode.
func seenmapByteToBool(byteseen map[string][]byte) map[string][]bool {
	boSeen := make(map[string][]bool)
	for key, bs := range byteseen {
		boSeen[key] = make([]bool, len(bs))
		for idx, b := range bs {
			if b == byte(1) {
				boSeen[key][idx] = true
			} else {
				boSeen[key][idx] = false
			}
		}
	}
	return boSeen
}
