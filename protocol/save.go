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
	"regexp"
	"sort"
	"strings"

	"golang.org/x/net/html"
	"net/http"
	urlpkg "net/url"

	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func init() {
	network.RegisterMessage(SaveAnnounce{})
	network.RegisterMessage(SaveReply{})
	onet.GlobalProtocolRegister(SaveName, NewSaveProtocol)
}

// SaveMessage just holds a message that is passed to all children. It
// also defines a channel that will receive the number of children. Only the
// root-node will write to the channel.
type SaveMessage struct {
	*onet.TreeNodeInstance
	Phase       SavePhase
	Errs        []error
	Url         string
	ContentType string
	Threshold   int32
	MasterTree  *AnonNode
	MasterHash  map[string]map[*network.ServerIdentity]crypto.SchnorrSig

	PlainNodes map[string]html.Node
	PlainData  map[string][]byte

	MsgToSign  chan []byte
	StringChan chan string
}

// NewSaveProtocol initialises the structure for use in one round
func NewSaveProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("Creating NewSaveProtocol")
	t := &SaveMessage{
		TreeNodeInstance: n,
		Url:              "",
		Phase:            NilPhase,
		PlainNodes:       make(map[string]html.Node),
		PlainData:        make(map[string][]byte),
		MsgToSign:        make(chan []byte),
		StringChan:       make(chan string),
	}
	for _, handler := range []interface{}{t.HandleAnnounce, t.HandleReply} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}
	return t, nil
}

// Start sends the Announce-message to all children
func (p *SaveMessage) Start() error {
	log.Lvl3("Starting SaveMessage")
	p.Phase = Consensus
	masterTree, masterHash, err := p.GetLocalData()
	if err != nil {
		log.Fatal("Error occurs during the protocol starting phase:", err)
	}
	p.MasterTree = masterTree
	p.MasterHash = masterHash
	return p.HandleAnnounce(StructSaveAnnounce{
		p.TreeNode(),
		SaveAnnounce{
			Url:        p.Url,
			Phase:      Consensus,
			MasterTree: convertToExplicitTree(p.MasterTree),
			MasterHash: p.MasterHash},
	})
}

// HandleAnnounce is the first message and is used to send an ID that
// is stored in all nodes.
func (p *SaveMessage) HandleAnnounce(msg StructSaveAnnounce) error {
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
		p.MasterHash = msg.SaveAnnounce.MasterHash
		if !p.IsLeaf() {
			return p.SendToChildren(&msg.SaveAnnounce)
		} else {
			resp := StructSaveReply{
				p.TreeNode(),
				SaveReply{
					Phase:      msg.SaveAnnounce.Phase,
					Url:        msg.SaveAnnounce.Url,
					MasterTree: msg.SaveAnnounce.MasterTree,
					MasterHash: msg.SaveAnnounce.MasterHash,
					Errs:       p.Errs},
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

// HandleReply is the message going up the tree and holding a counter
// to verify the number of nodes.
func (p *SaveMessage) HandleReply(reply []StructSaveReply) error {
	log.Lvl3("Handling Save Reply", p)
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
		if p.IsRoot() {
			log.Lvl4("Consensus reach root. Passing to next phase")
			// consensus on structured data
			if p.MasterTree != nil {
				masterRoot := p.MasterTree
				removeBelowThresholdNodes(p, masterRoot)
				//p.MasterTree = masterRoot
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
				Phase:      p.Phase,
				Url:        p.Url,
				MasterTree: convertToExplicitTree(p.MasterTree),
				MasterHash: p.MasterHash,
			}
			p.HandleAnnounce(StructSaveAnnounce{p.TreeNode(), msg})
		} else {
			log.Lvl4("Sending Consensus to Parent")
			resp := SaveReply{
				Phase:      p.Phase,
				Url:        p.Url,
				MasterTree: convertToExplicitTree(p.MasterTree),
				MasterHash: p.MasterHash,
				Errs:       p.Errs}
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
					hashedData, hashErr := crypto.HashBytes(network.Suite.Hash(), plain)
					if hashErr != nil {
						p.Errs = append(p.Errs, hashErr)
						continue
					}
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
				p.MsgToSign <- p.BuildConsensusHtmlPage()
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
	return errors.New("The protocol has skip the reply handling.")
}

// GetLocalData retrieve the data from the p.Url and handle it to make it either a AnonNodes tree
// or a signed hash.
// If the returned *AnonNode tree is not nil, then the map is. Else, it is the other way around.
// If both returned value are nil, then an error occured.
func (p *SaveMessage) GetLocalData() (*AnonNode, map[string]map[*network.ServerIdentity]crypto.SchnorrSig, error) {
	// get data
	resp, realUrl, _, err := GetRemoteData(p.Url)
	if err != nil {
		log.Lvl1("Error! Impossible to retrieve remote data.")
		return nil, nil, err
	}
	p.Url = realUrl
	defer resp.Body.Close()
	// apply procedure according to data type
	contentTypes := resp.Header.Get(http.CanonicalHeaderKey("Content-Type"))
	p.ContentType = contentTypes
	if b, e := regexp.MatchString("text/html", contentTypes); b && e == nil {
		htmlTree, htmlErr := html.Parse(resp.Body)
		if htmlErr != nil {
			log.Lvl1("Error: Impossible to parse html code!")
			return nil, nil, htmlErr
		}
		prunedHtmlTree := PruneHtmlTree(htmlTree)
		anonRoot := HtmlToAnonTree(p, prunedHtmlTree)
		return anonRoot, nil, nil
	} else {
		rawData, readErr := ioutil.ReadAll(resp.Body)
		if readErr != nil {
			log.Lvl1("Error: Impossible to read http request body!")
			return nil, nil, readErr
		}
		hashedData, hashErr := crypto.HashBytes(network.Suite.Hash(), rawData)
		if hashErr != nil {
			log.Lvl1("Error: Impossible to hash data!")
			return nil, nil, hashErr
		}
		locHashKey := base64.StdEncoding.EncodeToString(hashedData)
		sig, sigErr := crypto.SignSchnorr(network.Suite, p.Private(), []byte(locHashKey))
		if sigErr != nil {
			log.Lvl1("Error: Impossible to sign data!")
			return nil, nil, sigErr
		}
		localHash := make(map[string]map[*network.ServerIdentity]crypto.SchnorrSig)
		localHash[locHashKey] = make(map[*network.ServerIdentity]crypto.SchnorrSig)
		localHash[locHashKey][p.ServerIdentity()] = sig
		// save plaintext data locally
		p.PlainData[locHashKey] = rawData

		return nil, localHash, nil
	}
	return nil, nil, errors.New("Cannot handle data!")
}

// GetRemoteData take a url and return:
// - the http response corresponding to the url
// - the un-alias url corresponding to the response (id est the path to the file on
// the remote server)
// - the url structure associated (see net/url Url struct)
// - an error status
func GetRemoteData(url string) (*http.Response, string, *urlpkg.URL, error) {
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

// PruneHtmlTree is used to remove some parts of the tree that the node consider
// irrelevant for the final consensus tree.
//
// Note: for now, no pruning is done to the tree.
func PruneHtmlTree(tree *html.Node) *html.Node {
	return tree
}

// HtmlToAnonTree turn an tree composed of *html.Node to the corresponding tree
// composed of *AnonNode
func HtmlToAnonTree(p *SaveMessage, root *html.Node) *AnonNode {
	var queue []*html.Node
	var curr *html.Node
	discovered := make(map[*html.Node]*AnonNode)
	queue = append(queue, root)
	for len(queue) != 0 {
		curr = queue[0]
		queue = queue[1:]
		if _, ok := discovered[curr]; !ok {
			an := HtmlToAnonNode(p, curr)
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

// HtmlToAnonNode take a SaveMessage p and a pointer to html node hn as input
// and output the *AnonNode corresponding to hn.
// The SaveMessage is used in the signing process of the *AnonNode and to store
// the node locally as plaintext.
func HtmlToAnonNode(p *SaveMessage, hn *html.Node) *AnonNode {
	var anonNode *AnonNode = &AnonNode{}
	hashedData := hashHtmlData(hn)
	anonNode.HashedData = hashedData
	sig, sigErr := crypto.SignSchnorr(network.Suite, p.Private(), []byte(hashedData))
	if sigErr != nil {
		return anonNode
	}
	anonNode.Sign(p.ServerIdentity(), sig)

	// save node locally (only its data are relevant, not its position)
	p.PlainNodes[hashedData] = *hn

	return anonNode
}

// hashHtmlData turn the data fields of the html node hn into a hash.
// The "data fields" are all the attributes of an html Nodes except the ones
// related to its position in the html tree. Furthermore, the list hn.Attr is
// sorted before the hashing process.
func hashHtmlData(hn *html.Node) string {
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
	hashedData, hashErr := crypto.HashBytes(network.Suite.Hash(), data)
	if hashErr != nil {
		log.Fatal("Error during hashing the data of an html node")
	}

	return base64.StdEncoding.EncodeToString(hashedData)
}

// signMasterTree compares a slave tree define by its root salveRoot and a
// master tree defined by its root masterRoot. It adds the signature of the
// conode server on all the nodes of the master tree that can be associated
// with a node of the slave tree.
// See the high-level documentation (/doc/) for further details.
func signMasterTree(slaveRoot *AnonNode, masterRoot *AnonNode) error {
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
				}
				if sameLength && similarCommonAncestor {
					for k := 0; k < len(slavep); k++ {
						if !slavep[k].IsSimilarTo(masterp[k]) {
							break
						}
						if k == len(slavep)-1 {
							// we sign all the nodes of masterPaths[j]
							for nIdx := 0; nIdx < len(masterp); nIdx++ {
								sigsToAdd := slavep[nIdx].Signatures
								for srv, sig := range sigsToAdd {
									vErr := crypto.VerifySchnorr(
										network.Suite,
										srv.Public,
										[]byte(masterp[nIdx].HashedData),
										sig)
									if vErr == nil {
										masterp[nIdx].Sign(srv, sig)
									}
								}
							}
							mostLeftMasterSignedPathIdx = j
							mostLeftSlaveSignedPathIdx = i
						}
					}
					if mostLeftMasterSignedPathIdx == j {
						break
					}
				}
			}
		}
	}
	return nil
}

// AggregateErrors put all the errors contained in the children reply inside
// the SaveMessage p field p.Errs. It allows the current protocol to transmit
// the errors from its children to its parent.
func (p *SaveMessage) AggregateErrors(reply []StructSaveReply) {
	for _, r := range reply {
		p.Errs = append(p.Errs, r.Errs...)
	}
}

// AggregateStructData take locTree the tree computed locally by the node and
// reply the replies of the node's children. It add the localTree signatures and
// the children's tree signatures inside the master tree that will be send to
// the node's parent.
func (p *SaveMessage) AggregateStructData(locTree *AnonNode, reply []StructSaveReply) {
	if p.MasterTree != nil {
		masterRoot := p.MasterTree
		sigErr := signMasterTree(locTree, masterRoot)
		if sigErr != nil {
			log.Lvl1("Error! Impossible to sign master tree", sigErr)
			p.Errs = append(p.Errs, sigErr)
		}
		for _, r := range reply {
			if r.SaveReply.Url == p.Url {
				childSigErr := signMasterTree(
					convertToAnonTree(r.SaveReply.MasterTree),
					masterRoot)
				if childSigErr != nil {
					log.Lvl1(
						"Error! Impossible to sign master tree",
						childSigErr)
					p.Errs = append(p.Errs, childSigErr)
				}
			}
		}
	}
}

// AggregateUnstructData take locHash, the hash of the data signed by the current
// node and reply the replies of the node's children. It verifies and signs the
// p.MasterHash with the signatures of both the nodes and its chidren.
func (p *SaveMessage) AggregateUnstructData(locHash map[string]map[*network.ServerIdentity]crypto.SchnorrSig, reply []StructSaveReply) {
	if p.MasterHash != nil && len(p.MasterHash) > 0 {
		for img, sigmap := range locHash {
			for srv, sig := range sigmap {
				vErr := crypto.VerifySchnorr(
					network.Suite,
					srv.Public,
					[]byte(img),
					sig)
				if vErr == nil {
					if _, ok := p.MasterHash[img]; !ok {
						p.MasterHash[img] =
							make(map[*network.ServerIdentity]crypto.SchnorrSig)
					}
					p.MasterHash[img][p.ServerIdentity()] = sig
				}
			}
		}
		for _, r := range reply {
			for img, sigmap := range r.SaveReply.MasterHash {
				for srv, sig := range sigmap {
					vErr := crypto.VerifySchnorr(
						network.Suite,
						srv.Public,
						[]byte(img),
						sig)
					if vErr == nil {
						if _, ok := p.MasterHash[img]; !ok {
							p.MasterHash[img] =
								make(map[*network.ServerIdentity]crypto.SchnorrSig)
						}
						p.MasterHash[img][srv] = sig
					}
				}
			}
		}
	}
}

// removeBelowThresholdNodes takes all the leaves of the tree defined by root
// and remove the nodes that are signed by a number of server inferior to the
// p.Threshold.
//
// Warning : the signatures verification must be done BEFORE using this
// function. No signature verification are done here.
//
// Note : This function is highly linked with the signMasterTree function
// a change in the latter probably means a change in this one.
func removeBelowThresholdNodes(p *SaveMessage, root *AnonNode) error {
	if root == nil {
		return nil
	}

	var errs []error
	leaves := root.ListLeaves()
	for _, leaf := range leaves {
		if len(leaf.Signatures) >= int(p.Threshold) {
			var parent *AnonNode = leaf.Parent
			var child *AnonNode = leaf
			for ; parent != nil && parent.FirstChild == nil; parent = parent.Parent {
				errs = append(errs, parent.RemoveChild(child))
				child = parent
			}
		}
	}
	if len(errs) > 0 {
		return errors.New("Some below threshold children were not removed")
	}

	return nil
}

// getMostSignedHash returns a new map containing only the entry of the map
// where the number of signature is the highest.
// If hashmap is nil, it returns nil.
// If no entry are under p.Threshold, it returns a non-nil error.
//
// Warning: the signatures verification must be done BEFORE using this function.
// No signatures verification are done here.
func getMostSignedHash(p *SaveMessage, hashmap map[string]map[*network.ServerIdentity]crypto.SchnorrSig) (map[string]map[*network.ServerIdentity]crypto.SchnorrSig, error) {
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
	maxMap := make(map[string]map[*network.ServerIdentity]crypto.SchnorrSig)
	maxMap[maxImgH] = hashmap[maxImgH]
	return maxMap, nil
}

// getRequestedMissingHash should be used only during the RequestMissingData
// phase. It outputs the hash of the data requested by the root.
// A hash is produced only if the number of verified signature is higher than
// the node threshold.
func getRequestedMissingHash(p *SaveMessage) string {
	var missingHash string
	for dataH, sigs := range p.MasterHash {
		if len(sigs) >= int(p.Threshold) {
			verifiedSig := 0
			for srv, sig := range sigs {
				vErr := crypto.VerifySchnorr(
					network.Suite,
					srv.Public,
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

// BuildConsensusHtmlPage takes the p.MasterTree made of *AnonNode and combine
// this data with the p.PlainNodes in order to create an *html.Node tree. From
// there, it creates a valid html page and outputs it.
func (p *SaveMessage) BuildConsensusHtmlPage() []byte {
	log.Lvl4("Begin building consensus html page")
	// convert ExplicitNodes Tree to *html.Nodes tree
	explicitTree := convertToExplicitTree(p.MasterTree)
	var treeNodes []*html.Node = make([]*html.Node, 0)
	var root html.Node = ExplicitToHtmlNode(p.PlainNodes, explicitTree[0])
	treeNodes = append(treeNodes, &root)
	for _, child := range explicitTree[0].Children {
		child := ExplicitToHtmlNode(p.PlainNodes, explicitTree[child])
		(&root).AppendChild(&child)
		treeNodes = append(treeNodes, &child)
	}
	for i, node := range explicitTree {
		if i > 0 {
			var htmlNode *html.Node = treeNodes[i]
			for _, child := range node.Children {
				child := ExplicitToHtmlNode(p.PlainNodes, explicitTree[child])
				htmlNode.AppendChild(&child)
				treeNodes = append(treeNodes, &child)
			}

		}
	}

	// convert *html.Nodes tree to an html page
	var page bytes.Buffer
	err := html.Render(&page, &root)
	if err != nil {
		return nil
	}
	return page.Bytes()
}

func ExplicitToHtmlNode(plainNodes map[string]html.Node, en ExplicitNode) html.Node {
	var node html.Node = html.Node{
		Parent:      nil,
		FirstChild:  nil,
		LastChild:   nil,
		PrevSibling: nil,
		NextSibling: nil,

		Type:      plainNodes[en.HashedData].Type,
		DataAtom:  plainNodes[en.HashedData].DataAtom,
		Data:      plainNodes[en.HashedData].Data,
		Namespace: plainNodes[en.HashedData].Namespace,
		Attr:      plainNodes[en.HashedData].Attr}
	return node
}
