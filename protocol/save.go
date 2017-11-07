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
	"errors"
	"path"
	"sort"
	"strings"

	"net/http"
	urlpkg "net/url"

	"golang.org/x/net/html"

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
	Errs          []error
	Url           string
	Phase         SavePhase
	Threshold     uint32
	ConsensusTree WeightedPath
	FullTree      *html.Node
	Paths         map[PathHash][]*html.Node
	MsgToSign     chan []byte
}

// NewSaveProtocol initialises the structure for use in one round
func NewSaveProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl5("Creating NewSaveProtocol")
	t := &SaveMessage{
		TreeNodeInstance: n,
		Url:              "",
		Phase:            NilPhase,
		MsgToSign:        make(chan []byte),
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
	saveUrl := p.Url
	return p.HandleAnnounce(StructSaveAnnounce{
		p.TreeNode(),
		SaveAnnounce{Url: saveUrl, Phase: Consensus},
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
		if !p.IsLeaf() {
			p.SendToChildren(msg)
		} else {
			resp := StructSaveReply{
				p.TreeNode(),
				SaveReply{
					Phase: msg.SaveAnnounce.Phase,
					Url:   msg.SaveAnnounce.Url},
			}
			defer p.HandleReply([]StructSaveReply{resp})
		}
		return nil
	case RequestMissingPath:
		// PHASE REQUEST MISSING PATH
		if p.IsRoot() {
			if p.ConsensusTree == nil {
				return errors.New("RequestMissingPath on nil tree")
			} else {
				var plainPath map[PathHash][]*html.Node = make(map[PathHash][]*html.Node)
				var missingPaths WeightedPath = make(WeightedPath)
				for hPath, srvSign := range p.ConsensusTree {
					if nodes, ok := p.Paths[hPath]; !ok {
						missingPaths[hPath] = srvSign
					} else {
						plainPath[hPath] = nodes
					}
				}
				p.Paths = plainPath // we keep only consensus path
				// if root has all the path, skip the phase for children
				if len(missingPaths) == 0 {
					p.Phase = RequestMissingPath
					resp := StructSaveReply{
						p.TreeNode(),
						SaveReply{
							Phase: p.Phase,
							Url:   p.Url,
						},
					}
					p.HandleReply([]StructSaveReply{resp})
				} else {
					childrenAnnouce := StructSaveAnnounce{
						p.TreeNode(),
						SaveAnnounce{
							Phase: RequestMissingPath,
							Url:   p.Url,
							Paths: missingPaths},
					}
					p.SendToChildren(childrenAnnouce)
				}
				return nil
			}
		} else {
			var plainPath map[PathHash][]*html.Node = make(map[PathHash][]*html.Node)
			var missingPathLeft WeightedPath = make(WeightedPath)
			for missHPath, missSrvSign := range msg.SaveAnnounce.Paths {
				if nodes, ok := p.Paths[missHPath]; ok {
					plainPath[missHPath] = nodes
				} else {
					missingPathLeft[missHPath] = missSrvSign
				}
			}
			p.Paths = plainPath // we only keep useful path from now
			if len(missingPathLeft) == 0 {
				resp := StructSaveReply{
					p.TreeNode(),
					SaveReply{
						Phase:        p.Phase,
						Url:          p.Url,
						MissingPaths: plainPath},
				}
				p.HandleReply([]StructSaveReply{resp})
			} else {
				childrenAnnouce := StructSaveAnnounce{
					p.TreeNode(),
					SaveAnnounce{
						Phase: p.Phase,
						Url:   p.Url,
						Paths: missingPathLeft},
				}
				p.SendToChildren(childrenAnnouce)
			}
		}
	case CoSigning:
		// PHASE COSIGNING
		// For the moment, we use the Cosi API at service level
	case SkipchainSaving:
		// PHASE SKIPCHAIN SAVING
		// For the moment, we use the Cosi API at service level
	case End:
		// PHASE END
		p.SendToChildren(msg)
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
	log.Lvl4("Handling Save Reply", p)
	log.Lvl4("And the replies", reply)
	switch p.Phase {
	case NilPhase:
		log.Lvl1("NilPhase passed by", p)
		defer p.Done()
		return errors.New("NilPhase should not be replyable")
	case Consensus:
		resp, err := p.ConsensusBehaviour(reply)
		if err != nil {
			return err
		}
		if p.IsRoot() {
			log.Lvl3("Consensus reach root. Passing to next phase")
			p.ConsensusTree = CreateConsensusTree(p, resp.WeightTree)
			p.Phase = RequestMissingPath
			msg := SaveAnnounce{
				Phase: p.Phase,
				Url:   p.Url,
				Paths: p.ConsensusTree,
			}
			p.HandleAnnounce(StructSaveAnnounce{p.TreeNode(), msg})
		} else {
			log.Lvl3("Sending Consensus to Parent")
			return p.SendTo(p.Parent(), &resp)
		}
	case RequestMissingPath:
		if p.IsRoot() {
			for _, r := range reply {
				for hPath, nodes := range r.SaveReply.MissingPaths {
					// TODO verify that (path == hash) before adding
					p.Paths[hPath] = nodes
				}
			}
			p.MsgToSign <- p.BuildConsensusHtmlPage()
			msg := SaveAnnounce{
				Phase: End,
				Url:   p.Url,
			}
			return p.HandleAnnounce(StructSaveAnnounce{p.TreeNode(), msg})
		} else {
			plainPaths := p.Paths
			for _, r := range reply {
				for hPath, nodes := range r.SaveReply.MissingPaths {
					// TODO verify that (path == hash) before adding
					plainPaths[hPath] = nodes
				}
			}
			resp := SaveReply{
				Phase:        p.Phase,
				Url:          p.Url,
				MissingPaths: plainPaths}
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

func (p *SaveMessage) BuildConsensusHtmlPage() []byte {
	var outputTree *html.Node = nil
	for _, way := range p.Paths {
		// paths were given from leaf to root. we reverse that
		for i, j := 0, len(way)-1; i < j; i, j = i+1, j-1 {
			way[i], way[j] = way[j], way[i]
		}
		for idx, curr := range way {
			isRoot := idx == 0
			if clone, found := GetSimilarChild(outputTree, curr, isRoot); found {
				outputTree = clone
			} else {
				if outputTree == nil {
					KillNodeFamily(curr)
					outputTree = curr
				} else {
					var nextSibFound bool = false
					var currNextSibling *html.Node = nil
					for _, sib := range SiblingFollowing(curr) {
						for _, pchild := range ChildrenOf(outputTree) {
							if AreSimilar(sib, pchild) {
								nextSibFound = true
								currNextSibling = pchild
							}
						}
						if nextSibFound {
							break
						}
					}
					KillNodeFamily(curr)
					outputTree.InsertBefore(curr, currNextSibling)
					outputTree = curr
				}
			}
		}
		outputTree = GetRoot(outputTree)
	}
	var page bytes.Buffer
	err := html.Render(&page, outputTree)
	if err != nil {
		return nil
	}
	return page.Bytes()
}

// GetRoot takes a node of a tree and outputs the root of the associated tree
func GetRoot(node *html.Node) *html.Node {
	var root *html.Node = nil
	for n := node; n != nil; n = n.Parent {
		root = n
	}
	return root
}

// SiblingFollowing take a node and return the list of the siblings of the node
// that appears after it in the list of children of node's parent.
func SiblingFollowing(node *html.Node) []*html.Node {
	var afterSibling []*html.Node = make([]*html.Node, 0)
	for c := node.NextSibling; c != nil; c = c.NextSibling {
		afterSibling = append(afterSibling, c)
	}
	return afterSibling
}

// ChildrenOf output an array with all the child nodes of the node given as input
func ChildrenOf(parent *html.Node) []*html.Node {
	var children []*html.Node = make([]*html.Node, 0)
	for c := parent.FirstChild; c != nil; c = c.NextSibling {
		children = append(children, c)
	}
	return children
}

// GetSimilarChild tests if a child of the parent is similar to the candidate. If yes,
// the child is output. If no, nil is output.
func GetSimilarChild(parent *html.Node, candidate *html.Node, candidateIsRoot bool) (*html.Node, bool) {
	if parent == nil {
		return nil, false
	} else if candidateIsRoot {
		if AreSimilar(parent, candidate) {
			return parent, true
		} else {
			return nil, false
		}
	}
	for _, c := range ChildrenOf(parent) {
		if AreSimilar(c, candidate) {
			return c, true
		}
	}
	return nil, false
}

// AreSimilar define the criterions according to which we can replace a node
// by another in a tree without significant loss of data
func AreSimilar(this *html.Node, that *html.Node) bool {
	if this == nil && that == nil {
		return true
	}
	if this == nil || that == nil {
		return false
	}
	// compare node's attributes
	var sameAttr bool
	for _, a := range this.Attr {
		sameAttr = false
		for _, oa := range that.Attr {
			sameKey := a.Key == oa.Key
			sameVal := a.Val == oa.Val
			sameNam := a.Namespace == oa.Namespace
			if sameKey && sameVal && sameNam {
				sameAttr = true
				break
			}
			if !sameAttr {
				break
			}
		}
	}
	if len(this.Attr) == len(that.Attr) && len(this.Attr) == 0 {
		sameAttr = true
	}
	// compare nodes themself
	sameType := this.Type == that.Type
	sameData := this.Data == that.Data
	sameAtom := this.DataAtom == that.DataAtom
	sameName := this.Namespace == that.Namespace
	var sameContent bool = sameType && sameData && sameAtom && sameName

	return sameAttr && sameContent
}

// KillNodeFamily take a node as input and remove all the links it has with
// its parents and children. Thus making the node an orphan.
func KillNodeFamily(oliverTwist *html.Node) {
	oliverTwist.Parent = nil
	oliverTwist.FirstChild = nil
	oliverTwist.LastChild = nil
	oliverTwist.PrevSibling = nil
	oliverTwist.NextSibling = nil
}

// CreateConsensusTree take a protocol instance and a weighted path tree table
// and output the weighted path table where all the weight are greater than
// the Threshold associated with the protocol instance.
func CreateConsensusTree(p *SaveMessage, origin WeightedPath) WeightedPath {
	var consensusTree WeightedPath = make(WeightedPath)
	for hPath, srvSign := range origin {
		if len(srvSign) >= int(p.Threshold) {
			consensusTree[hPath] = srvSign
		}
	}
	return consensusTree
}

// ConsensusBehaviour define the behaviour to handle for the node in the
// consensus phase. Mainly to differentiate html, css and image media
// consensus protocols.
func (p *SaveMessage) ConsensusBehaviour(reply []StructSaveReply) (StructSaveReply, error) {
	resp := StructSaveReply{
		p.TreeNode(),
		SaveReply{
			Phase:      Consensus,
			Url:        p.Url,
			Errs:       make([]error, 0),
			WeightTree: make(WeightedPath)},
	}
	var url string = p.Url
	for _, r := range reply {
		if url != r.SaveReply.Url {
			urlErr := errors.New("Children do not agree on url")
			resp.Errs = append(resp.Errs, urlErr)
			return resp, urlErr
		}
	}
	var returnErr error = nil

	getResp, _, structURL, err := GetData(p.Url)
	if err != nil {
		resp.SaveReply.Errs = append(resp.SaveReply.Errs, err)
		return resp, err
	}
	getResp.Body.Close()

	switch path.Ext(structURL.Path) {
	case ".htm", ".html":
		tree, treeErr := html.Parse(getResp.Body)
		var myWeightTree WeightedPath
		var cumulatedTree WeightedPath
		var cumulatedErrs []error = make([]error, 0)
		if treeErr != nil {
			myWeightTree = nil
			cumulatedErrs = append(cumulatedErrs, treeErr)
		} else {
			myWeightTree = CreateWeightTree(p, PruneTree(tree))
			p.FullTree = PruneTree(tree)
		}
		cumulatedTree = myWeightTree
		for _, r := range reply {
			cumulatedErrs = append(cumulatedErrs, r.SaveReply.Errs...)
			childrenTree := GetVerifiedTree(r.SaveReply.WeightTree)
			cumulatedTree = cumulatedTree.InsertTree(childrenTree)
		}
		resp.SaveReply.WeightTree = cumulatedTree
	case ".css":
		// TODO tree comparaison (for css)
		returnErr = errors.New("No css protocol implemented")
	default:
		// TODO hash. if == ok, else drop
		returnErr = errors.New("No default protocol implemented")
	}
	return resp, returnErr
}

// InsertTree take the original tree t and add all the fileds of t2 in it.
func (t WeightedPath) InsertTree(t2 WeightedPath) WeightedPath {
	if t == nil || len(t) == 0 {
		if t2 == nil || len(t2) == 0 {
			return make(WeightedPath)
		} else {
			return t2
		}
	}
	if t2 == nil || len(t2) == 0 {
		return t
	}
	var combinedTree WeightedPath = t
	for hPath, srvSign := range t2 {
		if _, ok := combinedTree[hPath]; !ok {
			combinedTree[hPath] = srvSign
		} else {
			for srv, sig := range srvSign {
				combinedTree[hPath][srv] = sig
			}
		}
	}
	return combinedTree
}

// GetVerifiedTree take a WeightedPath tree, verify the signature given for each
// path and output the WeightedPath tree with only the valid signatures
func GetVerifiedTree(tree WeightedPath) WeightedPath {
	var verifiedTree WeightedPath = make(WeightedPath)
	for hPath, srvSign := range tree {
		verifiedTree[hPath] = make(PathSignatures)
		for srv, sig := range srvSign {
			vErr := crypto.VerifySchnorr(network.Suite, srv.Public, []byte(hPath), sig)
			if vErr == nil {
				verifiedTree[hPath][srv] = sig
			}
		}
	}
	return verifiedTree
}

// GetData take a url and return:
// - the http response corresponding to the url
// - the un-alias url corresponding to the response (id est the path to the file on
// the remote server)
// - the url structure associated (see net/url Url struct)
// - an error status
func GetData(url string) (*http.Response, string, *urlpkg.URL, error) {
	getResp, getErr := http.Get(url)
	if getErr != nil {
		return nil, "", nil, getErr
	}

	realUrl := getResp.Request.URL.String()

	urlStruct, urlErr := urlpkg.Parse(getResp.Request.URL.String())
	if urlErr != nil {
		getResp.Body.Close()
		return nil, "", nil, urlErr
	}

	return getResp, realUrl, urlStruct, getErr
}

// PruneTree is used to remove some parts of the tree that the node consider
// irrelevant for the final consensus tree.
func PruneTree(tree *html.Node) *html.Node {
	// remove from tree paths that leads to leaf whose only role is to
	// format html code
	leaves := LeavesDiscovery(tree)
	for _, leaf := range leaves {
		c1 := leaf.Type == html.TextNode
		c2 := len(leaf.Attr) == 0
		c3 := leaf.Data == string([]byte{10, 9})
		if c1 && c2 && c3 {
			// we remove the useless nodes from the leaf to the root
			child := leaf
			for parent := leaf.Parent; parent != nil; parent = parent.Parent {
				parent.RemoveChild(child)
				child = parent
				if parent.FirstChild != nil {
					break
				}
			}
		}
	}
	return tree
}

// CreateWeightTree take the state of the protocol and a tree and output
// the WeightTree for the current node. This means that it take all the possible
// paths of the tree given as input, hash it and sign the given hash.
func CreateWeightTree(p *SaveMessage, tree *html.Node) WeightedPath {
	leaves := LeavesDiscovery(tree)
	weightTree := make(WeightedPath)
	for _, leaf := range leaves {
		var pathHash PathHash
		var pathAssociated []*html.Node = make([]*html.Node, 0)
		for p := leaf; p != nil; p = p.Parent {
			pathHash = updatePathHash(pathHash, p)
			pathAssociated = append(pathAssociated, p)
		}
		p.Paths[pathHash] = pathAssociated
		srv := p.ServerIdentity()
		sigH, sigErr := crypto.SignSchnorr(network.Suite, p.Private(), []byte(pathHash))
		// we add weight to the tree only if we are capable to sign
		if sigErr == nil {
			weightTree[pathHash] = PathSignatures{srv: sigH}
		}
	}
	return weightTree
}

// updatePathHash take a hash representing the children of a node and
// output a hash that represents all the node of a path from a leaf to newNode.
func updatePathHash(childrenHash PathHash, newNode *html.Node) PathHash {
	if newNode == nil {
		return childrenHash
	}
	var attrList []string = make([]string, 0)
	for _, a := range newNode.Attr {
		attrList = append(attrList, a.Namespace+a.Key+a.Val)
	}
	sort.Sort(sort.StringSlice(attrList))
	hashNode := []byte(newNode.Namespace + newNode.Data + strings.Join(attrList, ""))
	if len(childrenHash) == 0 {
		newH, _ := crypto.HashBytes(network.Suite.Hash(), hashNode)
		return PathHash(string(newH))
	} else {
		toHash := append([]byte(childrenHash), hashNode...)
		newH, _ := crypto.HashBytes(network.Suite.Hash(), toHash)
		return PathHash(string(newH))
	}
}

// LeavesDiscovery is an implementation of an iterative DFS algorithm except
// that it does not list all the nodes of the graph but only the leaves.
func LeavesDiscovery(root *html.Node) []*html.Node {
	var stack []*html.Node
	var discovered map[*html.Node]bool = make(map[*html.Node]bool)
	var leaves []*html.Node = make([]*html.Node, 0)
	var curr *html.Node
	stack = append(stack, root)
	for stack != nil {
		l := len(stack)
		if l == 0 {
			curr = nil
			stack = nil
		} else {
			curr = stack[l-1]
			stack = stack[:l-1]
		}
		if !discovered[curr] {
			discovered[curr] = true
			for n := curr.FirstChild; n != nil; n = n.NextSibling {
				stack = append(stack, n)
			}
			if curr.FirstChild == nil {
				leaves = append(leaves, curr)
			}
		}
	}
	return leaves
}

// ExtractPageExternalLinks take html webpage as a buffer and extract the
// links to the additional ressources needed to display the webpage.
func ExtractPageExternalLinks(page *bytes.Buffer) []string {
	log.Lvl4("Parsing parent page")
	var links []string
	tokensPage := html.NewTokenizer(page)
	for tok := tokensPage.Next(); tok != html.ErrorToken; tok = tokensPage.Next() {
		tagName, _ := tokensPage.TagName()
		// extract attribute
		attributeMap := make(map[string]string)
		for moreAttr := true; moreAttr; {
			attrKey, attrValue, isMore := tokensPage.TagAttr()
			moreAttr = isMore
			attributeMap[string(attrKey)] = string(attrValue)
		}
		// check for relevant ressources
		if tok == html.StartTagToken {
			if string(tagName) == "link" && attributeMap["rel"] == "stylesheet" {
				links = append(links, attributeMap["href"])
			}
		} else if tok == html.SelfClosingTagToken {
			if string(tagName) == "img" {
				links = append(links, attributeMap["src"])
			}
		}
	}
	return links
}
