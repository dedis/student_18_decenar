package protocol

import (
	"encoding/base64"
	"errors"
	"io/ioutil"
	"net/http"
	urlpkg "net/url"

	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/sign/schnorr"

	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

func init() {
	network.RegisterMessage(SaveAnnounceUnstructured{})
	network.RegisterMessage(SaveReplyUnstructured{})
	onet.GlobalProtocolRegister(NameConsensusUnstructured, NewConsensusUnstructuredProtocol)
}

// ConsensusUnstructuredState holds the local state of a node when it runs the SaveProtocol
type ConsensusUnstructuredState struct {
	*onet.TreeNodeInstance
	Phase       SavePhase
	Errs        []error
	Url         string
	ContentType string
	Threshold   uint32

	MasterHash map[string]map[kyber.Point][]byte

	PlainData map[string][]byte

	MsgToSign []byte

	Finished chan bool
}

// NewSaveProtocol initialises the structure for use in one round
func NewConsensusUnstructuredProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("Creating NewSaveProtocol")
	t := &ConsensusUnstructuredState{
		TreeNodeInstance: n,
		Url:              "",
		Phase:            NilPhase,
		PlainData:        make(map[string][]byte),
		Finished:         make(chan bool),
	}
	for _, handler := range []interface{}{t.HandleAnnounceUnstructured, t.HandleReplyUnstructured} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}
	return t, nil
}

func (p *ConsensusUnstructuredState) Start() error {
	log.Lvl3("Starting ConsensusUnstructuredState")
	p.Phase = Consensus
	hash, err := p.GetLocalDataUnstructured()
	if err != nil {
		log.Error("Error in save protocol Start():", err)
		return err
	}
	p.MasterHash = hash
	return p.HandleAnnounceUnstructured(StructSaveAnnounceUnstructured{
		p.TreeNode(),
		SaveAnnounceUnstructured{
			Url:        p.Url,
			Phase:      Consensus,
			MasterHash: p.MasterHash,
		},
	})
}

// HandleAnnounceUnstructured is the message going down the tree
//
// Note: this function must be read as multiple functions with a common
// begining and end but each time a different 'case'. Each one can be
// considered as an independant function.
func (p *ConsensusUnstructuredState) HandleAnnounceUnstructured(msg StructSaveAnnounceUnstructured) error {
	log.Lvl4("Handling", p)
	log.Lvl4("And the message", msg)
	p.Phase = msg.SaveAnnounceUnstructured.Phase
	p.Url = msg.SaveAnnounceUnstructured.Url
	switch msg.SaveAnnounceUnstructured.Phase {
	case NilPhase:
		log.Lvl1("NilPhase passed by", p, "msg:", msg)
		err := errors.New("NilPhase should not be announceable")
		resp := StructSaveReplyUnstructured{
			p.TreeNode(),
			SaveReplyUnstructured{
				Phase: msg.SaveAnnounceUnstructured.Phase,
				Url:   msg.SaveAnnounceUnstructured.Url,
				Errs:  []error{err},
			},
		}
		defer p.HandleReplyUnstructured([]StructSaveReplyUnstructured{resp})
		return err
	case Consensus:
		log.Lvl4("Consensus Phase")
		p.MasterHash = msg.SaveAnnounceUnstructured.MasterHash
		if !p.IsLeaf() {
			return p.SendToChildren(&msg.SaveAnnounceUnstructured)
		} else {
			resp := StructSaveReplyUnstructured{
				p.TreeNode(),
				SaveReplyUnstructured{
					Phase:      msg.SaveAnnounceUnstructured.Phase,
					Url:        msg.SaveAnnounceUnstructured.Url,
					MasterHash: msg.SaveAnnounceUnstructured.MasterHash,
					Errs:       p.Errs},
			}
			return p.HandleReplyUnstructured([]StructSaveReplyUnstructured{resp})
		}
	case RequestMissingData:
		log.Lvl4("RequestMissingData Phase with", p)
		p.MasterHash = msg.SaveAnnounceUnstructured.MasterHash
		requestedHash := getRequestedMissingHashUnstructured(p)
		if _, ok := p.PlainData[requestedHash]; !ok {
			if !p.IsLeaf() {
				return p.SendToChildren(msg)
			}
		}
		// arriving here means either that:
		// * node has requested plaintext data
		// * node is a leaf so it has no more children to ask for data
		// * node refused to reveal plaintext data because of invalid signatures
		resp := StructSaveReplyUnstructured{
			p.TreeNode(),
			SaveReplyUnstructured{
				Phase:      p.Phase,
				Url:        p.Url,
				MasterHash: p.MasterHash,
				Errs:       p.Errs},
		}
		return p.HandleReplyUnstructured([]StructSaveReplyUnstructured{resp})
	case End:
		log.Lvl4("End Phase")
		p.SendToChildren(&msg.SaveAnnounceUnstructured)
	default:
		log.Lvl1("Unknown phase passed by", p, "msg:", msg)
		err := errors.New("Unknown Phase")
		resp := StructSaveReplyUnstructured{
			p.TreeNode(),
			SaveReplyUnstructured{
				Phase: msg.SaveAnnounceUnstructured.Phase,
				Url:   msg.SaveAnnounceUnstructured.Url,
				Errs:  []error{err}},
		}
		defer p.HandleReplyUnstructured([]StructSaveReplyUnstructured{resp})
		return err
	}
	return nil
}

// HandleReplyUnstructured is the message going up the tree
//
// Note: this function must be read as multiple functions with a common
// begining and end but each time a different 'case'. Each one can be
// considered as an independant function.
func (p *ConsensusUnstructuredState) HandleReplyUnstructured(reply []StructSaveReplyUnstructured) error {
	log.Lvl4("Handling Save Reply", p)
	log.Lvl4("And the replies", reply)
	switch p.Phase {
	case NilPhase:
		log.Lvl1("NilPhase passed by", p)
		defer p.Done()
		return errors.New("NilPhase should not be replyable")
	case Consensus:
		log.Lvl4("Consensus Reply Phase")
		locHash, err := p.GetLocalDataUnstructured()
		if err != nil {
			log.Lvl1("Error! Impossible to get local data", err)
			p.Errs = append(p.Errs, err)
		}
		p.AggregateUnstructDataUnstructured(locHash, reply)
		if p.IsRoot() {
			log.Lvl4("Consensus reach root. Passing to next phase")
			msMap, msErr := getMostSignedHashUnstructured(p, p.MasterHash)
			if msErr != nil {
				p.Errs = append(p.Errs, msErr)
			}
			p.MasterHash = msMap

			// pass to next phase, RequestMissingData
			p.Phase = RequestMissingData
			msg := SaveAnnounceUnstructured{
				Phase:      p.Phase,
				Url:        p.Url,
				MasterHash: p.MasterHash,
			}
			p.HandleAnnounceUnstructured(StructSaveAnnounceUnstructured{p.TreeNode(), msg})
		} else {
			log.Lvl4("Sending Consensus to Parent")
			resp := SaveReplyUnstructured{
				Phase: p.Phase,
				Url:   p.Url,

				MasterHash: p.MasterHash,

				Errs: p.Errs,
			}
			return p.SendToParent(&resp)
		}
	case RequestMissingData:
		log.Lvl4("RequestMissingData Reply Phase")
		p.AggregateErrorsUnstructured(reply)
		var requestedHash string
		if p.MasterHash != nil && len(p.MasterHash) > 0 {
			requestedHash = getRequestedMissingHashUnstructured(p)
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
			// communicate end of the protocol to children and to service
			p.MsgToSign = p.PlainData[requestedHash]

			// announce the end of the process to other conodes
			msg := SaveAnnounceUnstructured{Phase: End, Url: p.Url}
			return p.HandleAnnounceUnstructured(StructSaveAnnounceUnstructured{p.TreeNode(), msg})
		} else {
			requestedDataMap := make(map[string][]byte)
			requestedDataMap[requestedHash] = p.PlainData[requestedHash]
			resp := SaveReplyUnstructured{
				Phase:         p.Phase,
				Url:           p.Url,
				Errs:          p.Errs,
				MasterHash:    p.MasterHash,
				RequestedData: requestedDataMap}
			return p.SendToParent(&resp)
		}
	case End:
		// PHASE END
		log.Lvl4("End Reply Phase")
		log.Lvl1("Node is done")
		defer p.Done()
		if !p.IsRoot() {
			resp := SaveReplyUnstructured{Phase: End, Url: p.Url}
			return p.SendToParent(&resp)
		}

		p.Finished <- true
		return nil
	default:
		log.Lvl1("Unknown phase passed by", p)
		defer p.Done()
		return errors.New("Unknown Phase")

	}
	defer p.Done()
	return nil
}

// GetLocalData retrieve the data from the p.Url and handle it to make it
// either a *html.Node tree or a signed hash.  If the returned *html.Node tree is
// not nil, then the map is. Else, it is the other way around.  If both
// returned value are nil, then an error occured.
func (p *ConsensusUnstructuredState) GetLocalDataUnstructured() (map[string]map[kyber.Point][]byte, error) {
	// get data
	resp, realUrl, _, err := getRemoteDataUnstructured(p.Url)
	if err != nil {
		log.Lvl1("Error! Impossible to retrieve remote data.")
		return nil, err
	}
	p.Url = realUrl
	defer resp.Body.Close()
	// procedure for all other files (consensus on whole hash)
	rawData, readErr := ioutil.ReadAll(resp.Body)
	if readErr != nil {
		log.Lvl1("Error: Impossible to read http request body!")
		return nil, readErr
	}
	hashedData := p.Suite().(kyber.HashFactory).Hash().Sum(rawData)
	locHashKey := base64.StdEncoding.EncodeToString(hashedData)
	sig, sigErr := schnorr.Sign(p.Suite(), p.Private(), []byte(locHashKey))
	if sigErr != nil {
		log.Lvl1("Error: Impossible to sign data!")
		return nil, sigErr
	}
	localHash := make(map[string]map[kyber.Point][]byte)
	localHash[locHashKey] = make(map[kyber.Point][]byte)
	localHash[locHashKey][p.Public()] = sig
	// save plaintext data locally
	p.PlainData[locHashKey] = rawData

	return localHash, nil
}

// getRemoteData take a url and return: - the http response corresponding to
// the url - the un-alias url corresponding to the response (id est the path to
// the file on the remote server) - the url structure associated (see net/url
// Url struct) - an error status
func getRemoteDataUnstructured(url string) (*http.Response, string, *urlpkg.URL, error) {
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

// AggregateErrors put all the errors contained in the children reply inside
// the ConsensusUnstructuredState p field p.Errs. It allows the current protocol to
// transmit the errors from its children to its parent.
func (p *ConsensusUnstructuredState) AggregateErrorsUnstructured(reply []StructSaveReplyUnstructured) {
	for _, r := range reply {
		p.Errs = append(p.Errs, r.Errs...)
	}
}

// AggregateUnstructData take locHash, the hash of the data signed by the
// current node and reply the replies of the node's children. It verifies and
// signs the p.MasterHash with the signatures of both the nodes and its
// chidren.
func (p *ConsensusUnstructuredState) AggregateUnstructDataUnstructured(locHash map[string]map[kyber.Point][]byte, reply []StructSaveReplyUnstructured) {
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
			for img, sigmap := range r.SaveReplyUnstructured.MasterHash {
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

// getMostSignedHash returns a new map containing only the entry of the map
// where the number of signature is the highest.  If hashmap is nil, it returns
// nil.  If no entry are under p.Threshold, it returns a non-nil error.
//
// Warning: the signatures verification must be done BEFORE using this
// function.  No signatures verification are done here.
func getMostSignedHashUnstructured(p *ConsensusUnstructuredState, hashmap map[string]map[kyber.Point][]byte) (map[string]map[kyber.Point][]byte, error) {
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
// phase. It outputs the hash of the data requested by the root.  A hash is
// produced only if the number of verified signature is higher than the node
// threshold.
func getRequestedMissingHashUnstructured(p *ConsensusUnstructuredState) string {
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
