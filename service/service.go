package service

/*
The service.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"encoding/base64"
	urlpkg "net/url"

	decenarch "github.com/dedis/student_18_decenar"
	"github.com/dedis/student_18_decenar/lib"
	"github.com/dedis/student_18_decenar/protocol"
	skip "github.com/dedis/student_18_decenar/skip"
	"golang.org/x/net/html"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/share"

	ftcosiprotocol "gopkg.in/dedis/cothority.v2/ftcosi/protocol"
	ftcosiservice "gopkg.in/dedis/cothority.v2/ftcosi/service"

	"gopkg.in/dedis/kyber.v2/sign/cosi"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

// Used for tests
var serviceID onet.ServiceID

// timeout for protocol termination.
const timeout = 1 * time.Minute

func init() {
	var err error
	serviceID, err = onet.RegisterNewService(decenarch.ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessage(&storage{})
}

// Service is our template-service
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	storage *storage
}

// storageID reflects the data we're storing - we could store more
// than one structure.
var storageID = []byte("main")

type storage struct {
	sync.Mutex
	Threshold     uint32
	Key           kyber.Point // Key assigned by the DKG.
	Secret        *lib.SharedSecret
	LocalHTMLTree *html.Node // HTML tree received by this node
	Partials      map[int][]kyber.Point
}

// Setup is the function called by the service to setup everything is needed
// for DecenArch, in particular this function runs the DKG protocol
func (s *Service) Setup(req *decenarch.SetupRequest) (*decenarch.SetupResponse, error) {
	root := req.Roster.NewRosterWithRoot(s.ServerIdentity())
	tree := root.GenerateNaryTree(len(req.Roster.List))
	if tree == nil {
		return nil, errors.New("error while creating the tree")
	}

	// compute and store threshold. This threshold will be used also by the
	// other conodes of the roster
	s.storage.Lock()
	s.storage.Threshold = uint32(len(req.Roster.List) - (len(req.Roster.List)-1)/3)
	s.storage.Unlock()
	s.save()

	// run DKG protocol
	instance, err := s.CreateProtocol(protocol.NameDKG, tree)
	if err != nil {
		return nil, err
	}
	protocol := instance.(*protocol.SetupDKG)
	protocol.Threshold = s.threshold()

	err = protocol.Start()
	if err != nil {
		return nil, err
	}

	select {
	case <-protocol.Finished:
		secret, err := protocol.SharedSecret()
		if err != nil {
			return nil, err
		}
		s.storage.Lock()
		s.storage.Key = secret.X
		s.storage.Secret = secret
		s.storage.Unlock()
		s.save()
		return &decenarch.SetupResponse{Key: secret.X}, nil
	case <-time.After(timeout):
		return nil, errors.New("open error, protocol timeout")
	}
}

// Save is the function called by the service when a client want to save a website in the
// archive.
func (s *Service) SaveWebpage(req *decenarch.SaveRequest) (*decenarch.SaveResponse, error) {
	stattimes := make([]string, 0)
	log.Lvl3("Decenarch Service new SaveWebpage")

	// create the tree
	numNodes := len(req.Roster.List)
	root := req.Roster.NewRosterWithRoot(s.ServerIdentity())
	tree := root.GenerateNaryTree(numNodes)
	if tree == nil {
		return nil, fmt.Errorf("%v couldn't create tree", decenarch.ErrorParse)
	}

	// run consensus protocol
	instance, err := s.CreateProtocol(protocol.NameConsensusStructured, tree)
	if err != nil {
		return nil, err
	}
	structuredConsensusProtocol := instance.(*protocol.ConsensusStructuredState)
	structuredConsensusProtocol.SharedKey = s.key()
	structuredConsensusProtocol.Url = req.Url
	err = structuredConsensusProtocol.Start()
	if err != nil {
		return nil, err
	}
	log.Lvl4("Waiting for structuredConsensusProtocol data...")
	var webmain decenarch.Webstore
	var mainTimestamp string
	select {
	case <-structuredConsensusProtocol.Finished:
		// only if the consensus protocol terminates succesfully it
		// makes sense to store the webpage, otherwise an error should
		// be returned

		// get HTML tree to reconstruct the HTML page after consensus.
		// Note that only root has access to this, so no need to
		// (un)lock here
		s.storage.LocalHTMLTree = structuredConsensusProtocol.LocalTree

		// run decryt protocol
		partials, err := s.decrypt(tree, structuredConsensusProtocol.EncryptedCBFSet)
		if err != nil {
			return nil, err
		}

		// reconstruct html page
		msgToSign, err := s.reconstruct(partials, s.localHTMLTree(), structuredConsensusProtocol.ParametersCBF)
		if err != nil {
			return nil, err
		}

		// sign the consensus website found
		sig, sigErr := s.sign(tree, msgToSign)
		if sigErr != nil {
			return nil, sigErr
		}

		// create storing structure
		mainTimestamp = time.Now().Format("2006/01/02 15:04")
		webmain = decenarch.Webstore{
			Url:         structuredConsensusProtocol.Url,
			ContentType: structuredConsensusProtocol.ContentType,
			Sig:         sig,
			Page:        base64.StdEncoding.EncodeToString(msgToSign),
			AddsUrl:     make([]string, 0),
			Timestamp:   mainTimestamp,
		}
	case <-time.After(timeout):
		return nil, errors.New("structuredConsensusProtocol timeout")
	}

	log.Lvl4("Create stored request")

	//  run consensus protocol for all additional ressources
	var webadds []decenarch.Webstore = make([]decenarch.Webstore, 0)
	bytePage, err := base64.StdEncoding.DecodeString(webmain.Page)
	if err != nil {
		return nil, err
	}
	stattimes = append(stattimes, "sameForAddStart;"+time.Now().Format(decenarch.StatTimeFormat))
	addsLinks := ExtractPageExternalLinks(webmain.Url, bytes.NewBuffer(bytePage))

	// iterate over additional links and retrieve the content
	for _, al := range addsLinks {
		log.Lvl4("Get additional", al)
		api, err := s.CreateProtocol(protocol.NameConsensusUnstructured, tree)
		if err != nil {
			return nil, err
		}
		unstructuredConsensusProtocol := api.(*protocol.ConsensusUnstructuredState)
		unstructuredConsensusProtocol.Url = al
		unstructuredConsensusProtocol.Threshold = s.threshold()
		err = api.Start()
		if err != nil {
			return nil, err
		}
		select {
		case <-unstructuredConsensusProtocol.Finished:
			ru := unstructuredConsensusProtocol.Url
			ct := unstructuredConsensusProtocol.ContentType
			mts := unstructuredConsensusProtocol.MsgToSign

			// sign the consensus additional data
			as, err := s.sign(tree, mts)
			if err != nil {
				return nil, err
			}

			// create storing structure
			aweb := decenarch.Webstore{
				Url:         ru,
				ContentType: ct,
				Sig:         as,
				Page:        base64.StdEncoding.EncodeToString(mts),
				AddsUrl:     make([]string, 0),
				Timestamp:   mainTimestamp,
			}
			webadds = append(webadds, aweb)
			webmain.AddsUrl = append(webmain.AddsUrl, al)
		case <-time.After(timeout):
			return nil, errors.New("unstructuredConsensusProtocol timeout")

		}
	}

	// add additional data to the slice of storing structures
	webadds = append(webadds, webmain)

	// send data to the blockchain
	log.Lvl4("sending", webadds, "to skipchain")
	skipclient := skip.NewSkipClient()
	skipclient.SkipAddData(req.Roster, webadds)
	return &decenarch.SaveResponse{Times: stattimes}, nil
}

func (s *Service) decrypt(t *onet.Tree, encryptedCBFSet *lib.CipherVector) (map[int][]kyber.Point, error) {
	pi, err := s.CreateProtocol(protocol.NameDecrypt, t)
	if err != nil {
		return nil, err
	}
	p := pi.(*protocol.Decrypt)
	pi.(*protocol.Decrypt).EncryptedCBFSet = encryptedCBFSet
	pi.(*protocol.Decrypt).Secret = s.secret()
	pi.(*protocol.Decrypt).Threshold = s.threshold()
	if err := p.Start(); err != nil {
		return nil, err
	}
	select {
	case <-p.Finished:
		return p.Partials, nil
	case <-time.After(timeout):
		return nil, errors.New("decrypt error, protocol timeout")
	}
}

func (s *Service) reconstruct(partials map[int][]kyber.Point, localTree *html.Node, paramCBF []uint) ([]byte, error) {
	points := make([]kyber.Point, 0)
	n := 3
	for i := 0; i < len(partials[0]); i++ {
		shares := make([]*share.PubShare, n)
		for j, partial := range partials {
			shares[j] = &share.PubShare{I: j, V: partial[i]}
		}
		message, _ := share.RecoverCommit(decenarch.Suite, shares, n, n)
		points = append(points, message)
	}

	// reconstruct the points using by computing the dlog
	reconstructed := make([]int64, 0)
	for _, point := range points {
		reconstructed = append(reconstructed, lib.GetPointToInt(point))
	}

	// build the consensus HTML page using the reconstructed Bloom filter
	consensusCBF := lib.BloomFilterFromSet(reconstructed, paramCBF)
	htmlPage, err := s.buildConsensusHtmlPage(localTree, consensusCBF)
	if err != nil {
		return nil, err
	}

	return htmlPage, nil
}

// BuildConsensusHtmlPage takes the p.LocalTree of the root made of HTML nodes
// and returns the consensus HTML page coming from the consensus HTML tree.
// Only the leaves that appears in the combined Bloom filter more than
// threshold times are included in the HTML page. All the other nodes are
// included by the root.  The output is a valid HTML page there, it creates a
// valid html page and outputs it.
func (s *Service) buildConsensusHtmlPage(localTree *html.Node, CBF *lib.CBF) ([]byte, error) {
	log.Lvl4("Begin building consensus html page")

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.FirstChild == nil { // it is a leaf
			if CBF.Count([]byte(n.Data)) < int64(s.threshold()) {
				n.Parent.RemoveChild(n)
			}

		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(localTree)

	// convert *html.Nodes tree to an html page
	var page bytes.Buffer
	err := html.Render(&page, localTree)
	if err != nil {
		return nil, err
	}

	return page.Bytes(), nil
}

func (s *Service) sign(t *onet.Tree, msgToSign []byte) (*ftcosiservice.SignatureResponse, error) {
	// protocol instance
	pi, err := s.CreateProtocol(protocol.NameSign, t)

	// configure the protocol
	p := pi.(*ftcosiprotocol.FtCosi)
	p.CreateProtocol = s.CreateProtocol
	p.Msg = msgToSign
	// We set NSubtrees to the cube root of n to evenly distribute the load,
	// i.e. depth (=3) = log_f n, where f is the fan-out (branching factor).
	p.NSubtrees = int(math.Pow(float64(t.Size()), 1.0/3.0))
	if p.NSubtrees < 1 {
		p.NSubtrees = 1
	}
	// Timeout is not a global timeout for the protocol, but a timeout used
	// for waiting for responses for sub protocols.
	p.Timeout = time.Second * 5

	// start the protocol
	log.Lvl3("Cosi Service starting up root protocol")
	if err = pi.Start(); err != nil {
		return nil, err
	}

	// wait for reply
	var sig []byte
	select {
	case sig = <-p.FinalSignature:
	case <-time.After(p.Timeout*5 + time.Second):
		fmt.Println("Timeout")
		return nil, errors.New("protocol timed out")
	}

	//The hash is the message ftcosi actually signs, we recompute it the
	//same way as ftcosi and then return it.
	h := decenarch.Suite.Hash()
	h.Write(msgToSign)
	return &ftcosiservice.SignatureResponse{Hash: h.Sum(nil), Signature: sig}, nil
}

// Retrieve returns the webpage retrieved from the skipchain
func (s *Service) Retrieve(req *decenarch.RetrieveRequest) (*decenarch.RetrieveResponse, error) {
	log.Lvl3("Decenarch Service new RetrieveRequest:", req)
	returnResp := decenarch.RetrieveResponse{}
	returnResp.Adds = make([]decenarch.Webstore, 0)
	skipclient := skip.NewSkipClient()
	resp, err := skipclient.SkipGetData(req.Roster, req.Url, req.Timestamp)
	if err != nil {
		return nil, err
	}
	log.Lvl4("service-RetrieveRequest-skipchain response")
	log.Lvl4("the response:", resp, "and the error", err)
	returnResp.Main = resp.MainPage
	mainPage := resp.MainPage.Page
	bPage, bErr := base64.StdEncoding.DecodeString(mainPage)
	if bErr != nil {
		return nil, bErr
	}
	log.Lvl4("service-RetrieveRequest-verify signature")
	vsigErr := cosi.Verify(
		ftcosiprotocol.EdDSACompatibleCosiSuite,
		req.Roster.Publics(),
		bPage,
		resp.MainPage.Sig.Signature,
		cosi.CompletePolicy{})
	if vsigErr != nil {
		log.Lvl1(vsigErr)
		return nil, vsigErr
	}
	for _, addUrl := range resp.MainPage.AddsUrl {
		for _, addPage := range resp.AllPages {
			if addUrl == addPage.Url {
				baPage, baErr := base64.StdEncoding.DecodeString(addPage.Page)
				if baErr == nil {
					sErr := cosi.Verify(
						ftcosiprotocol.EdDSACompatibleCosiSuite,
						req.Roster.Publics(),
						baPage,
						addPage.Sig.Signature,
						cosi.CompletePolicy{})
					if sErr == nil {
						returnResp.Adds = append(returnResp.Adds, addPage)
					} else {
						log.Lvl1("A non-fatal error occured:", sErr)
					}
				} else {
					log.Lvl1("A non-fatal error occured:", baErr)
				}
			}
		}
	}
	return &returnResp, nil
}

// NewProtocol is called on all nodes of a Tree (except the root, since it is
// the one starting the protocol) so it's the Service that will be called to
// generate the PI on all others node.
// If you use CreateProtocolOnet, this will not be called, as the Onet will
// instantiate the protocol on its own. If you need more control at the
// instantiation of the protocol, use CreateProtocolService, and you can
// give some extra-configuration to your protocol in here.
func (s *Service) NewProtocol(node *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("Decenarch Service new protocol event")
	switch node.ProtocolName() {
	case protocol.NameDKG:
		pi, err := protocol.NewSetupDKG(node)
		if err != nil {
			return nil, err
		}
		protocol := pi.(*protocol.SetupDKG)
		go func() {
			<-protocol.Finished
			secret, err := protocol.SharedSecret()
			if err != nil {
				log.Error(err)
				return
			}
			s.storage.Lock()
			s.storage.Key = secret.X
			s.storage.Secret = secret
			s.storage.Threshold = protocol.Threshold // define by the root and valid for all the conodes
			s.storage.Unlock()
			s.save()
		}()
		return protocol, nil
	case protocol.NameConsensusStructured:
		instance, err := protocol.NewConsensusStructuredProtocol(node)
		if err != nil {
			return nil, err
		}
		protocol := instance.(*protocol.ConsensusStructuredState)
		protocol.SharedKey = s.key()
		return protocol, nil
	case protocol.NameConsensusUnstructured:
		instance, err := protocol.NewConsensusUnstructuredProtocol(node)
		if err != nil {
			return nil, err
		}
		protocol := instance.(*protocol.ConsensusUnstructuredState)
		return protocol, nil
	case protocol.NameDecrypt:
		instance, err := protocol.NewDecrypt(node)
		if err != nil {
			return nil, err
		}
		protocol := instance.(*protocol.Decrypt)
		protocol.Secret = s.secret()
		protocol.Threshold = s.threshold()
		return protocol, nil
	case protocol.NameSign:
		protocol, err := protocol.NewSignProtocol(node)
		if err != nil {
			return nil, err
		}
		return protocol, nil
	case protocol.NameSubSign:
		protocol, err := protocol.NewSubSignProtocol(node)
		if err != nil {
			return nil, err
		}
		return protocol, nil
	case protocol.SaveName:
		instance, err := protocol.NewSaveProtocol(node)
		if err != nil {
			return nil, err
		}
		protocol := instance.(*protocol.SaveLocalState)
		protocol.SharedKey = s.key()
		return protocol, nil
	default:
		return nil, errors.New("protocol error, unknown protocol")
	}
}

// LocalHTMLTree
func (s *Service) localHTMLTree() *html.Node {
	s.storage.Lock()
	defer s.storage.Unlock()
	return s.storage.LocalHTMLTree
}

// threshold
func (s *Service) threshold() uint32 {
	s.storage.Lock()
	defer s.storage.Unlock()
	return s.storage.Threshold
}

// secret returns the shared secret for a given election.
func (s *Service) secret() *lib.SharedSecret {
	s.storage.Lock()
	defer s.storage.Unlock()
	return s.storage.Secret
}

// key returns the key given by DKG
func (s *Service) key() kyber.Point {
	s.storage.Lock()
	defer s.storage.Unlock()
	return s.storage.Key
}

// saves all skipblocks.
func (s *Service) save() {
	log.Lvl3(s.String(), "Saving Service")
	s.storage.Lock()
	defer s.storage.Unlock()
	err := s.Save(storageID, s.storage)
	if err != nil {
		log.Error("Couldn't save file:", err)
	}
}

// Tries to load the configuration and updates the data in the service
// if it finds a valid config-file.
func (s *Service) tryLoad() error {
	s.storage.Lock()
	defer s.storage.Unlock()

	msg, err := s.Load(storageID)
	if err != nil {
		return err
	}
	if msg == nil {
		return nil
	}
	var ok bool
	s.storage, ok = msg.(*storage)
	if !ok {
		return errors.New("Data of wrong type")
	}
	return nil
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments.
func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		storage:          &storage{Partials: make(map[int][]kyber.Point)},
	}
	if err := s.RegisterHandlers(s.Setup, s.SaveWebpage, s.Retrieve); err != nil {
		log.Error(err, "Couldn't register messages")
		return nil, err
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, err
	}
	return s, nil
}

// ExtractPageExternalLinks take html webpage as a buffer and extract the
// links to the additional ressources needed to display the webpage.
// "Additional ressources" means :
//    - css file
//    - images
func ExtractPageExternalLinks(pageUrl string, page *bytes.Buffer) []string {
	log.Lvl4("Parsing parent page")
	var links []string
	// parse page to extract links
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
		// check for relevant ressources, i.e. CSS file and/or images
		if tok == html.StartTagToken || tok == html.SelfClosingTagToken {
			if string(tagName) == "link" && attributeMap["rel"] == "stylesheet" {
				links = append(links, attributeMap["href"])
			} else if string(tagName) == "img" {
				links = append(links, attributeMap["src"])
			}
		}
	}
	// turns found links into web-requestable links
	var requestLinks []string = make([]string, 0)
	urlStruct, urlErr := urlpkg.Parse(pageUrl)
	if urlErr != nil {
		return make([]string, 0)
	}
	for _, link := range links {
		urlS, urlE := urlpkg.Parse(link)
		if urlE == nil {
			if urlS.IsAbs() {
				requestLinks = append(requestLinks, link)
			} else {
				reqLink, reqErr := urlStruct.Parse(link)
				if reqErr == nil {
					requestLinks = append(requestLinks, reqLink.String())
				}
			}
		}
	}
	return requestLinks
}
