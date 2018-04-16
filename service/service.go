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
	"strconv"
	"sync"
	"time"

	"encoding/base64"
	urlpkg "net/url"

	"github.com/dedis/student_18_decenar"
	"github.com/dedis/student_18_decenar/lib"
	"github.com/dedis/student_18_decenar/protocol"
	"golang.org/x/net/html"
	"gopkg.in/dedis/cothority.v2"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/share"

	cosiservice "gopkg.in/dedis/cothority.v2/ftcosi/service"

	"gopkg.in/dedis/kyber.v2/sign/cosi"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

// Used for tests
var serviceID onet.ServiceID

// timeout for protocol termination.
const timeout = 60 * time.Minute

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
	Key      kyber.Point // Key assigned by the DKG.
	Secret   *lib.SharedSecret
	Partials map[int][]kyber.Point
}

// Setup is the function called by the service to setup everything is needed
// for DecenArch, in particular this function runs the DKG protocol
func (s *Service) Setup(req *decenarch.SetupRequest) (*decenarch.SetupResponse, error) {
	root := req.Roster.NewRosterWithRoot(s.ServerIdentity())
	tree := root.GenerateNaryTree(len(req.Roster.List))
	if tree == nil {
		return nil, errors.New("error while creating the tree")
	}

	instance, _ := s.CreateProtocol(protocol.NameDKG, tree)
	protocol := instance.(*protocol.SetupDKG)

	err := protocol.Start()
	if err != nil {
		return nil, err
	}

	select {
	case <-protocol.Done:
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
	stattimes = append(stattimes, "saveReqStart;"+time.Now().Format(decenarch.StatTimeFormat))
	log.Lvl3("Decenarch Service new SaveWebpage")

	// create the tree
	numNodes := len(req.Roster.List)
	root := req.Roster.NewRosterWithRoot(s.ServerIdentity())
	tree := root.GenerateNaryTree(numNodes)
	if tree == nil {
		return nil, fmt.Errorf("%v couldn't create tree", decenarch.ErrorParse)
	}

	// run consensus protocol
	threshold := int32(math.Ceil(float64(numNodes) * 0.8))
	pi, err := s.CreateProtocol(protocol.SaveName, tree)
	if err != nil {
		return nil, err
	}
	pi.(*protocol.SaveLocalState).SharedKey = s.key()
	pi.(*protocol.SaveLocalState).Url = req.Url
	pi.(*protocol.SaveLocalState).Threshold = threshold
	stattimes = append(stattimes, "saveProtoStart;"+time.Now().Format(decenarch.StatTimeFormat))
	go pi.Start()
	// get result of consensus
	log.Lvl4("Waiting for protocol data...")
	var parametersCBF []uint = <-pi.(*protocol.SaveLocalState).ParametersCBFChan
	//var uniqueLeaves string = <-pi.(*protocol.SaveLocalState).StringChan
	// TODO: change again
	var uniqueLeaves string = "0"
	var realUrl string = <-pi.(*protocol.SaveLocalState).StringChan
	var contentType string = <-pi.(*protocol.SaveLocalState).StringChan
	var msgToSign []byte = <-pi.(*protocol.SaveLocalState).MsgToSign
	stattimes = append(stattimes, "saveCosiStart;"+time.Now().Format(decenarch.StatTimeFormat))
	// sign the consensus website found
	cosiclient := cosiservice.NewClient()
	sig, sigErr := cosiclient.SignatureRequest(req.Roster, msgToSign)
	if sigErr != nil {
		return nil, sigErr
	}
	stattimes = append(stattimes, "saveCreaStructStart;"+time.Now().Format(decenarch.StatTimeFormat))
	mainTimestamp := time.Now().Format("2006/01/02 15:04")
	webmain := decenarch.Webstore{
		Url:         realUrl,
		ContentType: contentType,
		Sig:         sig,
		Page:        base64.StdEncoding.EncodeToString(msgToSign),
		AddsUrl:     make([]string, 0),
		Timestamp:   mainTimestamp,
	}
	proof := &decenarch.GeneralProof{
		Url:       realUrl,
		CoSig:     sig,
		Timestamp: mainTimestamp,
	}
	var consensusCBF *lib.CipherVector = <-pi.(*protocol.SaveLocalState).ConsensusCBF
	log.Lvl4("Create stored request")

	//  run consensus protocol for all additional ressources
	var webadds []decenarch.Webstore = make([]decenarch.Webstore, 0)
	bytePage, byteErr := base64.StdEncoding.DecodeString(webmain.Page)
	stattimes = append(stattimes, "sameForAddStart;"+time.Now().Format(decenarch.StatTimeFormat))
	addsLinks := make([]string, 0)
	if byteErr == nil {
		addsLinks = ExtractPageExternalLinks(webmain.Url, bytes.NewBuffer(bytePage))
	}
	for _, al := range addsLinks {
		log.Lvl4("Get additional", al)
		api, aerr := s.CreateProtocol(protocol.SaveName, tree)
		if aerr == nil {
			api.(*protocol.SaveLocalState).Url = al
			api.(*protocol.SaveLocalState).Threshold = threshold
			go api.Start()
			ru := <-api.(*protocol.SaveLocalState).StringChan
			ct := <-api.(*protocol.SaveLocalState).StringChan
			mts := <-api.(*protocol.SaveLocalState).MsgToSign
			as, asE := cosiclient.SignatureRequest(req.Roster, mts)
			if asE == nil {
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
			}
		}
	}
	webadds = append(webadds, webmain)

	// run decrypt protocol
	instanceDecrypt, _ := s.CreateProtocol(protocol.NameDecrypt, tree)
	protocolDecrypt := instanceDecrypt.(*protocol.Decrypt)
	instanceDecrypt.(*protocol.Decrypt).EncryptedCBFSet = consensusCBF
	instanceDecrypt.(*protocol.Decrypt).Secret = s.secret()
	if err := protocolDecrypt.Start(); err != nil {
		return nil, err
	}
	select {
	case <-protocolDecrypt.Finished:
	case <-time.After(timeout):
		return nil, errors.New("decrypt error, protocol timeout")
	}

	partials := protocolDecrypt.Partials
	s.Reconstruct(partials)

	log.Lvl4("sending", webadds, "to skipchain")
	skipclient := decenarch.NewSkipClient()
	stattimes = append(stattimes, "skipAddStart;"+time.Now().Format(decenarch.StatTimeFormat))
	skipclient.SkipAddData(req.Roster, webadds)
	stattimes = append(stattimes, "saveReqEnd;"+time.Now().Format(decenarch.StatTimeFormat))
	sInt := strconv.Itoa(numNodes)
	stattimes = append(stattimes, "numbrNodes;"+sInt)
	stattimes = append(stattimes, "uniqueLeaves;"+uniqueLeaves)
	stattimes = append(stattimes, "mCBF;"+strconv.Itoa(int(parametersCBF[0])))
	stattimes = append(stattimes, "kCBF;"+strconv.Itoa(int(parametersCBF[1])))
	resp := &decenarch.SaveResponse{Times: stattimes, Proof: proof}
	return resp, nil
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

func (s *Service) Reconstruct(partials map[int][]kyber.Point) {
	points := make([]kyber.Point, 0)
	n := 3
	for i := 0; i < len(partials[0]); i++ {
		shares := make([]*share.PubShare, n)
		for j, partial := range partials {
			shares[j] = &share.PubShare{I: j, V: partial[i]}
		}
		message, _ := share.RecoverCommit(cothority.Suite, shares, n, n)
		points = append(points, message)
	}
	reconstructed := make([]int64, 0)
	for _, point := range points {
		reconstructed = append(reconstructed, lib.GetPointToInt(point))
	}
	fmt.Println("I'm there")
	fmt.Printf("Reconstructed %#v\n", reconstructed)
}

// RetrieveRequest
func (s *Service) RetrieveRequest(req *decenarch.RetrieveRequest) (*decenarch.RetrieveResponse, error) {
	log.Lvl3("Decenarch Service new RetrieveRequest:", req)
	returnResp := decenarch.RetrieveResponse{}
	returnResp.Adds = make([]decenarch.Webstore, 0)
	skipclient := decenarch.NewSkipClient()
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
		s.Suite().(cosi.Suite),
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
						s.Suite().(cosi.Suite),
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
			<-protocol.Done
			secret, err := protocol.SharedSecret()
			if err != nil {
				log.Error(err)
				return
			}
			s.storage.Lock()
			s.storage.Key = secret.X
			s.storage.Secret = secret
			s.storage.Unlock()
			s.save()
		}()
		return protocol, nil
	case protocol.SaveName:
		instance, _ := protocol.NewSaveProtocol(node)
		protocol := instance.(*protocol.SaveLocalState)
		return protocol, nil
	case protocol.NameDecrypt:
		instance, _ := protocol.NewDecrypt(node)
		protocol := instance.(*protocol.Decrypt)
		protocol.Secret = s.secret()
		return protocol, nil
	default:
		return nil, errors.New("protocol error, unknown protocol")
	}
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
	if err := s.RegisterHandlers(s.SaveWebpage, s.RetrieveRequest, s.Setup); err != nil {
		log.Error(err, "Couldn't register messages")
		return nil, err
	}
	//if err := s.tryLoad(); err != nil {
	//		log.Error(err)
	//		return nil, err
	//	}
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
		// check for relevant ressources
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
