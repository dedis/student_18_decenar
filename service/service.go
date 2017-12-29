package service

/*
The service.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"bytes"
	"errors"
	"math"
	"sync"
	"time"

	"encoding/base64"
	urlpkg "net/url"

	"github.com/nblp/decenarch"
	"github.com/nblp/decenarch/protocol"
	"golang.org/x/net/html"

	cosiservice "gopkg.in/dedis/cothority.v1/cosi/service"

	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

// Used for tests
var templateID onet.ServiceID

func init() {
	var err error
	templateID, err = onet.RegisterNewService(decenarch.ServiceName, newService)
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
const storageID = "main"

type storage struct {
	sync.Mutex
}

// SaveRequest is the function called by the service when a client want to save a website in the
// archive.
func (s *Service) SaveRequest(req *decenarch.SaveRequest) (*decenarch.SaveResponse, onet.ClientError) {
	log.Lvl3("Decenarch Service new SaveRequest")
	tree := req.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		return nil, onet.NewClientErrorCode(decenarch.ErrorParse, "couldn't create tree")
	}

	// IMPROVEMENT threshold should be easily configurable
	threshold := int32(math.Ceil(float64(len(tree.Roster.List)) * 0.8))

	pi, err := s.CreateProtocol(protocol.SaveName, tree)
	if err != nil {
		return nil, onet.NewClientErrorCode(4042, err.Error())
	}
	pi.(*protocol.SaveMessage).Url = req.Url
	// IMPROVEMENT threshold could not be hardcoded
	pi.(*protocol.SaveMessage).Threshold = threshold
	go pi.Start()
	// sign the consensus website found
	var realUrl string = <-pi.(*protocol.SaveMessage).StringChan
	var contentType string = <-pi.(*protocol.SaveMessage).StringChan
	var msgToSign []byte = <-pi.(*protocol.SaveMessage).MsgToSign
	cosiclient := cosiservice.NewClient()
	sig, sigErr := cosiclient.SignatureRequest(req.Roster, msgToSign)
	if sigErr != nil {
		return nil, onet.NewClientErrorCode(4042, err.Error())
	}
	mainTimestamp := time.Now().Format("2006/01/02 15:04")
	webmain := decenarch.Webstore{
		Url:         realUrl,
		ContentType: contentType,
		Sig:         sig,
		Page:        base64.StdEncoding.EncodeToString(msgToSign),
		AddsUrl:     make([]string, 0),
		Timestamp:   mainTimestamp,
	}
	log.Lvl4("Create stored request")
	// consensus protocol for all additional ressources
	var webadds []decenarch.Webstore = make([]decenarch.Webstore, 0)
	bytePage, byteErr := base64.StdEncoding.DecodeString(webmain.Page)
	addsLinks := make([]string, 0)
	if byteErr == nil {
		addsLinks = ExtractPageExternalLinks(webmain.Url, bytes.NewBuffer(bytePage))
	}
	for _, al := range addsLinks {
		log.Lvl4("Get additional", al)
		api, aerr := s.CreateProtocol(protocol.SaveName, tree)
		if aerr == nil {
			api.(*protocol.SaveMessage).Url = al
			api.(*protocol.SaveMessage).Threshold = threshold
			go api.Start()
			ru := <-api.(*protocol.SaveMessage).StringChan
			ct := <-api.(*protocol.SaveMessage).StringChan
			mts := <-api.(*protocol.SaveMessage).MsgToSign
			as, asE := cosiclient.SignatureRequest(req.Roster, mts)
			if asE == nil {
				aweb := decenarch.Webstore{
					Url:         ru,
					ContentType: ct,
					Sig:         as,
					Page:        base64.StdEncoding.EncodeToString(mts),
					AddsUrl:     make([]string, 0),
					Timestamp:   mainTimestamp}
				webadds = append(webadds, aweb)
				webmain.AddsUrl = append(webmain.AddsUrl, al)
			}
		}
	}
	webadds = append(webadds, webmain)
	log.Lvl4("sending", webadds, "to skipchain")
	skipclient := decenarch.NewSkipClient()
	skipclient.SkipAddData(req.Roster, webadds)

	resp := &decenarch.SaveResponse{}
	return resp, nil
}

// RetrieveRequest
func (s *Service) RetrieveRequest(req *decenarch.RetrieveRequest) (*decenarch.RetrieveResponse, onet.ClientError) {
	log.Lvl3("Decenarch Service new RetrieveRequest")
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
		return nil, onet.NewClientError(bErr)
	}
	// TODO verify signature error here 65 bits instead of 64
	//log.Lvl4("service-RetrieveRequest-verify signature")
	vsigErr := crypto.VerifySchnorr(
		network.Suite,
		req.Roster.Aggregate,
		bPage,
		resp.MainPage.Sig.Signature)
	if vsigErr != nil {
		log.Lvl1(vsigErr)
		//return nil, onet.NewClientError(vsigErr)
	}
	for _, addUrl := range resp.MainPage.AddsUrl {
		for _, addPage := range resp.AllPages {
			if addUrl == addPage.Url {
				// TODO verify cosi signature
				returnResp.Adds = append(returnResp.Adds, addPage)
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
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("Decenarch Service new protocol event")
	return nil, nil
}

// saves all skipblocks.
func (s *Service) save() {
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
	s.storage = &storage{}
	if !s.DataAvailable(storageID) {
		return nil
	}
	msg, err := s.Load(storageID)
	if err != nil {
		return err
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
func newService(c *onet.Context) onet.Service {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	if err := s.RegisterHandlers(s.SaveRequest, s.RetrieveRequest); err != nil {
		log.ErrFatal(err, "Couldn't register messages")
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
	}
	return s
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
