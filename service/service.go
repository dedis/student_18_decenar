package service

/*
The service.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"errors"
	"math"
	"sync"

	"github.com/nblp/decenarch"
	"github.com/nblp/decenarch/protocol"

	cosiservice "github.com/dedis/cothority/cosi/service"

	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

//TODO skipchain "github.com/dedis/cothority/skipchain"

// Used for tests
var templateID onet.ServiceID

func init() {
	var err error
	templateID, err = onet.RegisterNewService(template.ServiceName, newService)
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

// storage is used to save our data.
type storage struct {
	webarchive map[string]webstore

	sync.Mutex
}

// webstore is used to store website
type webstore struct {
	Url    string
	FsPath string
	Sig    *cosiservice.SignatureResponse
}

// SaveRequest
func (s *Service) SaveRequest(req *template.SaveRequest) (*template.SaveResponse, onet.ClientError) {
	log.Lvl3("Decenarch Service new SaveRequest")
	// find a consensus on webpage
	tree := req.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		return nil, onet.NewClientErrorCode(template.ErrorParse, "couldn't create tree")
	}
	pi, err := s.CreateProtocol(protocol.SaveName, tree)
	if err != nil {
		return nil, onet.NewClientErrorCode(4042, err.Error())
	}
	pi.(*protocol.SaveMessage).Url = req.Url
	// BUG(nblp) threshold should not be hardcoded
	pi.(*protocol.SaveMessage).Threshold = uint32(math.Ceil(float64(len(tree.Roster.List)) * 0.8))
	go pi.Start()
	var msgToSign []byte = <-pi.(*protocol.SaveMessage).MsgToSign
	cosiClient := cosiservice.NewClient()
	sig, sigErr := cosiClient.SignatureRequest(req.Roster, msgToSign)
	if sigErr != nil {
		return nil, onet.NewClientErrorCode(4042, err.Error())
	}
	log.Lvl4("Create stored request")
	CreateStoredRequest(msgToSign, sig)
	// TODO store result in Skipchain
	// TODO relaunch it for all additional ressources

	// TODO update code below
	resp := &template.SaveResponse{}
	return resp, nil
}

// TODO create function
func CreateStoredRequest(rawData []byte, sig *cosiservice.SignatureResponse) error {
	return nil
}

// RetrieveRequest
func (s *Service) RetrieveRequest(req *template.RetrieveRequest) (*template.RetrieveResponse, onet.ClientError) {
	log.Lvl3("Decenarch Service new RetrieveRequest")
	//	s.storage.Lock()
	//	defer s.storage.Unlock()
	//	if web, isSaved := s.storage.webarchive[req.Url]; isSaved {
	//		// retrive website
	//		log.Lvl4("Retrive Website Raw Data")
	//		tree := req.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	//		if tree == nil {
	//			return nil, onet.NewClientErrorCode(template.ErrorParse, "couldn't create tree")
	//		}
	//		pi, err := s.CreateProtocol(protocol.RetrieveName, tree)
	//		if err != nil {
	//			return nil, onet.NewClientErrorCode(4043, err.Error())
	//		}
	//		pi.(*protocol.RetrieveMessage).Url = web.Url
	//		go pi.Start()
	//		website := <-pi.(*protocol.RetrieveMessage).ParentPath
	//		data := <-pi.(*protocol.RetrieveMessage).Data
	//		// (cosi) control signature
	//		log.Lvl4("Verify Website Signature")
	//		voFile, voErr := ioutil.ReadFile(website)
	//		if voErr != nil {
	//			log.Lvl4("Verification error: cannot read file")
	//			return nil, onet.NewClientErrorCode(4043, voErr.Error())
	//		}
	//		sig := web.Sig
	//		vErr := VerificationSignature(voFile, sig, req.Roster)
	//		if vErr != nil {
	//			log.Lvl4("Verification error: cannot verify signature", vErr)
	//			return nil, onet.NewClientErrorCode(4043, vErr.Error())
	//		}
	//		log.Lvl4("Verification Done.")
	//		return &template.RetrieveResponse{Website: website, Data: data}, nil
	//	} else {
	//		log.Lvl3("storage:\n", s.storage.webarchive)
	//		return nil, onet.NewClientErrorCode(template.ErrorParse, "website requested was not saved")
	//	}
	return nil, nil
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
