package service

/*
The service.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"time"

	"errors"
	"sync"

	"github.com/nblp/decenarch"
	"github.com/nblp/decenarch/protocol"

	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"

	"golang.org/x/crypto/bcrypt"
)

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
	Count      int
	webarchive map[string]webstore

	sync.Mutex
}

// webstore is used to store website
type webstore struct {
	Hash []byte
	Url  string
}

// SaveRequest
func (s *Service) SaveRequest(req *template.SaveRequest) (*template.SaveResponse, onet.ClientError) {
	log.Lvl3("Decenarch Service new SaveRequest")
	// start save protocol
	tree := req.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		return nil, onet.NewClientErrorCode(template.ErrorParse, "couldn't create tree")
	}
	pi, err := s.CreateProtocol("DecenarchSave", tree)
	if err != nil {
		return nil, onet.NewClientErrorCode(4042, err.Error())
	}
	log.Lvl5("Write Url in SaveMessage channel")
	pi.(*protocol.SaveMessage).Url = req.Url
	log.Lvl5("Start Protocol")
	pi.Start()
	resp := &template.SaveResponse{}
	// record website in saved website index
	log.Lvl4("Acknowledge the archiving process in service level")
	url := req.Url
	hash, err_hash := bcrypt.GenerateFromPassword([]byte(url), 30)
	if err_hash != nil {
		return nil, onet.NewClientErrorCode(4042, err_hash.Error())
	}
	web := webstore{
		Hash: hash,
		Url:  url,
	}
	s.storage.Lock()
	s.storage.webarchive[url] = web
	s.storage.Unlock()
	s.save()
	return resp, nil
}

// RetrieveRequest
func (s *Service) RetrieveRequest(req *template.RetrieveRequest) (*template.RetrieveResponse, onet.ClientError) {
	log.Lvl3("Decenarch Service new RetriveRequest")
	s.storage.Lock()
	defer s.storage.Unlock()
	if web, isSaved := s.storage.webarchive[req.Url]; isSaved {
		//TODO need to send File or []byte + all needed data
		return &template.RetrieveResponse{Website: web.Url}, nil
	} else {
		return nil, onet.NewClientErrorCode(template.ErrorParse, "website requested was not saved")
	}
}

// ClockRequest starts a template-protocol and returns the run-time.
func (s *Service) ClockRequest(req *template.ClockRequest) (*template.ClockResponse, onet.ClientError) {
	log.Lvl3("Decenarch Service new ClockRequest")
	s.storage.Lock()
	s.storage.Count++
	s.storage.Unlock()
	s.save()
	tree := req.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		return nil, onet.NewClientErrorCode(template.ErrorParse, "couldn't create tree")
	}
	pi, err := s.CreateProtocol(protocol.Name, tree)
	if err != nil {
		return nil, onet.NewClientError(err)
	}
	start := time.Now()
	pi.Start()
	resp := &template.ClockResponse{
		Children: <-pi.(*protocol.Template).ChildCount,
	}
	resp.Time = time.Now().Sub(start).Seconds()
	return resp, nil
}

// CountRequest returns the number of instantiations of the protocol.
func (s *Service) CountRequest(req *template.CountRequest) (*template.CountResponse, onet.ClientError) {
	log.Lvl3("Decenarch Service new CountRequest")
	s.storage.Lock()
	defer s.storage.Unlock()
	return &template.CountResponse{Count: s.storage.Count}, nil
}

// NewProtocol is called on all nodes of a Tree (except the root, since it is
// the one starting the protocol) so it's the Service that will be called to
// generate the PI on all others node.
// If you use CreateProtocolOnet, this will not be called, as the Onet will
// instantiate the protocol on its own. If you need more control at the
// instantiation of the protocol, use CreateProtocolService, and you can
// give some extra-configuration to your protocol in here.
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	//log.Lvl3("Decenarch Service new protocol event")
	//t := &protocol.SaveMessage{
	//	TreeNodeInstance: tn,
	//	Url:              make(chan string),
	//	Errs:             make(chan []error),
	//}
	//t.Url <- ""
	//for _, handler := range []interface{}{t.HandleAnnounce, t.HandleReply} {
	//	if err := t.RegisterHandler(handler); err != nil {
	//		return nil, errors.New("couldn't register handler: " + err.Error())
	//	}
	//}
	//return t, nil
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
	if err := s.RegisterHandlers(s.ClockRequest, s.CountRequest, s.SaveRequest, s.RetrieveRequest); err != nil {
		log.ErrFatal(err, "Couldn't register messages")
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
	}
	return s
}
