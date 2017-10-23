package service

/*
The service.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"bytes"
	"errors"
	"sync"

	"io/ioutil"

	"github.com/nblp/decenarch"
	"github.com/nblp/decenarch/protocol"

	cosiprotocol "github.com/dedis/cothority/cosi/protocol"
	cosiservice "github.com/dedis/cothority/cosi/service"
	skipchain "github.com/dedis/cothority/skipchain"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

//"golang.org/x/crypto/bcrypt"

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

func RequestSignature(f string, r *onet.Roster) (*cosiservice.SignatureResponse, error) {
	if f == "" {
		return nil, errors.New("Invalid file input")
	}
	bF, bErr := ioutil.ReadFile(f)
	if bErr != nil {
		return nil, bErr
	}
	c := cosiservice.NewClient()
	sig, err := c.SignatureRequest(r, bF)
	if err != nil {
		return nil, err
	}
	log.Lvl5("file/signature", f, sig)
	return sig, nil
}

// VerificationSignature is an almost full copycat of the cosi/client.go
// verifySignatureHash. It verifies the validity of the signature sig emits by
// the roster el for the bytes b
func VerificationSignature(b []byte, sig *cosiservice.SignatureResponse, el *onet.Roster) error {
	fPublics := func(r *onet.Roster) []abstract.Point {
		publics := make([]abstract.Point, len(r.List))
		for i, e := range r.List {
			publics[i] = e.Public
		}
		return publics
	}
	publics := fPublics(el)
	hashHash, _ := crypto.HashBytes(network.Suite.Hash(), b)
	log.Lvl5("fileH, sigH", hashHash, sig.Hash)
	if !bytes.Equal(hashHash, sig.Hash) {
		return errors.New("You are trying to verify a signature " +
			"belonging to another file. (The hash provided by the signature " +
			"doesn't match with the hash of the file.)")
	}
	if err := cosiprotocol.VerifySignature(network.Suite, publics, b, sig.Signature); err != nil {
		return errors.New("Invalid sig:" + err.Error())
	}
	return nil
}

// StoreWebArchive add the saved url to the service's list of saved website
func StoreWebArchive(s *Service, url string, realUrl string, fsPath string, sig *cosiservice.SignatureResponse) {
	log.Lvl4("Store", url, "as archived website with realUrl", realUrl)
	if url == "" || realUrl == "" || fsPath == "" {
		log.Lvl3("Not storing the website as archived: invalid inputs")
	}
	// add entry to archive storage
	web := webstore{
		Url:    realUrl,
		FsPath: fsPath,
		Sig:    sig,
	}
	s.storage.Lock()
	if s.storage.webarchive == nil {
		s.storage.webarchive = make(map[string]webstore)
	}
	// we store the page under the alias (url) and effective url (realUrl)
	s.storage.webarchive[url] = web
	s.storage.webarchive[realUrl] = web
	s.storage.Unlock()
	s.save()
}

// SaveRequest
func (s *Service) SaveRequest(req *template.SaveRequest) (*template.SaveResponse, onet.ClientError) {
	log.Lvl3("Decenarch Service new SaveRequest")
	tree := req.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	if tree == nil {
		return nil, onet.NewClientErrorCode(template.ErrorParse, "couldn't create tree")
	}
	pi, err := s.CreateProtocol(protocol.SaveName, tree)
	if err != nil {
		return nil, onet.NewClientErrorCode(4042, err.Error())
	}
	pi.(*protocol.SaveMessage).Url = req.Url
	go pi.Start()
	realUrl := <-pi.(*protocol.SaveMessage).RealUrl
	path := <-pi.(*protocol.SaveMessage).FsPath
	sig, err := RequestSignature(path, req.Roster)
	if err != nil {
		log.Fatal("Error during signature retrival:", err)
	}
	StoreWebArchive(s, req.Url, realUrl, path, sig)
	resp := &template.SaveResponse{}
	return resp, nil
}

// RetrieveRequest
func (s *Service) RetrieveRequest(req *template.RetrieveRequest) (*template.RetrieveResponse, onet.ClientError) {
	log.Lvl3("Decenarch Service new RetrieveRequest")
	s.storage.Lock()
	defer s.storage.Unlock()
	if web, isSaved := s.storage.webarchive[req.Url]; isSaved {
		// retrive website
		log.Lvl4("Retrive Website Raw Data")
		tree := req.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
		if tree == nil {
			return nil, onet.NewClientErrorCode(template.ErrorParse, "couldn't create tree")
		}
		pi, err := s.CreateProtocol(protocol.RetrieveName, tree)
		if err != nil {
			return nil, onet.NewClientErrorCode(4043, err.Error())
		}
		pi.(*protocol.RetrieveMessage).Url = web.Url
		go pi.Start()
		website := <-pi.(*protocol.RetrieveMessage).ParentPath
		data := <-pi.(*protocol.RetrieveMessage).Data
		// (cosi) control signature
		log.Lvl4("Verify Website Signature")
		voFile, voErr := ioutil.ReadFile(website)
		if voErr != nil {
			log.Lvl4("Verification error: cannot read file")
			return nil, onet.NewClientErrorCode(4043, voErr.Error())
		}
		sig := web.Sig
		vErr := VerificationSignature(voFile, sig, req.Roster)
		if vErr != nil {
			log.Lvl4("Verification error: cannot verify signature", vErr)
			return nil, onet.NewClientErrorCode(4043, vErr.Error())
		}
		log.Lvl4("Verification Done.")
		return &template.RetrieveResponse{Website: website, Data: data}, nil
	} else {
		log.Lvl3("storage:\n", s.storage.webarchive)
		return nil, onet.NewClientErrorCode(template.ErrorParse, "website requested was not saved")
	}
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
	pi, err := protocol.NewSaveProtocol(tn)
	go func() {
		realUrl := <-pi.(*protocol.SaveMessage).RealUrl
		path := <-pi.(*protocol.SaveMessage).FsPath
		saveUrl := <-pi.(*protocol.SaveMessage).ChanUrl
		StoreWebArchive(s, saveUrl, realUrl, path, nil) //TODO access signature
	}()
	return pi, err
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
