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

	"golang.org/x/net/html"

	decenarch "github.com/dedis/student_18_decenar"
	"github.com/dedis/student_18_decenar/lib"
	"github.com/dedis/student_18_decenar/protocol"
	skip "github.com/dedis/student_18_decenar/skip"
	"gopkg.in/dedis/cothority.v2/messaging"

	ftcosiprotocol "gopkg.in/dedis/cothority.v2/ftcosi/protocol"
	ftcosiservice "gopkg.in/dedis/cothority.v2/ftcosi/service"
	"gopkg.in/dedis/cothority.v2/skipchain"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/kyber.v2/sign/cosi"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"
)

// Used for tests
var templateID onet.ServiceID

// timeout for protocol termination.
const timeout = 24 * time.Hour

func init() {
	var err error
	templateID, err = onet.RegisterNewService(decenarch.ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(&Storage{}, SetupPropagation{}, ConsensusPropagation{})
}

// Service is our template-service
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	// used to propagate setup parameters to other conodes
	propagateSetup     messaging.PropagationFunc
	propagateConsensus messaging.PropagationFunc

	// material for consensus on a single wepage
	LocalHTMLTree        *html.Node // HTML tree received by this node
	Leaves               []string   // unique leaves of the HTML tree
	EncryptedCBFSet      *lib.CipherVector
	ConsensusPropagation *ConsensusPropagation

	Storage *Storage
}

// storageID reflects the data we're storing - we could store more
// than one structure.
var storageID = []byte("storage")

type Storage struct {
	sync.Mutex
	GenesisID      skipchain.SkipBlockID
	LatestID       skipchain.SkipBlockID
	Threshold      int32
	Secret         *lib.SharedSecret
	CompleteProofs lib.CompleteProofs
}

type SetupPropagation struct {
	GenesisID skipchain.SkipBlockID
	Threshold int32
}

type ConsensusPropagation struct {
	RootKey             string
	PartialsBytes       map[int][]byte
	ConsensusSet        []int64
	ConsensusParameters []uint64
}

// Setup is the function called by the service to setup everything is needed
// for DecenArch, in particular this function runs the DKG protocol
func (s *Service) Setup(req *decenarch.SetupRequest) (*decenarch.SetupResponse, error) {
	// compute and store threshold. This threshold will be used also by the
	// other conodes of the roster
	s.Storage.Lock()
	s.Storage.Threshold = int32(len(req.Roster.List) - (len(req.Roster.List)-1)/3)
	s.Storage.Unlock()
	s.save()

	// start a new skipchain only if there isn't one already
	if s.genesisID() == nil {
		client := skip.NewSkipClient(int(s.threshold()))
		genesis, err := client.SkipStart(req.Roster)
		if err != nil {
			return nil, err
		}

		// store genesisID and latestID
		s.Storage.Lock()
		s.Storage.GenesisID = genesis.Hash
		s.Storage.LatestID = genesis.Hash // latest know block is genesis at the beginning
		s.Storage.Unlock()
		s.save()
	}

	// propagate setup
	threshold := int32(len(req.Roster.List) - (len(req.Roster.List)-1)/3)
	replies, err := s.propagateSetup(req.Roster, &SetupPropagation{s.genesisID(), threshold}, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if replies != len(req.Roster.List) {
		log.Lvl1("Got only", replies, "replies for setup-propagation")
	}

	// run DKG protocol
	root := req.Roster.NewRosterWithRoot(s.ServerIdentity())
	tree := root.GenerateNaryTree(len(req.Roster.List))
	if tree == nil {
		return nil, errors.New("error while creating the tree for the DKG protocol")
	}

	// run DKG protocol
	instance, err := s.CreateProtocol(protocol.NameDKG, tree)
	if err != nil {
		return nil, err
	}
	protocol := instance.(*protocol.SetupDKG)
	protocol.Wait = true

	err = protocol.Start()
	if err != nil {
		return nil, err
	}

	select {
	case <-protocol.Done:
		secret, err := lib.NewSharedSecret(protocol.DKG)
		if err != nil {
			return nil, err
		}
		s.Storage.Lock()
		s.Storage.Secret = secret
		s.Storage.Unlock()
		s.save()

		return &decenarch.SetupResponse{Key: secret.X}, nil
	case <-time.After(timeout):
		return nil, errors.New("dkg didn't finish in time")
	}
}

// Save is the function called by the service when a client want to save a website in the
// archive.
func (s *Service) SaveWebpage(req *decenarch.SaveRequest) (*decenarch.SaveResponse, error) {
	log.Lvl3("Decenarch Service new SaveWebpage")

	// create the tree
	root := req.Roster.NewRosterWithRoot(s.ServerIdentity())
	tree := root.GenerateNaryTree(len(req.Roster.List))
	if tree == nil {
		return nil, errors.New("error while creating the tree for the consensus protocol")
	}

	// configure the protocol
	instance, err := s.CreateProtocol(protocol.NameConsensusStructured, tree)
	if err != nil {
		return nil, err
	}
	structuredConsensusProtocol := instance.(*protocol.ConsensusStructuredState)
	structuredConsensusProtocol.SharedKey, err = s.key()
	if err != nil {
		return nil, err
	}
	structuredConsensusProtocol.Url = req.Url

	// start the protocol
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
		s.LocalHTMLTree = structuredConsensusProtocol.LocalTree

		// get unique leaves
		s.Leaves = lib.ListUniqueDataLeaves(structuredConsensusProtocol.LocalTree)

		// get complete proofs of the whole consensus over structured
		// data protocol
		s.Storage.Lock()
		s.Storage.CompleteProofs = structuredConsensusProtocol.CompleteProofs
		s.Storage.Unlock()
		s.save()

		// run decryt protocol
		partials, err := s.decrypt(tree, structuredConsensusProtocol.EncryptedCBFSet)
		if err != nil {
			return nil, err
		}

		// reconstruct html page
		consensusCBF, msgToSign, err := s.reconstruct(len(req.Roster.List), partials, s.localHTMLTree(), structuredConsensusProtocol.ParametersCBF)
		if err != nil {
			return nil, err
		}

		// propagate consensus result
		partialsBytes := make(map[int][]byte)
		for k, p := range partials {
			partialsBytes[k] = lib.AbstractPointsToBytes(p)
		}

		// get CBF parameters
		paramCBF := structuredConsensusProtocol.ParametersCBF
		parametersToMarshal := []uint64{uint64(paramCBF[0]), uint64(paramCBF[1])}

		// pass consensus set and parameters to children
		childrenData := &ConsensusPropagation{
			RootKey:             s.ServerIdentity().Public.String(),
			ConsensusSet:        consensusCBF,
			ConsensusParameters: parametersToMarshal,
			PartialsBytes:       partialsBytes,
		}
		replies, err := s.propagateConsensus(req.Roster, childrenData, 10*time.Second)
		if err != nil {
			return nil, err
		}
		if replies != len(req.Roster.List) {
			log.Lvl1("Got only", replies, "replies for setup-propagation")
		}

		// sign the consensus website found
		sig, sigErr := s.sign(tree, msgToSign, partials, consensusCBF, structuredConsensusProtocol.ParametersCBF, true)
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
	//var webadds []decenarch.Webstore = make([]decenarch.Webstore, 0)
	bytePage, err := base64.StdEncoding.DecodeString(webmain.Page)
	if err != nil {
		return nil, err
	}
	addsLinks := ExtractPageExternalLinks(webmain.Url, bytes.NewBuffer(bytePage))

	// iterate over additional links and retrieve the content
	webadds := make([]decenarch.Webstore, len(addsLinks))
	webmain.AddsUrl = make([]string, len(addsLinks))
	for i, al := range addsLinks {
		log.Lvl4("Get additional", al)
		api, err := s.CreateProtocol(protocol.NameConsensusUnstructured, tree)
		if err != nil {
			// If there is an error for additional data we
			// do not return an error, we simply inform the
			// user and handle the next additional data
			log.Infof("Error during unstructured consensus protocol for additional link %v: %v\n", al, err)
			continue
		}
		unstructuredConsensusProtocol := api.(*protocol.ConsensusUnstructuredState)
		unstructuredConsensusProtocol.Url = al
		unstructuredConsensusProtocol.Threshold = uint32(s.threshold())
		err = api.Start()
		if err != nil {
			log.Infof("Error during unstructured consensus protocol for additional link %v: %v\n", al, err)
			continue
		}
		select {
		case <-unstructuredConsensusProtocol.Finished:
			ru := unstructuredConsensusProtocol.Url
			ct := unstructuredConsensusProtocol.ContentType
			mts := unstructuredConsensusProtocol.MsgToSign

			// sign the consensus additional data
			// consensus Bloom filter is not needed for additional data
			as, err := s.sign(tree, mts, nil, nil, nil, false)
			if err != nil {
				log.Error(err)
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
			webadds[i] = aweb
			webmain.AddsUrl[i] = al
		case <-time.After(timeout):
			log.Infof("Timeout for unstructured consensus protocol for additional link %v: %v\n", al, err)
		}
	}

	// add additional data to the slice of storing structures
	webadds = append(webadds, webmain)
	// send data to the blockchain
	log.Lvl4("sending", webadds, "to skipchain")
	skipclient := skip.NewSkipClient(int(s.threshold()))
	resp, err := skipclient.SkipAddData(s.genesisID(), req.Roster, webadds)
	if err != nil {
		return nil, err
	}

	// store latest block ID for retrieval
	s.Storage.Lock()
	s.Storage.LatestID = resp.Latest.Hash
	s.Storage.Unlock()
	s.save()

	return &decenarch.SaveResponse{}, nil
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
	err = p.Start()
	if err != nil {
		return nil, err
	}

	if !<-p.Finished {
		return nil, errors.New("decrypt error, impossible to ge partials")
	}
	log.Lvl3("Decryption protocol is done.")
	return p.Partials, nil
}

func (s *Service) reconstruct(nodes int, partials map[int][]kyber.Point, localTree *html.Node, paramCBF []uint) ([]int64, []byte, error) {
	reconstructed, err := lib.ReconstructVectorFromPartials(nodes, int(s.threshold()), partials)
	if err != nil {
		return nil, nil, err
	}

	// build the consensus HTML page using the reconstructed Bloom filter
	consensusCBF := lib.BloomFilterFromSet(reconstructed, paramCBF)
	htmlPage, err := s.buildConsensusHtmlPage(localTree, consensusCBF)
	if err != nil {
		return nil, nil, err
	}

	return reconstructed, htmlPage, nil
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

func (s *Service) sign(t *onet.Tree, msgToSign []byte, partials map[int][]kyber.Point, reconstructedCBF []int64, paramCBF []uint, structured bool) (*ftcosiservice.SignatureResponse, error) {
	// create the protocol depending on the data we want to sign -
	// structured, i.e. HTML, or unstructured data
	var pi onet.ProtocolInstance
	var err error
	if structured {
		// protocol instance
		pi, err = s.CreateProtocol(protocol.NameSignStructured, t)
		if err != nil {
			return nil, err
		}
	} else {
		// protocol instance
		pi, err = s.CreateProtocol(protocol.NameSignUnstructured, t)
		if err != nil {
			return nil, err
		}
	}

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
	//p.Timeout = time.Second * 5
	p.Timeout = time.Minute * 5

	// add data for verification depending on what we want to sign
	if structured {
		// get CBF parameters
		parametersToMarshal := []uint64{uint64(paramCBF[0]), uint64(paramCBF[1])}

		// set and marshal verification data
		data := protocol.VerificationData{
			RootKey:             p.Public().String(),
			ConodeKey:           p.Public().String(),
			Leaves:              s.uniqueLeaves(),
			CompleteProofs:      s.completeProofs(),
			ConsensusSet:        reconstructedCBF,
			ConsensusParameters: parametersToMarshal,
		}

		dataMarshaled, err := network.Marshal(&data)
		if err != nil {
			return nil, err
		}
		p.Data = dataMarshaled
		p.CreateProtocol = s.CreateProtocol
	}

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
		return nil, errors.New("signature protocol timed out")
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
	skipclient := skip.NewSkipClient(int(s.threshold()))
	resp, err := skipclient.SkipGetData(s.latestID(), req.Roster, req.Url, req.Timestamp)
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
		cosi.NewThresholdPolicy(int(s.threshold())))
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
						cosi.NewThresholdPolicy(int(s.threshold())))
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
		instance, err := protocol.NewSetupDKG(node)
		if err != nil {
			return nil, err
		}
		proto := instance.(*protocol.SetupDKG)
		go func() {
			<-proto.Done
			secret, err := lib.NewSharedSecret(proto.DKG)
			if err != nil {
				log.Error(err)
				return
			}
			s.Storage.Lock()
			s.Storage.Secret = secret
			s.Storage.Unlock()
			s.save()
		}()
		return proto, nil
	case protocol.NameConsensusStructured:
		instance, err := protocol.NewConsensusStructuredProtocol(node)
		if err != nil {
			return nil, err
		}
		proto := instance.(*protocol.ConsensusStructuredState)
		proto.SharedKey, err = s.key()
		if err != nil {
			return nil, err
		}
		go func() {
			<-proto.Finished
			// get local HTML of the conode for later verification of the
			// proposed consensus HTML page
			s.Leaves = lib.ListUniqueDataLeaves(proto.LocalTree)
			s.Storage.Lock()
			s.Storage.CompleteProofs = proto.CompleteProofsToSend
			s.Storage.Unlock()
			s.save()
		}()
		return proto, nil
	case protocol.NameConsensusUnstructured:
		instance, err := protocol.NewConsensusUnstructuredProtocol(node)
		if err != nil {
			return nil, err
		}
		proto := instance.(*protocol.ConsensusUnstructuredState)
		return proto, nil
	case protocol.NameDecrypt:
		instance, err := protocol.NewDecrypt(node)
		if err != nil {
			return nil, err
		}
		proto := instance.(*protocol.Decrypt)
		proto.Secret = s.secret()
		proto.Threshold = s.threshold()
		go func() {
			<-proto.Received
			s.EncryptedCBFSet = proto.EncryptedCBFSet
		}()
		return proto, nil
	// for the sign protocol only the sub protocol is needed here
	case protocol.NameSubSignStructured:
		instance, err := protocol.NewSubSignStructuredProtocol(node)
		if err != nil {
			return nil, err
		}
		proto := instance.(*ftcosiprotocol.SubFtCosi)
		// set verification data
		data := protocol.VerificationData{
			Threshold:           int(s.threshold()),
			RootKey:             s.ConsensusPropagation.RootKey,
			Partials:            s.ConsensusPropagation.PartialsBytes,
			ConodeKey:           proto.Public().String(),
			EncryptedCBFSet:     s.EncryptedCBFSet,
			Leaves:              s.uniqueLeaves(),
			CompleteProofs:      s.completeProofs(),
			ConsensusSet:        s.ConsensusPropagation.ConsensusSet,
			ConsensusParameters: s.ConsensusPropagation.ConsensusParameters,
		}
		dataMarshaled, err := network.Marshal(&data)
		if err != nil {
			return nil, err
		}
		proto.Data = dataMarshaled
		return proto, nil
	case protocol.NameSubSignUnstructured:
		proto, err := protocol.NewSubSignUnstructuredProtocol(node)
		if err != nil {
			return nil, err
		}
		return proto, nil
	}
	return nil, nil
}

// completeProofs
func (s *Service) completeProofs() lib.CompleteProofs {
	s.Storage.Lock()
	defer s.Storage.Unlock()
	return s.Storage.CompleteProofs
}

// uniqueLeaves
func (s *Service) uniqueLeaves() []string {
	return s.Leaves
}

// latestID
func (s *Service) latestID() skipchain.SkipBlockID {
	s.Storage.Lock()
	defer s.Storage.Unlock()
	return s.Storage.LatestID
}

// genesisID
func (s *Service) genesisID() skipchain.SkipBlockID {
	s.Storage.Lock()
	defer s.Storage.Unlock()
	return s.Storage.GenesisID
}

// LocalHTMLTree
func (s *Service) localHTMLTree() *html.Node {
	return s.LocalHTMLTree
}

// threshold
func (s *Service) threshold() int32 {
	s.Storage.Lock()
	defer s.Storage.Unlock()
	return s.Storage.Threshold
}

// secret returns the shared secret for a given election.
func (s *Service) secret() *lib.SharedSecret {
	s.Storage.Lock()
	defer s.Storage.Unlock()
	return s.Storage.Secret
}

// key returns the key given by DKG
func (s *Service) key() (kyber.Point, error) {
	s.Storage.Lock()
	defer s.Storage.Unlock()
	if s.Storage.Secret == nil {
		return nil, errors.New("Shared public key not found: run setup before saving a webpage")
	}
	return s.Storage.Secret.X, nil
}

func (s *Service) propagateConsensusFunc(consensusMessage network.Message) {
	m, ok := consensusMessage.(*ConsensusPropagation)
	if !ok {
		log.Error("got something else than a setup propagation message")
		return
	}
	s.ConsensusPropagation = m
}

func (s *Service) propagateSetupFunc(setupMessage network.Message) {
	m, ok := setupMessage.(*SetupPropagation)
	if !ok {
		log.Error("got something else than a setup propagation message")
		return
	}
	s.Storage.Lock()
	s.Storage.GenesisID = m.GenesisID
	s.Storage.Threshold = m.Threshold
	s.Storage.Unlock()
	s.save()
}

// saves all skipblocks.
func (s *Service) save() {
	log.Lvl3(s.String(), "Saving Service")
	s.Storage.Lock()
	defer s.Storage.Unlock()
	err := s.Save(storageID, s.Storage)
	if err != nil {
		log.Error("Couldn't save file:", err)
	}
}

// Tries to load the configuration and updates the data in the service
// if it finds a valid config-file.
func (s *Service) tryLoad() error {
	s.Storage.Lock()
	defer s.Storage.Unlock()

	msg, err := s.Load(storageID)
	if err != nil {
		return err
	}
	if msg == nil {
		return nil
	}
	var ok bool
	s.Storage, ok = msg.(*Storage)
	if !ok {
		return errors.New("service error: could not unmarshal storage")
	}
	return nil
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments.
func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		Storage:          &Storage{},
	}
	if err := s.RegisterHandlers(s.Setup, s.SaveWebpage, s.Retrieve); err != nil {
		log.Error(err, "Couldn't register messages")
		return nil, err
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, err
	}
	var err error
	s.propagateSetup, err = messaging.NewPropagationFunc(c, "PropagateSetup", s.propagateSetupFunc, -1)
	s.propagateConsensus, err = messaging.NewPropagationFunc(c, "PropagateConsensus", s.propagateConsensusFunc, -1)
	log.ErrFatal(err)
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
