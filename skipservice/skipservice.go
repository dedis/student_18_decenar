package skipservice

/*
The skipservice.go defines what to do for each API-call. This part of the service
runs on the node.
*/

import (
	"errors"
	"sync"
	"time"

	"encoding/base64"
	"encoding/json"

	"github.com/dedis/student_18_decenar"
	skipchain "gopkg.in/dedis/cothority.v1/skipchain"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"gopkg.in/dedis/crypto.v0/cosi"
)

// Used for tests
var templateID onet.ServiceID

func init() {
	var err error
	templateID, err = onet.RegisterNewService(decenarch.SkipServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessage(&skipstorage{})
}

// Service is our template-service
type SkipService struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor

	skipstorage *skipstorage
	stopsignal  bool

	data     []decenarch.Webstore
	dataChan chan decenarch.Webstore
}

// skipstorageID reflects the data we're storing - we could store more
// than one structure.
const skipstorageID = "main"

// skipMin is the number of minutes between each block creation
// TODO original value 10
const skipMin = 2

type skipstorage struct {
	sync.Mutex
	LastSkipBlockID skipchain.SkipBlockID
	Skipchain       []*skipchain.SkipBlock
}

// SkipRootStartRequest create a genesis block and begin a new skipchain
// it should not be used without SkipStartRequest.
func (s *SkipService) SkipRootStartRequest(req *decenarch.SkipRootStartRequest) (*decenarch.SkipRootStartResponse, onet.ClientError) {
	log.Lvl1("SkipRootStartRequest execution")
	skipclient := skipchain.NewClient()
	// here we assume the skipchain will be forwarded to other member of the roster
	skipblock, err := skipclient.CreateGenesis(
		req.Roster,
		2,
		2,
		skipchain.VerificationStandard,
		nil,
		nil)
	if err != nil {
		return nil, err
	}
	s.skipstorage.Lock()
	s.skipstorage.LastSkipBlockID = skipblock.Hash
	s.skipstorage.Skipchain = append(s.skipstorage.Skipchain, skipblock)
	s.skipstorage.Unlock()
	return &decenarch.SkipRootStartResponse{skipblock}, nil
}

// SkipStartRequest create a go-routine that will listen to the s.dataChan and
// will create a skipblock every skipMin minutes. No data verification will
// be done. We assume it is done before when storing the data in s.data in the
// SkipAddDataRequest function.
func (s *SkipService) SkipStartRequest(req *decenarch.SkipStartRequest) (*decenarch.SkipStartResponse, onet.ClientError) {
	log.Lvl1("SkipStartRequest execution")
	skipclient := skipchain.NewClient()
	go func() {
		log.Lvl1("SkipStartRequest - Begin blocks creation's loop")
		for !s.stopsignal {
			log.Lvl3("SkipStartLoop - create new block")
			// update skipchain
			upresp, uperr := skipclient.GetUpdateChain(
				req.Roster, req.Genesis.Hash)
			if uperr != nil {
				log.Error(uperr)
			} else {
				s.skipstorage.Lock()
				l := len(s.skipstorage.Skipchain)
				if l == 0 {
					s.skipstorage.Skipchain = upresp.Update
				} else {
					s.skipstorage.Skipchain = append(
						s.skipstorage.Skipchain[:l-1],
						upresp.Update...)
				}
				l = len(s.skipstorage.Skipchain)
				s.skipstorage.LastSkipBlockID = s.skipstorage.Skipchain[l-1].Hash
				s.skipstorage.Unlock()
			}
			s.skipstorage.Lock()
			latest := s.skipstorage.Skipchain[len(s.skipstorage.Skipchain)-1]
			s.skipstorage.Unlock()
			// store data in nextblock
			bData, bErr := webstoreExtractAndConvert(s.data)
			if bErr != nil {
				log.Error(bErr)
			} else {
				resp, err := skipclient.StoreSkipBlock(latest, req.Roster, bData)
				if err != nil {
					log.Error(err)
				} else {
					s.skipstorage.Lock()
					s.skipstorage.LastSkipBlockID = resp.Latest.Hash
					s.skipstorage.Unlock()
					s.data = make([]decenarch.Webstore, 0)
					s.save()
				}
			}
			// read data from dataChan for skipMin minutes
			readTimeout := false
			for !readTimeout {
				log.Lvl4("Waiting for data...")
				select {
				case d := <-s.dataChan:
					log.Lvl4("skipstart - data added:", d.Url, "!")
					s.data = append(s.data, d)
				case <-time.After(skipMin * time.Minute):
					log.Lvl4("skipstart - data timeout!")
					readTimeout = true
				}
			}
			//time.Sleep(skipMin * time.Minute)
		}
	}()
	return &decenarch.SkipStartResponse{Msg: "Blocks creation's loop launched"}, nil
}

// SkipStopRequest sends a signal to the service to stop the loop of skipblock creation
func (s *SkipService) SkipStopRequest(req *decenarch.SkipStopRequest) (*decenarch.SkipStopResponse, onet.ClientError) {
	s.stopsignal = true
	return &decenarch.SkipStopResponse{}, nil
}

// SkipAddDataRequest receive webstore data, verify their integrity and store
// the valid data inside the service waiting for them to be put on the skipchain
func (s *SkipService) SkipAddDataRequest(req *decenarch.SkipAddDataRequest) (*decenarch.SkipAddDataResponse, onet.ClientError) {
	log.Lvl4("SkipAddDataRequest - Begin")
	s.data = make([]decenarch.Webstore, 0)
	for _, d := range req.Data {
		log.Lvl4("SkipAddDataRequest - add", d)
		// verify signature
		bd, bdErr := base64.StdEncoding.DecodeString(d.Page)
		if bdErr != nil {
			return nil, onet.NewClientError(bdErr)
		}
		vsErr := cosi.VerifySignature(
			network.Suite,
			req.Roster.Publics(),
			bd,
			d.Sig.Signature)
		if vsErr != nil {
			return nil, onet.NewClientError(vsErr)
		}
		// effectively add data
		s.dataChan <- d
		s.data = append(s.data, d)
	}
	log.Lvl4("SkipAddDataRequest - done")
	return &decenarch.SkipAddDataResponse{}, nil
}

func (s *SkipService) SkipGetDataRequest(req *decenarch.SkipGetDataRequest) (*decenarch.SkipGetDataResponse, onet.ClientError) {
	log.Lvl4("Begin GetData request on service")
	s.skipstorage.Lock()
	lastKnowID := s.skipstorage.LastSkipBlockID
	s.skipstorage.Unlock()
	tReq, trErr := time.Parse("2006/01/02 15:04", req.Timestamp)
	if trErr != nil {
		return nil, onet.NewClientError(trErr)
	}

	skipclient := skipchain.NewClient()
	// get last block
	resp, rErr := skipclient.GetUpdateChain(req.Roster, lastKnowID)
	if rErr != nil {
		return nil, rErr
	}
	lastKnowBlock := resp.Update[len(resp.Update)-1]
	lastKnowID = lastKnowBlock.Hash
	// get whole skip chain once
	allResp, alErr := skipclient.GetUpdateChain(req.Roster, lastKnowBlock.GenesisID)
	if alErr != nil {
		return nil, alErr
	}
	for _, block := range allResp.Update {
		log.Lvl4("Test with block:", block)
		// test if data contains the correct (url,timestamp) couple
		var mainPage decenarch.Webstore
		webs, wErr := webstoreCompleteFromBytes(block.Data)
		log.Lvl4("WE HAVE", webs)
		if wErr == nil {
			for _, webpage := range webs {
				tBlock, tbErr := time.Parse("2006/01/02 15:04", webpage.Timestamp)
				if tbErr == nil {
					if webpage.Url == req.Url && (tReq.Equal(tBlock) || tReq.After(tBlock)) {
						mainPage = webpage
						break
					}
				}
			}
		}
		// check if a mainPage was found
		if mainPage.Url != "" {
			finalResp := decenarch.SkipGetDataResponse{
				MainPage: mainPage,
				AllPages: webs,
			}
			return &finalResp, nil
		}
	}

	return nil, onet.NewClientErrorCode(4242, "Could not find block in skipchain")
}

// NewProtocol is called on all nodes of a Tree (except the root, since it is
// the one starting the protocol) so it's the Service that will be called to
// generate the PI on all others node.
// If you use CreateProtocolOnet, this will not be called, as the Onet will
// instantiate the protocol on its own. If you need more control at the
// instantiation of the protocol, use CreateProtocolService, and you can
// give some extra-configuration to your protocol in here.
func (s *SkipService) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3("Decenarch SkipService new protocol event")
	return nil, nil
}

// saves all skipblocks.
func (s *SkipService) save() {
	s.skipstorage.Lock()
	defer s.skipstorage.Unlock()
	err := s.Save(skipstorageID, s.skipstorage)
	if err != nil {
		log.Error("Couldn't save file:", err)
	}
}

// Tries to load the configuration and updates the data in the service
// if it finds a valid config-file.
func (s *SkipService) tryLoad() error {
	s.skipstorage = &skipstorage{}
	if !s.DataAvailable(skipstorageID) {
		return nil
	}
	msg, err := s.Load(skipstorageID)
	if err != nil {
		return err
	}
	var ok bool
	s.skipstorage, ok = msg.(*skipstorage)
	if !ok {
		return errors.New("Data of wrong type")
	}
	return nil
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments.
func newService(c *onet.Context) onet.Service {
	s := &SkipService{
		ServiceProcessor: onet.NewServiceProcessor(c),
		data:             make([]decenarch.Webstore, 0),
		dataChan:         make(chan decenarch.Webstore),
	}
	if err := s.RegisterHandlers(
		s.SkipRootStartRequest,
		s.SkipStartRequest,
		s.SkipStopRequest,
		s.SkipAddDataRequest,
		s.SkipGetDataRequest); err != nil {
		log.ErrFatal(err, "Couldn't register messages")
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
	}
	return s
}

// webstoreExtractAndConvert takes an array of Webstore and do three things:
//    1 extract the useful subset of the data contained in the Webstore
//      to be stored in the skipchain
//    2 convert the extracted data into a []byte format or any format
//      understood by the skipchain API
//    3 if the subset is not all the set, store the Webstore on disk
func webstoreExtractAndConvert(webarray []decenarch.Webstore) ([]byte, error) {
	log.Lvl4("extract and convert webstore")
	b, err := json.Marshal(webarray)
	return b, err
}

func webstoreCompleteFromBytes(data []byte) ([]decenarch.Webstore, error) {
	log.Lvl4("unmarshal webstore - begin")
	var webs []decenarch.Webstore = make([]decenarch.Webstore, 0)
	err := json.Unmarshal(data, &webs)
	if err != nil {
		return nil, err
	}
	log.Lvl4("unmarshal webstore - success")
	return webs, nil
}
