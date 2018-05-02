package decenarch

/*
The skipapi.go defines the methods that can be called from the outside. Most
of the methods will take a roster so that the service knows which nodes
it should work with.

This part of the service runs on the client or the app.
*/

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	ftcosiprotocol "gopkg.in/dedis/cothority.v2/ftcosi/protocol"
	"gopkg.in/dedis/cothority.v2/skipchain"
	"gopkg.in/dedis/kyber.v2/sign/cosi"
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"

	decenarch "github.com/dedis/student_18_decenar"
)

// ServiceName is used for registration on the onet.
const SkipServiceName = "Decenskip"

// SkipClient is a structure to communicate with the Decenskip
// service
type SkipClient struct {
	*skipchain.Client
	Policy *cosi.ThresholdPolicy
}

// NewClient instantiates a new decenarch.Client
func NewSkipClient(threshold int) *SkipClient {
	return &SkipClient{Client: skipchain.NewClient(), Policy: cosi.NewThresholdPolicy(threshold)}
}

// SkipStart starts the infinite skipblocks creations loop on all the conodes.
func (c *SkipClient) SkipStart(r *onet.Roster) (*skipchain.SkipBlock, error) {
	log.Lvl1("SkipStart")
	return c.CreateGenesis(r, 2, 2, skipchain.VerificationStandard, nil, nil)
}

// SkipAddData allows to add data to the next block that will be created by the conode.
func (c *SkipClient) SkipAddData(genesisID skipchain.SkipBlockID, r *onet.Roster, data []decenarch.Webstore) (*skipchain.StoreSkipBlockReply, error) {
	log.Lvl1("SkipAddData")

	// verify signatures of all the pages before adding the data to the
	// skipchain
	for _, d := range data {
		bd, err := base64.StdEncoding.DecodeString(d.Page)
		if err != nil {
			return nil, err
		}
		vsErr := cosi.Verify(
			ftcosiprotocol.EdDSACompatibleCosiSuite,
			r.Publics(),
			bd,
			d.Sig.Signature,
			c.Policy)
		if vsErr != nil {
			return nil, vsErr
		}
	}

	// marshal data
	dataBytes, err := webstoreExtractAndConvert(data)
	if err != nil {
		return nil, err
	}

	// compress datai using gzip
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	_, err = w.Write(dataBytes)
	if err != nil {
		return nil, err
	}
	err = w.Close()
	if err != nil {
		return nil, err
	}

	// get genesis block
	genesis, err := c.GetSingleBlock(r, genesisID)
	if err != nil {
		return nil, err
	}

	// target is a skipblock, where new skipblock is going to be added
	// after it, but not necessarily immediately after it.  The caller
	// should use the genesis skipblock as the target.
	return c.StoreSkipBlock(genesis, r, b.Bytes())
}

// SkipGetData allow to get the data related to the url at the time given that
// were stored on the skipchain. Time format is "2006/01/02 15:04". url must
// be given with scheme.
func (c *SkipClient) SkipGetData(latestID skipchain.SkipBlockID, r *onet.Roster, url string, timeString string) (*SkipGetDataResponse, error) {
	// get real url, since the page is stored with the real url and if we
	// don't use it we risk to miss the block because of a missing slash o
	// a redirect
	getResp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer getResp.Body.Close()
	realUrl := getResp.Request.URL.String()

	// parse timestamp
	tReq, err := time.Parse("2006/01/02 15:04", timeString)
	if err != nil {
		return nil, err
	}

	// get latest block
	block, err := c.GetSingleBlock(r, latestID)

	// iterate until we find the right block
	notFound := true

	for notFound {
		// Index == 0 -> genesis-block.
		// Since we don't store data in the genesis block, we are sure
		// that we tested all the possible blocks and we don't have the
		// website
		if block.Index == 0 {
			return nil, errors.New("Could not find block in skipcain")
		}

		log.Lvl4("Test with block:", block)

		// decompress data stored in block
		rData := bytes.NewReader(block.Data)
		rz, err := gzip.NewReader(rData)
		if err != nil {
			return nil, err
		}
		decompressedData, err := ioutil.ReadAll(rz)
		if err != nil {
			return nil, err
		}

		// test if data contains the correct (url,timestamp) couple
		webs, err := webstoreCompleteFromBytes(decompressedData)
		if err != nil {
			return nil, err
		}
		log.Lvl4("WE HAVE", webs)

		// iterate over the webpages present in the block to look for
		// the given url
		for _, webpage := range webs {
			tBlock, err := time.Parse("2006/01/02 15:04", webpage.Timestamp)
			if err != nil {
				fmt.Println("Nel parsing")
				return nil, err
			}
			if webpage.Url == realUrl && (tReq.Equal(tBlock) || tReq.After(tBlock)) {
				finalResp := SkipGetDataResponse{
					MainPage: webpage,
					AllPages: webs,
				}
				notFound = true
				return &finalResp, nil

			}
		}

		// go to previous block
		block, err = c.GetSingleBlock(r, block.BackLinkIDs[0])
		if err != nil {
			fmt.Printf("Nel previsou")
			return nil, err
		}

	}

	return nil, errors.New("Could not find block in skipchain")
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
