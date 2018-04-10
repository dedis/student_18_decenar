package decenarch

/*
The skipapi.go defines the methods that can be called from the outside. Most
of the methods will take a roster so that the service knows which nodes
it should work with.

This part of the service runs on the client or the app.
*/

import (
	"time"

	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
)

// ServiceName is used for registration on the onet.
const SkipServiceName = "Decenskip"

// SkipClient is a structure to communicate with the Decenskip
// service
type SkipClient struct {
	*onet.Client
}

// NewClient instantiates a new decenarch.Client
func NewSkipClient() *SkipClient {
	return &SkipClient{Client: onet.NewClient(DecenarSuite, SkipServiceName)}
}

// SkipStart starts the infinite skipblocks creations loop on all the conodes.
func (c *SkipClient) SkipStart(r *onet.Roster) (*SkipStartResponse, error) {
	log.Lvl1("SkipStart")
	dstRoot := r.RandomServerIdentity()
	rootResp := &SkipRootStartResponse{}
	err := c.SendProtobuf(dstRoot, &SkipRootStartRequest{Roster: r}, rootResp)
	if err != nil {
		return nil, err
	}
	log.Lvl1("rootResp:", rootResp, "and error:", err)
	resp := &SkipStartResponse{}
	errs := make([]error, 0)
	for _, srv := range r.List {
		time.Sleep(2 * time.Second)
		log.Lvl4("send SkipStartRequest to:", srv)
		resp = &SkipStartResponse{}
		err := c.SendProtobuf(
			srv,
			&SkipStartRequest{Roster: r, Genesis: rootResp.Bloc},
			resp)
		if err != nil {
			errs = append(errs, err)
		}
		log.Lvl4("received SkipStartResponse:", resp, "and error", err)
	}
	if len(errs) > 0 {
		log.Error(errs)
		return nil, errs[0]
	}
	return resp, nil
}

// SkipStop stops the infinite skipblocks creations loop on all the conodes.
func (c *SkipClient) SkipStop(r *onet.Roster) (*SkipStopResponse, error) {
	log.Lvl1("SkipStop")
	resp := &SkipStopResponse{}
	errs := make([]error, 0)
	for _, srv := range r.List {
		err := c.SendProtobuf(srv, &SkipStopRequest{}, resp)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return nil, errs[0]
	}
	return resp, nil
}

// SkipAddData allows to add data to the next block that will be created by the conode.
func (c *SkipClient) SkipAddData(r *onet.Roster, data []Webstore) (*SkipAddDataResponse, error) {
	log.Lvl1("SkipAddData")
	resp := &SkipAddDataResponse{}
	dst := r.RandomServerIdentity()
	err := c.SendProtobuf(dst, &SkipAddDataRequest{Roster: r, Data: data}, resp)
	if err != nil {
		return nil, err
	}
	log.Lvl1("SkipAddData done sucessfully")
	return resp, nil
}

// SkipGetData allow to get the data related to the url at the time given that
// were stored on the skipchain. Time format is "2006/01/02 15:04". url must
// be given with scheme.
func (c *SkipClient) SkipGetData(r *onet.Roster, url string, time string) (*SkipGetDataResponse, error) {
	log.Lvl1("SkipGetData")
	log.Lvl4("API call")
	resp := &SkipGetDataResponse{}
	dst := r.RandomServerIdentity()
	log.Lvl4("Send GetDataRequest to service")
	err := c.SendProtobuf(
		dst,
		&SkipGetDataRequest{
			Roster:    r,
			Url:       url,
			Timestamp: time,
		},
		resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
