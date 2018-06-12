package decenarch

/*
The api.go defines the methods that can be called from the outside. Most
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
const ServiceName = "Decenarch"
const StatTimeFormat = "2006/01/02 15:04:05.0000"

// Client is a structure to communicate with the Decenarch
// service
type Client struct {
	*onet.Client
}

// NewClient instantiates a new decenarch.Client
func NewClient() *Client {
	return &Client{Client: onet.NewClient(Suite, ServiceName)}
}

// Setup will setup everything is needed for DecenArch
func (c *Client) Setup(r *onet.Roster) (*SetupResponse, error) {
	dst := r.List[0]
	resp := &SetupResponse{}
	err := c.SendProtobuf(dst, &SetupRequest{Roster: r}, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Save will record the website requested in the conodes
func (c *Client) Save(r *onet.Roster, url string) (*SaveResponse, error) {
	dst := r.List[0]
	log.Lvl4("Sending message to", dst)
	resp := &SaveResponse{Times: make([]string, 0)}
	resp.Times = append(resp.Times, "genstart;"+time.Now().Format(StatTimeFormat))
	err := c.SendProtobuf(dst, &SaveRequest{url, r}, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Retrieve will send the website requested to the client
func (c *Client) Retrieve(r *onet.Roster, url string, timestamp string) (*RetrieveResponse, error) {
	// if no timestamp is given, take 'now as timestamp'
	if timestamp == "" {
		t := time.Now()
		timestamp = t.Format("2006/01/02 15:04")
	}
	resp := &RetrieveResponse{}
	dst := r.RandomServerIdentity()
	err := c.SendProtobuf(
		dst,
		&RetrieveRequest{Roster: r, Url: url, Timestamp: timestamp},
		resp)
	if err != nil {
		return nil, err
	}
	log.Info("Page", resp.Main.Url, "sucessfully retrieved!")
	return resp, nil
}
