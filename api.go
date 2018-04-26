package decenarch

/*
The api.go defines the methods that can be called from the outside. Most
of the methods will take a roster so that the service knows which nodes
it should work with.

This part of the service runs on the client or the app.
*/

import (
	"strconv"
	"strings"
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
	dst := r.RandomServerIdentity()
	resp := &SetupResponse{}
	err := c.SendProtobuf(dst, &SetupRequest{Roster: r}, resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Save will record the website requested in the conodes
func (c *Client) Save(r *onet.Roster, url string) (*SaveResponse, error) {
	dst := r.RandomServerIdentity()
	log.Lvl4("Sending message to", dst)
	resp := &SaveResponse{Times: make([]string, 0)}
	resp.Times = append(resp.Times, "genstart;"+time.Now().Format(StatTimeFormat))
	err := c.SendProtobuf(dst, &SaveRequest{url, r}, resp)
	if err != nil {
		return nil, err
	}
	resp.Times = append(resp.Times, "genend;"+time.Now().Format(StatTimeFormat))
	log.Lvl1("ttime: begin")
	csvMap := make(map[string]string)
	for _, t := range resp.Times {
		tabl := strings.Split(t, ";")
		log.Lvl1("ttime:", tabl)
		csvMap[tabl[0]] = tabl[1]
	}
	log.Lvl1(csvMap)
	csvLine := "web,numConodes,numHtmlNodes,start,reqS,cosi,adds,skip\n"
	// web, numConodes
	csvLine += url + "," + csvMap["numbrNodes"] + ","
	// CBF parameters
	csvLine += csvMap["mCBF"] + ","
	csvLine += csvMap["kCBF"] + ","
	// start (always == 0)
	t1, _ := time.Parse(StatTimeFormat, csvMap["genstart"])
	t2, _ := time.Parse(StatTimeFormat, csvMap["genstart"])
	d := t1.Sub(t2)
	csvLine += strconv.Itoa(int(d.Nanoseconds())) + ","
	// reqS
	t1, _ = time.Parse(StatTimeFormat, csvMap["saveCosiStart"])
	t2, _ = time.Parse(StatTimeFormat, csvMap["genstart"])
	d = t1.Sub(t2)
	csvLine += strconv.Itoa(int(d.Nanoseconds())) + ","
	// cosi
	t1, _ = time.Parse(StatTimeFormat, csvMap["sameForAddStart"])
	t2, _ = time.Parse(StatTimeFormat, csvMap["saveCosiStart"])
	d = t1.Sub(t2)
	csvLine += strconv.Itoa(int(d.Nanoseconds())) + ","
	// adds
	t1, _ = time.Parse(StatTimeFormat, csvMap["skipAddStart"])
	t2, _ = time.Parse(StatTimeFormat, csvMap["sameForAddStart"])
	d = t1.Sub(t2)
	csvLine += strconv.Itoa(int(d.Nanoseconds())) + ","
	// skip
	t1, _ = time.Parse(StatTimeFormat, csvMap["genend"])
	t2, _ = time.Parse(StatTimeFormat, csvMap["skipAddStart"])
	d = t1.Sub(t2)
	csvLine += strconv.Itoa(int(d.Nanoseconds()))
	log.Lvl1(csvLine)
	log.Lvl1("ttime: end")
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
