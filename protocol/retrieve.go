package protocol

/*
The `NewProtocol` method is used to define the protocol and to register
the handlers that will be called if a certain type of message is received.
The handlers will be treated according to their signature.

The protocol-file defines the actions that the protocol needs to do in each
step. The root-node will call the `Start`-method of the protocol. Each
node will only use the `Handle`-methods, and not call `Start` again.
*/

import (
	"bytes"
	"errors"
	"io"
	"os"

	"io/ioutil"
	"net/url"

	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func init() {
	network.RegisterMessage(RetrieveAnnounce{})
	network.RegisterMessage(RetrieveReply{})
	onet.GlobalProtocolRegister(RetrieveName, NewRetrieveProtocol)
}

// RetrieveMessage just holds a message that is passed to all children. It
// also defines a channel that will receive the number of children. Only the
// root-node will write to the channel.
type RetrieveMessage struct {
	*onet.TreeNodeInstance
	Url        string
	ParentPath chan string
	Data       chan map[string][]byte
}

// NewProtocol initialises the structure for use in one round
func NewRetrieveProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	t := &RetrieveMessage{
		TreeNodeInstance: n,
		ParentPath:       make(chan string),
		Data:             make(chan map[string][]byte),
	}
	for _, handler := range []interface{}{t.HandleAnnounce, t.HandleReply} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}
	return t, nil
}

// Start sends the Announce-message to all children
func (p *RetrieveMessage) Start() error {
	log.Lvl3("Starting RetrieveMessage")
	return p.HandleAnnounce(StructRetrieveAnnounce{
		p.TreeNode(),
		RetrieveAnnounce{p.Url}})
}

// HandleAnnounce is the first message and is used to send an ID that
// is stored in all nodes.
func (p *RetrieveMessage) HandleAnnounce(msg StructRetrieveAnnounce) error {
	log.Lvl4("Handling", p)
	//if !p.IsLeaf() {
	//	// If we have children, send the same message to all of them
	//	p.SendToChildren(&msg.RetrieveAnnounce)
	//} else {
	//	// If we're the leaf, start to reply
	//	p.HandleReply(nil)
	//}
	var dataMap = make(map[string][]byte)
	structUrl, structErr := url.Parse(p.Url)
	if structErr != nil {
		log.Fatal("Cannot parse", p.Url)
		return structErr
	}
	parentFile, parentDir := GetParentfileHierarchy(structUrl)
	file, fErr := os.Open(parentDir + parentFile)
	if fErr != nil {
		log.Fatal("Cannot open", parentDir+parentFile)
		return fErr
	}
	defer file.Close()
	var pageBuffer bytes.Buffer
	pageReader := io.TeeReader(file, &pageBuffer)
	pData, pErr := ioutil.ReadAll(pageReader)
	if pErr != nil {
		log.Fatal("Cannot read", parentDir+parentFile)
		return pErr
	}
	dataMap[parentDir+parentFile] = pData
	additionalLink := ExtractPageExternalLinks(&pageBuffer)
	for _, link := range additionalLink {
		var aPath string
		if string(link[0]) != "/" {
			aPath = parentDir + link
		} else {
			aPath = link
		}
		aFile, aErr := os.Open(aPath)
		if aErr != nil {
			log.Lvl3("Cannot open", aPath)
			continue
		}
		aData, aErr := ioutil.ReadAll(aFile)
		aFile.Close()
		if aErr != nil {
			log.Lvl3("Cannot read", aPath)
			aFile.Close()
			continue
		}
		dataMap[aPath] = aData
	}

	var resp StructRetrieveReply = StructRetrieveReply{
		p.TreeNode(),
		RetrieveReply{Data: dataMap},
	}

	// send informations requested by the service via the channels
	p.ParentPath <- parentDir + parentFile
	p.Data <- dataMap

	p.HandleReply([]StructRetrieveReply{resp})
	return nil
}

// HandleReply is the message going up the tree and holding a counter
// to verify the number of nodes.
func (p *RetrieveMessage) HandleReply(reply []StructRetrieveReply) error {
	defer p.Done()

	if !p.IsRoot() {
		log.Lvl3("Sending to parent")
		return p.SendTo(p.Parent(), &RetrieveReply{})
	}
	log.Lvl3("Root node is done")
	return nil
}
