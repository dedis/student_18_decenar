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
	"strings"

	"net/http"
	"net/url"

	"golang.org/x/net/html"

	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func init() {
	network.RegisterMessage(SaveAnnounce{})
	network.RegisterMessage(SaveReply{})
	onet.GlobalProtocolRegister(SaveName, NewSaveProtocol)
}

// Template just holds a message that is passed to all children. It
// also defines a channel that will receive the number of children. Only the
// root-node will write to the channel.
type SaveMessage struct {
	*onet.TreeNodeInstance
	Url     string
	Errs    []error
	ChanUrl chan string
	RealUrl chan string
	FsPath  chan string
}

// NewSaveProtocol initialises the structure for use in one round
func NewSaveProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl5("Creating NewSaveProtocol")
	t := &SaveMessage{
		TreeNodeInstance: n,
		Url:              "",
		ChanUrl:          make(chan string),
		RealUrl:          make(chan string),
		FsPath:           make(chan string),
	}
	for _, handler := range []interface{}{t.HandleAnnounce, t.HandleReply} {
		if err := t.RegisterHandler(handler); err != nil {
			return nil, errors.New("couldn't register handler: " + err.Error())
		}
	}
	return t, nil
}

// Start sends the Announce-message to all children
func (p *SaveMessage) Start() error {
	log.Lvl3("Starting SaveMessage")
	saveUrl := p.Url
	return p.HandleAnnounce(StructSaveAnnounce{
		p.TreeNode(),
		SaveAnnounce{Url: saveUrl, Hash: []byte{byte(0)}},
	})
}

// HandleAnnounce is the first message and is used to send an ID that
// is stored in all nodes.
func (p *SaveMessage) HandleAnnounce(msg StructSaveAnnounce) error {
	log.Lvl4("Handling", p)
	p.Url = msg.SaveAnnounce.Url
	err := p.SaveUrl(msg.SaveAnnounce.Url)
	if err != nil {
		urlFail := msg.SaveAnnounce.Url
		log.Lvl1("Impossible to save", urlFail, ":", err)
	}
	if !p.IsLeaf() {
		// If we have children, send the same message to all of them
		p.SendToChildren(&msg.SaveAnnounce)
	} else {
		p.ChanUrl <- msg.SaveAnnounce.Url
		// If we're the leaf, start to reply
		resp := StructSaveReply{
			p.TreeNode(),
			SaveReply{Hash: []byte{byte(0)}, Errs: []error{err}},
		}
		p.HandleReply([]StructSaveReply{resp})
	}
	return nil
}

// HandleReply is the message going up the tree and holding a counter
// to verify the number of nodes.
func (p *SaveMessage) HandleReply(reply []StructSaveReply) error {
	defer p.Done()
	log.Lvl4("Handling Save Reply")
	var AllErrs []error
	for _, r := range reply {
		for _, erro := range r.Errs {
			AllErrs = append(AllErrs, erro)
		}
	}
	log.Lvl3(p.ServerIdentity().Address, "is done with collecting errors")
	if !p.IsRoot() {
		log.Lvl3("Sending to parent")
		return p.SendTo(p.Parent(), &SaveReply{Hash: []byte{byte(0)}, Errs: AllErrs})
	}
	p.Errs = AllErrs
	log.Lvl3("Root-node is done")
	return nil
}

// ExtractPageExternalLinks take html webpage as a buffer and extract the
// links to the additional ressources needed to display the webpage.
func ExtractPageExternalLinks(page *bytes.Buffer) []string {
	log.Lvl4("Parsing parent page")
	var links []string
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
		// check for relevant ressources
		if tok == html.StartTagToken {
			if string(tagName) == "link" && attributeMap["rel"] == "stylesheet" {
				links = append(links, attributeMap["href"])
			}
		} else if tok == html.SelfClosingTagToken {
			if string(tagName) == "img" {
				links = append(links, attributeMap["src"])
			}
		}
	}
	return links
}

// GetParentfileHierarchy take a pointer to an url.URL structure and return
// the name of the file requested and the path to it inferred from the url.
// Example: domain.ext/folder would become (index.html, ext/domain/folder)
func GetParentfileHierarchy(pUrl *url.URL) (string, string) {
	log.Lvl4("Creating folders for", pUrl)
	var bottomPath string
	var folderHierarchy []string = strings.Split(pUrl.Hostname(), ".")
	for i := len(folderHierarchy) - 1; i >= 0; i-- {
		bottomPath += folderHierarchy[i] + "/"
	}
	if string(pUrl.Path[0]) == "/" {
		// if a path is already in the url, then remove first "/" to avoid "//"
		bottomPath += pUrl.Path[1:]
	} else {
		bottomPath += pUrl.Path
	}

	var file string
	if string(bottomPath[len(bottomPath)-1]) != "/" {
		tmpFileHierarchy := strings.Split(bottomPath, "/")
		bottomPath = strings.Join(tmpFileHierarchy[:len(tmpFileHierarchy)-1], "/") + "/"
	} else {
		file = "index.html"
	}
	return file, bottomPath
}

// SaveFile saves the data given in the filesystem in the place indicated by
// the path. It creates the file but not the folders.
func SaveFile(path string, data io.Reader) error {
	log.Lvl4("Saving", path)
	creaFile, creaErr := os.Create(path)
	if creaErr != nil {
		return creaErr
	}
	defer creaFile.Close()
	_, copyErr := io.Copy(creaFile, data)
	if copyErr != nil {
		return copyErr
	}
	return nil
}

// CreateAdditionalRessourceFolders create a folder hierarchy on the computer
// using a reference path (parentPath) and a relative path (relativePath).
// Note that if the parentPath is relative, the result will be relative too.
func CreateAdditionalRessourceFolders(parentPath string, relativePath string) error {
	log.Lvl4("Creating folders for", parentPath, relativePath)
	path := parentPath
	subfolders := strings.Split(relativePath, "/")
	subfolders = subfolders[:len(subfolders)-1]
	for _, sub := range subfolders {
		path += sub + "/"
	}
	mkErr := os.MkdirAll(path, os.ModePerm|os.ModeDir)
	return mkErr
}

// GetAdditionalRessource create a usable url to retrieve the additional ressource
func GetAdditionalRessource(parentUrl *url.URL, link string) (*http.Response, error) {
	log.Lvl4("Gettting link: ", link)
	prefix := parentUrl.Scheme + "://" + parentUrl.Host + parentUrl.Path
	return http.Get(prefix + link)
}

// SaveUrl is the function called when a SaveRequest is received.
func (p *SaveMessage) SaveUrl(urlToSave string) error {
	log.Lvl4("Saving website on system")
	getResp, getErr := http.Get(urlToSave)
	if getErr != nil {
		// fill channel with dummy values to avoid service deadlock
		p.RealUrl <- ""
		p.FsPath <- ""
		return getErr
	}
	defer getResp.Body.Close()
	urlStruct, urlErr := url.Parse(getResp.Request.URL.String())
	if urlErr != nil {
		// fill channel with dummy values to avoid service deadlock
		p.RealUrl <- ""
		p.FsPath <- ""
		return urlErr
	}
	p.RealUrl <- getResp.Request.URL.String()
	// we create two buffers to record the page and extract external ressources
	var pageBuffer bytes.Buffer
	pageReader := io.TeeReader(getResp.Body, &pageBuffer)

	// we record parent file
	parentFile, parentFolder := GetParentfileHierarchy(urlStruct)
	mkErr := os.MkdirAll(parentFolder, os.ModePerm|os.ModeDir)
	if mkErr != nil {
		// fill channel with dummy values to avoid service deadlock
		p.FsPath <- ""
		return mkErr
	}
	fileErr := SaveFile(parentFolder+parentFile, pageReader)
	if fileErr != nil {
		// fill channel with dummy values to avoid service deadlock
		p.FsPath <- ""
		return fileErr
	}
	p.FsPath <- parentFolder + parentFile
	// we record additional ressources
	additionalLinks := ExtractPageExternalLinks(&pageBuffer)
	for _, link := range additionalLinks {
		mkErr = CreateAdditionalRessourceFolders(parentFolder, link)
		if mkErr != nil {
			return mkErr
		}
		addResp, addErr := GetAdditionalRessource(urlStruct, link)
		defer addResp.Body.Close()
		if addErr != nil {
			return addErr
		} else if addResp.StatusCode != 200 {
			log.Lvl3(addResp.StatusCode, ": Cannot get", link)
			continue
		}
		fileErr = SaveFile(parentFolder+link, addResp.Body)
		if fileErr != nil {
			return fileErr
		}
	}

	return nil
}
