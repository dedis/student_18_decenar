package main

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"encoding/base64"
	urlpkg "net/url"

	decenarch "github.com/dedis/student_18_decenar"
	"golang.org/x/net/html"

	"gopkg.in/dedis/onet.v2/app"

	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/urfave/cli.v1"
)

// TODO: these values should probably go in some config file
// path to the directory where website will be stored for consultation
const (
	cachePath = "/tmp/cocache"
)

func main() {
	log.Info("Start decenarch application")
	cliApp := cli.NewApp()
	cliApp.Name = "decenarch"
	cliApp.Usage = "retrieve static websites"
	cliApp.Version = "0.1"
	groupsDef := "the group-definition-file"
	cliApp.Commands = []cli.Command{
		{
			Name:      "retrieve",
			Usage:     "retrive the website",
			Aliases:   []string{"r"},
			ArgsUsage: groupsDef,
			Action:    cmdRetrieve,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "url, u",
					Usage: "Provide url to retrieve",
				},
				cli.StringFlag{
					Name:  "timestamp, t",
					Usage: "Provide timestamp",
				},
			},
		},
		{
			Name:      "save",
			Usage:     "save the website",
			Aliases:   []string{"s"},
			ArgsUsage: groupsDef,
			Action:    cmdSave,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "url, u",
					Usage: "Provide url to save",
				},
				cli.BoolFlag{
					Name:  "proof, p",
					Usage: "Show proofs for the consensus algorithm",
				},
			},
		},
		{
			Name:      "skipstart",
			Usage:     "start the storing skipchain",
			Aliases:   []string{"k"},
			ArgsUsage: groupsDef,
			Action:    cmdStart,
		},
	}
	cliApp.Flags = []cli.Flag{
		cli.IntFlag{
			Name:  "debug, d",
			Value: 0,
			Usage: "debug-level: 1 for terse, 5 for maximal",
		},
	}
	cliApp.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.Int("debug"))
		return nil
	}
	cliApp.Run(os.Args)
}

// Returns the asked website if saved.
func cmdRetrieve(c *cli.Context) error {
	log.Info("Retrieve command")
	url := c.String("url")
	timestamp := c.String("timestamp")
	if url == "" {
		log.Fatal("Please provide an url with save -u [url] ")
	}
	if timestamp == "" {
		log.Info("It is possible to provide a timestamp with -t [2006/01/02 15:04]")
	}
	group := readGroup(c)
	client := decenarch.NewClient()
	resp, err := client.Retrieve(group.Roster, url, timestamp)
	if err != nil {
		log.Fatal("When asking to retrieve", url, ":", err)
	}
	// save data on local filesystem
	bPage, bErr := base64.StdEncoding.DecodeString(resp.Main.Page)
	if bErr != nil {
		return bErr
	}
	// modify images links
	mbPage, err := changeImgSrc(bPage, resp.Main.Url)
	if err != nil {
		return err
	}
	// store main pag on disk
	p, pErr := storeWebPageOnDisk(resp.Main.Url, mbPage)
	if pErr != nil {
		return pErr
	}
	log.Info("Website", url, "stored in", p)
	for _, adds := range resp.Adds {
		abPage, abErr := base64.StdEncoding.DecodeString(adds.Page)
		if abErr == nil {
			log.Info("Storing", adds.Url)
			_, apErr := storeWebPageOnDisk(adds.Url, abPage)
			if apErr != nil {
				log.Lvl1("An non-fatal error occured:", apErr)
			}
		} else {
			log.Lvl1("An non-fatal error occured:", abErr)
		}
	}
	log.Info("Website sucessfully stored in", p)
	return nil
}

// Saves the asked website and returns an exit state
func cmdSave(c *cli.Context) error {
	log.Info("Save command")
	url := c.String("url")
	if url == "" {
		log.Fatal("Please provide an url.")
	}
	group := readGroup(c)
	client := decenarch.NewClient()
	resp, err := client.Save(group.Roster, url)
	if err != nil {
		log.Fatal("When asking to save", url, ":", err)
	}
	log.Info("Website", url, "saved.", resp)
	if c.Bool("proof") {
		fmt.Println("Proof of the consensu algorithm")
		fmt.Printf("%+v\n", resp.Proof)
	}
	return nil
}

// start DecenArch by starting the skipchain and the DKG protocol
func cmdStart(c *cli.Context) error {
	err := cmdSkipStart(c)
	if err != nil {
		return err
	}
	// give some time to the skipchain for starting
	time.Sleep(1 * time.Second)
	err = cmdDKGStart(c)
	if err != nil {
		return err
	}

	return nil
}

// Start the skipchain that will be responsible to store the websites archived
func cmdSkipStart(c *cli.Context) error {
	log.Info("SkipStart command")
	group := readGroup(c)
	// start the skipchain
	client := decenarch.NewSkipClient()
	resp, err := client.SkipStart(group.Roster)
	if err != nil {
		log.Fatal("When asking to start skipchain", err)
	}
	log.Info("Skipchain started with", resp)
	return nil
}

// start the DKG protocol
func cmdDKGStart(c *cli.Context) error {
	group := readGroup(c)
	client := decenarch.NewClient()
	resp, err := client.Setup(group.Roster)
	if err != nil {
		log.Fatal("When asking to start the DKG protocol", err)
	}
	log.Info("DKG protocol went well with key", resp)
	return nil
}

func readGroup(c *cli.Context) *app.Group {
	if c.NArg() != 1 {
		log.Fatal("Please give the group-file as argument")
	}
	name := c.Args().First()
	f, err := os.Open(name)
	log.ErrFatal(err, "Couldn't open group definition file")
	group, err := app.ReadGroupDescToml(f)
	log.ErrFatal(err, "Error while reading group definition file", err)
	if len(group.Roster.List) == 0 {
		log.ErrFatalf(err, "Empty entity or invalid group defintion in: %s",
			name)
	}
	return group
}

// storeWebPageOnDisk store the data bData on the filesystem under the path:
// $cachePath/<path infer from url>.
// Example: url==http://my.example.ext/folder/file.fext will be stored in
// $cachePath/ext/example/my/folder/file.fext and file.fext will contains bData
func storeWebPageOnDisk(mUrl string, bData []byte) (string, error) {
	folderPath, filePath, err := getFolderAndFilePath(mUrl)
	if err != nil {
		return "", nil
	}
	mkErr := os.MkdirAll(folderPath, os.ModePerm|os.ModeDir)
	if mkErr != nil {
		return "", mkErr
	}
	mainFile, mfErr := os.Create(filePath)
	if mfErr != nil {
		return "", mfErr
	}
	_, writErr := mainFile.Write(bData)
	if writErr != nil {
		return "", writErr
	}
	return filePath, nil
}

func getFolderAndFilePath(url string) (string, string, error) {
	u, err := urlpkg.Parse(url)
	if err != nil {
		return "", "", err
	}
	var urlDir string
	for _, dom := range strings.Split(u.Host, ".") {
		urlDir = dom + "/" + urlDir
	}
	locDir, locFile := path.Split(u.Path)
	if locFile == "" {
		locFile = "index.html"
	}
	folderPath := path.Join(cachePath, urlDir, locDir)
	filePath := path.Join(folderPath, locFile)

	return folderPath, filePath, nil
}

// changeImgSrc iterates over the entire HTML document and changes
// the sources of the images to use the images stored on disk
// when retrieving a web page with deceanrch
func changeImgSrc(bData []byte, url string) ([]byte, error) {
	r := bytes.NewReader(bData)
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}

	// parse and modify html document
	err = changeNodeImgSrc(doc, url)
	if err != nil {
		return nil, err
	}

	// render modified html document
	var b bytes.Buffer
	err = html.Render(&b, doc)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), err
}

// changeNodeImgSrc is an helper function of changeImgSrc and it changes the
// source of a given HTML node from internet address to local address, if
// needed
func changeNodeImgSrc(n *html.Node, url string) error {
	var err error
	if n.Type == html.ElementNode && n.Data == "img" {
		for i, a := range n.Attr {
			if a.Key == "src" {
				newSrc := ""
				if strings.Contains(a.Val, "http") {
					_, newSrc, err = getFolderAndFilePath(a.Val)
				} else {
					_, newSrc, err = getFolderAndFilePath(url + "/" + a.Val)
				}
				if err != nil {
					return err
				}
				log.Lvlf4("Imgage source changed from %v to %v", a.Val, newSrc)
				n.Attr[i].Val = newSrc
				break
			}
		}

	}

	// recursively change children
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		changeNodeImgSrc(c, url)
	}

	return nil
}
