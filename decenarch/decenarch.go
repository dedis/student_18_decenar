package main

import (
	"os"
	"path"
	"strings"

	"encoding/base64"
	urlpkg "net/url"

	decenarch "github.com/dedis/student_18_decenar"

	"github.com/dedis/onet/app"

	"github.com/dedis/onet/log"
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
			},
		},
		{
			Name:      "skipstart",
			Usage:     "start the storing skipchain",
			Aliases:   []string{"k"},
			ArgsUsage: groupsDef,
			Action:    cmdSkipStart,
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
	p, pErr := storeWebPageOnDisk(resp.Main.Url, bPage)
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
	return nil
}

// Start the skipchain that will be responsible to store the websites archived
func cmdSkipStart(c *cli.Context) error {
	log.Info("SkipStart command")
	group := readGroup(c)
	client := decenarch.NewSkipClient()
	resp, err := client.SkipStart(group.Roster)
	if err != nil {
		log.Fatal("When asking to start skipchain", err)
	}
	log.Info("Skipchain started with", resp)
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
	pUrl, puErr := urlpkg.Parse(mUrl)
	if puErr != nil {
		return "", puErr
	}
	var urlDir string
	for _, dom := range strings.Split(pUrl.Host, ".") {
		urlDir = dom + "/" + urlDir
	}
	locDir, locFile := path.Split(pUrl.Path)
	if locFile == "" {
		locFile = "index.html"
	}
	mkErr := os.MkdirAll(path.Join(cachePath, urlDir, locDir), os.ModePerm|os.ModeDir)
	if mkErr != nil {
		return "", mkErr
	}
	mainFile, mfErr := os.Create(path.Join(cachePath, urlDir, locDir, locFile))
	if mfErr != nil {
		return "", mfErr
	}
	_, writErr := mainFile.Write(bData)
	if writErr != nil {
		return "", writErr
	}
	return path.Join(cachePath, urlDir, locDir, locFile), nil
}
