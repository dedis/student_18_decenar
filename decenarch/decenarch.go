package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	decenarch "github.com/nblp/decenarch"

	"gopkg.in/dedis/onet.v1/app"

	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/urfave/cli.v1"
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
	}
	cliApp.Flags = []cli.Flag{
		app.FlagDebug,
	}
	cliApp.Before = func(c *cli.Context) error {
		log.SetDebugVisible(c.Int("debug"))
		return nil
	}
	cliApp.Run(os.Args)
}

// cacheData save data on file system using the path provided
func cacheData(path string, data []byte) error {
	mErr := os.MkdirAll(filepath.Dir(path), os.ModePerm|os.ModeDir)
	if mErr != nil {
		log.Lvl3("Error while creating folders for", path)
		return mErr
	}
	file, fErr := os.Create(path)
	if fErr != nil {
		log.Lvl3("Error while create file", path)
		return fErr
	}
	defer file.Close()
	_, cErr := io.Copy(file, bytes.NewReader(data))
	if cErr != nil {
		log.Lvl3("Error while copying data in", path)
		return cErr
	}
	return nil
}

// Returns the asked website if saved.
func cmdRetrieve(c *cli.Context) error {
	log.Info("Retrieve command")
	url := c.String("url")
	if url == "" {
		log.Fatal("Please provide an url with save -u [url] ")
	}
	group := readGroup(c)
	client := decenarch.NewClient()
	resp, err := client.Retrieve(group.Roster, url)
	if err != nil {
		log.Fatal("When asking to retrieve", url, ":", err)
	}
	// save the website in filesystem's cache
	prefix := decenarch.CachePath
	for path, data := range resp.Data {
		if string(path[0]) != "/" {
			prefix += "/"
		}
		err := cacheData(prefix+path, data)
		if err != nil {
			log.Lvl3("Impossible to cache", path, ":", err)
		}
	}
	log.Info("Website", url, "retrieved in", prefix+resp.Website)
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
