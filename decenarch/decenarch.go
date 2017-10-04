package main

import (
	"os"

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
			Name:      "time",
			Usage:     "measure the time to contact all nodes",
			Aliases:   []string{"t"},
			ArgsUsage: groupsDef,
			Action:    cmdTime,
		},
		{
			Name:      "counter",
			Usage:     "return the counter",
			Aliases:   []string{"c"},
			ArgsUsage: groupsDef,
			Action:    cmdCounter,
		},
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
		{
			Name:      "dummy",
			Usage:     "dummy new command",
			Aliases:   []string{"d"},
			ArgsUsage: groupsDef,
			Action:    dummy,
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

func dummy(c *cli.Context) {
	log.Info("Dummy Command")
}

// Returns the asked website if saved.
func cmdRetrieve(c *cli.Context) (string, error) {
	log.Info("Retrieve command")
	url := c.String("url")
	if url == "" {
		log.Fatal("Please provide an url.")
	}
	group := readGroup(c)
	client := decenarch.NewClient()
	resp, err := client.Retrieve(group.Roster.RandomServerIdentity(), url)
	if err != nil {
		log.Fatal("When asking to retrieve", url, ":", err)
	}
	log.Info("Website", url, "retrieved")
	return resp.Website, nil
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

// Returns the time needed to contact all nodes.
func cmdTime(c *cli.Context) error {
	log.Info("Time command")
	group := readGroup(c)
	client := decenarch.NewClient()
	resp, err := client.Clock(group.Roster)
	if err != nil {
		log.Fatal("When asking the time:", err)
	}
	log.Infof("Children: %d - Time spent: %f", resp.Children, resp.Time)
	return nil
}

// Returns the number of calls.
func cmdCounter(c *cli.Context) error {
	log.Info("Counter command")
	group := readGroup(c)
	client := decenarch.NewClient()
	counter, err := client.Count(group.Roster.RandomServerIdentity())
	if err != nil {
		log.Fatal("When asking for counter:", err)
	}
	log.Info("Number of requests:", counter)
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
