This repository contains the implementation of the Decentralized Internet Archive
realized in the context of a Master Thesis at the DEDIS laboratory at EPFL.

This repository is based on the DEDIS [cothority template](https://github.com/dedis/cothority_template).
It is highly experimental and still a prototype and should not be considered
secure or reliable for real-world purposes.

## Documentation

This project is related to an EPFL Master Thesis report which can be used as
a documentation. Plancherel Nicolas, Decentralized Internet Archive, EPFL 2018.
You can found it in the doc/ folder.

More documentation and examples can be found at:
- To run and use a conode, have a look at 
	[Cothority Node](https://github.com/dedis/cothority/wiki)
	with examples of protocols, services and apps

## Installation

* Install a working go environment
* ```go get -u https://github.com/dedis/student_17_decenar```
* Install the dependencies (please note that the following list may be incomplete and/or redundant):
    * "gopkg.in/dedis/onet.v1"
    * "gopkg.in/dedis/onet.v1/log"
    * "gopkg.in/dedis/cothority.v1/cosi/service"
    * "gopkg.in/dedis/onet.v1/crypto"
    * "gopkg.in/dedis/onet.v1/network"
    * "gopkg.in/dedis/cothority.v1/skipchain"
    * "gopkg.in/dedis/crypto.v0/abstract"
    * "gopkg.in/dedis/crypto.v0/cosi"
    * "gopkg.in/dedis/onet.v1/app"
    * "gopkg.in/urfave/cli.v1"
    * "golang.org/x/net/html"
    * "encoding/base64"
    * "encoding/json"
    * "net/url"
    * "net/http"
    * "bytes"
    * "errors"
    * "io/ioutil"
    * "regexp"
    * "sort"
    * "strings"



## Example

To test the archive installation, you can do the following:
* ```cd student_17_decenar/``` (go to the repository folder)
* ```go install ./conode``` (install the conode module)
* ```go install ./decenarch``` (install the decenarch module)
* create a cothority with the number of nodes you want (see the [cothority repository](https://github.com/dedis/cothority))
* ```conode server -c /path/to/conode/private.toml``` for each conode (run the local conode)
* ```decenarch k /path/to/general/public.toml``` (start the skipchain routine)
* ```decenarch s -u "https://url.of.your.choice" /path/to/general/public.toml``` (save a web page)
* ```decenarch r -u "https://url.of.your.choice" /path/to/general/public.toml``` (retrieve the saved web page
* The last line in the terminal should indicate where the webpage was stored on your filesystem
## License

All repositories for the cothority are double-licensed under a 
GNU/AGPL 3.0 and a commercial license. If you want to have more information, 
contact us at dedis@epfl.ch.

