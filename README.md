This repository contains the implementation of the Decentralized Internet Archive 2.0
realized in the context of a Master Thesis at the DEDIS laboratory at EPFL.

The implementation contained in this branch assume honest-but-curious conodes, i.e. a conode correctly follows the protocols and only try to learn the content of the data retrieved from other conodes. The implementation for mailicious conodes can be found in the master branch. For more information about the 

This repository is based on the DEDIS [cothority template](https://github.com/dedis/cothority_template).

**The Decentralized Internet Archive is highly experimental and still a prototype and should not be considered secure or reliable for real-world purposes.**

## Documentation

See the report of the Master thesis.

## Installation

```go get github.com/dedis/student_18_decenar``` and then install all the needed dependencies.

## Example

To test the archive installation, you can do the following:
* ```cd student_18_decenar/``` (go to the repository folder)
* ```go install ./conode``` (install the conode module)
* ```go install ./decenarch``` (install the decenarch module)
* create a cothority with the number of nodes you want (see the [cothority repository](https://github.com/dedis/cothority))
* ```conode -c /path/to/conode/private.toml server``` for each conode (run the local conode)
* ```decenarch k /path/to/general/public.toml``` (start the skipchain routine)
* ```decenarch s -u "https://url.of.your.choice" /path/to/general/public.toml``` (save a web page)
* ```decenarch r -u "https://url.of.your.choice" /path/to/general/public.toml``` (retrieve the saved web page
* The last line in the terminal should indicate where the webpage was stored on your filesystem

## License

All repositories for the cothority are double-licensed under a 
GNU/AGPL 3.0 and a commercial license. If you want to have more information, 
contact us at dedis@epfl.ch.

