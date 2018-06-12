This repository contains the implementation of DecenArch, a decentralized system for privacy-conscious Internet archiving against censorship. This project is realized in the context of a Master Thesis at the DEDIS laboratory at EPFL.

**DecenArch is highly experimental and still a prototype and should not be considered secure or reliable for real-world purposes.**

## Documentation

The Master Thesis report provides the documentation for the project.  
To run and use a conode, have a look at [Cothority Node](https://github.com/dedis/cothority/wiki) with examples of protocols, services and apps. 

## Installation

* Install and set up a Go working environment according to https://golang.org/doc/install. DecenArch has been developed and tested with Go version 1.10.3.
* Get the last version of DecenArch by running: ```go get -u https://github.com/dedis/student_18_decenar```
* Move in the project directory: ```cd $(go env GOPATH)/src/github.com/dedis/student_18_decenar```
* Recursively get all the dependencies: ```go get -d ./...```

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
* The last line in the terminal indicates where the webpage was stored on your filesystem

## Credits

The virst version of DecenArch, quite different from this one, was developed by [Nicolas Plancherel](https://github.com/nblp) and is available here: https://github.com/dedis/student_17_decenar.

## License

All repositories for the cothority are double-licensed under a 
GNU/AGPL 3.0 and a commercial license. If you want to have more information, 
contact us at dedis@epfl.ch.

