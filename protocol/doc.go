/*
Package protocol contains the functions and structure related to the save and
retrieve protocol of the decenarch service.

The protocol has two messages:
	- Announce which is sent from the root down the tree
	- Reply which is sent back up to the root

A simple protocol uses four files:
- struct.go defines the messages sent around
- save.go defines the actions for each message related to the save process
- retrieve.go defines the actions for each message related to the retieve process
- utils.go defines the structures and functions of ExplicitNode and AnonNode used
in the save process to reach consensus on an html tree without revealing the
original tree itself.
- protocol_test.go tests the protocol in a local test
- simulation.go tests the protocol on distant platforms like deterlab
*/
package protocol
