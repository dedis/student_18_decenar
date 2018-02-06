/*
Package protocol contains the functions and structure related to the save and
retrieve protocol of the decenarch service.

The protocol has two messages:
	- Announce which is sent from the root down the tree
	- Reply which is sent back up to the root

A simple protocol uses four files:
- struct.go defines the messages sent around
- save.go defines the actions for each message related to the save process
- utils.go defines the structures and functions of ExplicitNode and AnonNode used
in the save process to reach consensus on an html tree without revealing the
original tree itself.
*/
package protocol
