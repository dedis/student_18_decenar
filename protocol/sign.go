package protocol

import (
	"gopkg.in/dedis/onet.v2"
	"gopkg.in/dedis/onet.v2/log"
	"gopkg.in/dedis/onet.v2/network"

	ftcosiprotocol "gopkg.in/dedis/cothority.v2/ftcosi/protocol"
)

const NameSign = "Sign"
const NameSubSign = "Sub" + NameSign

func init() {
	network.RegisterMessages(ftcosiprotocol.Announcement{}, ftcosiprotocol.Commitment{}, ftcosiprotocol.Challenge{}, ftcosiprotocol.Response{}, ftcosiprotocol.Stop{})
	onet.GlobalProtocolRegister(NameSign, NewSignProtocol)
	onet.GlobalProtocolRegister(NameSubSign, NewSubSignProtocol)
}

func NewSignProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("Creating NewSignProtocol")
	vf := func(a, b []byte) bool { return true }
	return ftcosiprotocol.NewFtCosi(n, vf, NameSubSign, ftcosiprotocol.EdDSACompatibleCosiSuite)
}

func NewSubSignProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	log.Lvl4("Creating NewSubSignProtocol")
	vf := func(a, b []byte) bool { return true }
	return ftcosiprotocol.NewSubFtCosi(n, vf, ftcosiprotocol.EdDSACompatibleCosiSuite)
}
