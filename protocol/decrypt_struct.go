package protocol

import (
	"github.com/dedis/student_18_decenar/lib"
	"gopkg.in/dedis/kyber.v2"
	"gopkg.in/dedis/onet.v2"
)

// PromptDecrypt is sent from node to node prompting the receiver to perform
// their respective partial decryption of the last mix.
type PromptDecrypt struct {
	EncryptedCBFSet *lib.CipherVector
}

// MessagePromptDecrypt is a wrapper around PromptDecrypt.
type MessagePromptDecrypt struct {
	*onet.TreeNode
	PromptDecrypt
}

type SendPartial struct {
	Partial []kyber.Point
}

type MessageSendPartial struct {
	*onet.TreeNode
	SendPartial
}
