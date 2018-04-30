package protocol

import "github.com/dedis/student_18_decenar/lib"

type VerificationData struct {
	Leaves         []string
	CompleteProofs lib.CompleteProofs
}
