package fingerprint

import (
	"breakerspace.cs.umd.edu/censorship/measurement/detection/shared"
)

type Fingerprint interface {
	shared.MainInterface
	shared.ProcessPacketInterface

	// Does this specific fingerprint believe that the censor was involved in this connection
	CensorshipTriggered() bool
}
