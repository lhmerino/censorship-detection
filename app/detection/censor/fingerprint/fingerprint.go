package fingerprint

type Fingerprint interface {
	// Does this specific fingerprint believe that the censor was involved in this connection
	CensorshipTriggered() bool
}
