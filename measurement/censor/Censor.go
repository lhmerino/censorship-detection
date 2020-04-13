package censor

type Interface interface {
	ProcessCensor()
}

type Censor struct {
	Interface
}
