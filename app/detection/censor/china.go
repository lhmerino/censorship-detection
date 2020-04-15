package censor

type China struct {
	Censor
}

func NewChina() *China {
	return &China{}
}

func (c China) GetName() string {
	return "China"
}
