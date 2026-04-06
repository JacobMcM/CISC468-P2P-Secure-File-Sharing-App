package msgs

import "GoClient/discovery"

type Page int

const (
	PageHome Page = iota
	PageMenu
	PageDetail
	PageFiles
)

type NavigateMsg struct {
	Target  Page
	Payload any
}

type PeerUpdateMsg []*discovery.Peer