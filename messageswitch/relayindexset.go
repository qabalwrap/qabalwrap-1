package messageswitch

import (
	"time"
)

type relayIndexSet struct {
	d map[int]int64
}

func newRelayIndexSet() (s *relayIndexSet) {
	return &relayIndexSet{
		d: make(map[int]int64),
	}
}

func (s *relayIndexSet) retain(relayIndexes []int) (popouts []int) {
	currentTimestamp := time.Now().UnixNano()
	for _, relayIndex := range relayIndexes {
		s.d[relayIndex] = currentTimestamp
	}
	for relayIndex, t := range s.d {
		if t < currentTimestamp {
			popouts = append(popouts, relayIndex)
		}
	}
	for _, relayIndex := range popouts {
		delete(s.d, relayIndex)
	}
	return
}
