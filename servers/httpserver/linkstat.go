package httpserver

import (
	"net/http"
	"sync"
	"time"
)

type linkStat struct {
	requestMethod string
	requestURI    string
	destHost      string
	remoteAddr    string
	startAt       time.Time
}

func (l *linkStat) clear() {
	l.requestMethod = ""
	l.requestURI = ""
	l.destHost = ""
	l.remoteAddr = ""
	l.startAt = time.Time{}
}

func (l *linkStat) setWithRequest(r *http.Request) {
	l.requestMethod = r.Method
	l.requestURI = r.RequestURI
	l.destHost = r.Host
	l.remoteAddr = r.RemoteAddr
	l.startAt = time.Now()
}

type linkStatSlice struct {
	lck sync.Mutex

	linkStates     []linkStat
	availableLinks []int
	remainLinks    int
}

func (s *linkStatSlice) init(maxLinks int) {
	s.linkStates = make([]linkStat, maxLinks)
	s.availableLinks = make([]int, maxLinks)
	for i := 0; i < maxLinks; i++ {
		s.availableLinks[i] = i
	}
	s.remainLinks = maxLinks
}

func (s *linkStatSlice) allocateLink(r *http.Request) (linkIndex int, success bool) {
	s.lck.Lock()
	defer s.lck.Unlock()
	if s.remainLinks == 0 {
		return
	}
	s.remainLinks = s.remainLinks - 1
	linkIndex = s.availableLinks[s.remainLinks]
	s.linkStates[linkIndex].setWithRequest(r)
	success = true
	return
}

func (s *linkStatSlice) releaseLink(linkIndex int) {
	s.lck.Lock()
	defer s.lck.Unlock()
	s.linkStates[linkIndex].clear()
	s.availableLinks[s.remainLinks] = linkIndex
	s.remainLinks = s.remainLinks + 1
}
