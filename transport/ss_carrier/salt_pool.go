package ss_carrier

import (
	"sync"
	"time"
)

// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md
// Servers MUST store all incoming salts for 60 seconds.
// When a new TCP session is established, the first received message
// is decrypted and its timestamp MUST be checked against system time.
// If the time difference is within 30 seconds, then the salt is checked
// against all stored salts. If no repeated salt is discovered, then the
// salt is added to the pool and the session is successfully established.
type saltPool[T comparable] struct {
	pool        map[T]time.Time
	lastCleaned time.Time
	mutex       sync.Mutex
}

func newSaltPool[T comparable]() *saltPool[T] {
	return &saltPool[T]{pool: make(map[T]time.Time), lastCleaned: time.Now()}
}

const retainDuration = 60 * time.Second

func (p *saltPool[T]) add(salt T) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.pool[salt] = time.Now()
}

func (p *saltPool[T]) check(salt T) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if now := time.Now(); now.Sub(p.lastCleaned) > retainDuration {
		for oldSalt, addedTime := range p.pool {
			if now.Sub(addedTime) > retainDuration {
				delete(p.pool, oldSalt)
			}
		}
		p.lastCleaned = now
	}
	_, ok := p.pool[salt]
	return !ok
}
