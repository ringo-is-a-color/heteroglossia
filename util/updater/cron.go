package updater

import (
	"time"
)

const day = 24 * time.Hour

func StartUpdateCron(f func()) {
	f()
	tick := time.Tick(day)
	for range tick {
		go f()
	}
}
