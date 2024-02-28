package randutil

import (
	"crypto/rand"
	mathRand "math/rand/v2"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

func RandNBytes(n int) ([]byte, error) {
	bs := make([]byte, n)
	n, err := rand.Read(bs)
	return bs, errors.WithStack(err)
}

func RandBytes(bs []byte) (int, error) {
	n, err := rand.Read(bs)
	return n, errors.WithStack(err)
}

// forked from https://stackoverflow.com/a/6737362

func WeightedIntN(n int) func() int {
	weights := make([]float32, n)
	var totalWeight float32 = 0.0
	for i := range n {
		weights[i] = mathRand.Float32()
		totalWeight += weights[i]
	}

	return func() int {
		if totalWeight == 0.0 {
			return mathRand.IntN(n)
		}
		r := mathRand.Float32() * totalWeight
		for i := range n {
			r -= weights[i]
			if r <= 0.0 {
				return i
			}
		}
		panic("unreachable code line")
	}
}
