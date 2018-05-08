package lib

// adapted from https://github.com/lca1/unlynx/blob/master/lib/constants.go

import (
	"sync"

	decenarch "github.com/dedis/student_18_decenar"
)

// PARALLELIZE is true if we use protocols with parallelization of computations.
const PARALLELIZE = true

// VPARALLELIZE allows to choose the level of parallelization in the vector computations
const VPARALLELIZE = 50

// just to avoid changing everywhere, at least for the moment
var SuiTe = decenarch.Suite

// StartParallelize starts parallelization by instanciating number of threads
func StartParallelize(nbrWg int) *sync.WaitGroup {
	var wg sync.WaitGroup
	if PARALLELIZE {
		wg.Add(nbrWg)
	}
	return &wg
}

// EndParallelize waits for a number of threads to finish
func EndParallelize(wg *sync.WaitGroup) {
	if PARALLELIZE {
		wg.Wait()
	}
}
