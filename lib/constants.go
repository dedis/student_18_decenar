package lib

import decenar "github.com/dedis/student_18_decenar"

// PARALLELIZE is true if we use protocols with parallelization of computations.
const PARALLELIZE = true

// VPARALLELIZE allows to choose the level of parallelization in the vector computations
const VPARALLELIZE = 100

// just to avoid changing everywhere, at least for the moment
var SuiTe = decenar.DecenarSuite
