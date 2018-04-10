package lib

type AggregationProof struct {
	Contributions map[string]*CipherVector
	Aggregation   *CipherVector
}

func CreateAggregationiProof(c map[string]*CipherVector, a *CipherVector) *AggregationProof {
	return &AggregationProof{Contributions: c, Aggregation: a}
}

func VerifyAggregationProof(p *AggregationProof) bool {
	return true
}
