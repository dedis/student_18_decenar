package lib

import "reflect"

type AggregationProof struct {
	Contributions map[string]CipherVector
	Aggregation   CipherVector
}

func CreateAggregationiProof(c map[string]CipherVector, a CipherVector) *AggregationProof {
	return &AggregationProof{Contributions: c, Aggregation: a}
}

func VerifyAggregationProof(p *AggregationProof) bool {
	tmp := NewCipherVector(len(p.Aggregation))
	for _, c := range p.Contributions {
		tmp.Add(*tmp, c)
	}

	return reflect.DeepEqual(tmp, p.Aggregation)
}
