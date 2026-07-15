package embed

import "testing"

func TestDeterministic(t *testing.T) {
	e := NewHash(128)
	a := e.Embed("checkout payment failed timeout")
	b := e.Embed("checkout payment failed timeout")
	if Cosine(a, b) < 0.999 {
		t.Fatal("identical text must produce an identical vector (deterministic)")
	}
}

func TestSimilarCloserThanDissimilar(t *testing.T) {
	e := NewHash(256)
	q := e.Embed("checkout payment gateway timeout error")
	similar := e.Embed("payment gateway timeout on checkout")
	dissimilar := e.Embed("user login page rendered successfully")

	simScore := Cosine(q, similar)
	disScore := Cosine(q, dissimilar)
	if simScore <= disScore {
		t.Fatalf("text sharing tokens must score closer: sim=%.3f dis=%.3f", simScore, disScore)
	}
}

func TestNormalized(t *testing.T) {
	e := NewHash(64)
	v := e.Embed("some log line with several tokens here")
	if s := Cosine(v, v); s < 0.999 || s > 1.001 {
		t.Fatalf("a normalised vector must have |v|=1 (cos self=%.4f)", s)
	}
}
