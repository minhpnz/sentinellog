package anomaly

import "testing"

func TestBaselineWarmupThenSpike(t *testing.T) {
	d := New(0.3, 3.0, 10)
	// Warmup: the baseline settles around ~5 and must not alert while learning.
	for i := 0; i < 30; i++ {
		if _, anom := d.Observe("acme", "checkout", "error_volume", 5); anom {
			t.Fatalf("a normal value must not be flagged as anomalous (i=%d)", i)
		}
	}
	// A large spike must be detected.
	_, anom := d.Observe("acme", "checkout", "error_volume", 500)
	if !anom {
		t.Fatal("a spike of 500 against a ~5 baseline must be detected")
	}
}

func TestNoAlertDuringWarmup(t *testing.T) {
	d := New(0.3, 3.0, 50)
	// Even a spike must not alert before warmup completes, which avoids early false positives.
	d.Observe("acme", "s", "sig", 5)
	if _, anom := d.Observe("acme", "s", "sig", 1000); anom {
		t.Fatal("must not alert before warmup completes")
	}
}

func TestPerSeriesIsolation(t *testing.T) {
	d := New(0.3, 3.0, 5)
	// Two different series keep independent baselines.
	for i := 0; i < 10; i++ {
		d.Observe("acme", "a", "sig", 1)
		d.Observe("acme", "b", "sig", 100)
	}
	if d.Baselines() != 2 {
		t.Fatalf("expected 2 independent baselines, got %d", d.Baselines())
	}
}
