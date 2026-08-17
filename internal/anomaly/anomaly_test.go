package anomaly

import "testing"

func TestBaselineWarmupThenSpike(t *testing.T) {
	d := New(0.3, 3.0, 10)
	// Warmup: baseline ổn định quanh ~5, không được báo trong giai đoạn học.
	for i := 0; i < 30; i++ {
		if _, anom := d.Observe("acme", "checkout", "error_volume", 5); anom {
			t.Fatalf("giá trị bình thường không được coi là bất thường (i=%d)", i)
		}
	}
	// Spike lớn => phải phát hiện.
	_, anom := d.Observe("acme", "checkout", "error_volume", 500)
	if !anom {
		t.Fatal("spike 500 so với baseline ~5 phải bị phát hiện")
	}
}

func TestNoAlertDuringWarmup(t *testing.T) {
	d := New(0.3, 3.0, 50)
	// Ngay cả spike nhưng chưa đủ warmup thì chưa báo (tránh false positive sớm).
	d.Observe("acme", "s", "sig", 5)
	if _, anom := d.Observe("acme", "s", "sig", 1000); anom {
		t.Fatal("chưa đủ warmup không được báo")
	}
}

func TestPerSeriesIsolation(t *testing.T) {
	d := New(0.3, 3.0, 5)
	// Hai series khác nhau có baseline độc lập.
	for i := 0; i < 10; i++ {
		d.Observe("acme", "a", "sig", 1)
		d.Observe("acme", "b", "sig", 100)
	}
	if d.Baselines() != 2 {
		t.Fatalf("phải có 2 baseline độc lập, got %d", d.Baselines())
	}
}
