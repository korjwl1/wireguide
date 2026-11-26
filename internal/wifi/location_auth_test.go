package wifi

import "testing"

func TestMapLocationAuthStatus(t *testing.T) {
	cases := map[int]string{
		0: LocationNotDetermined, 1: LocationRestricted, 2: LocationDenied,
		3: LocationAuthorized, 4: LocationAuthorized, -1: LocationUnknown, 99: LocationUnknown,
	}
	for raw, want := range cases {
		if got := mapLocationAuthStatus(raw); got != want {
			t.Errorf("raw %d: got %q want %q", raw, got, want)
		}
	}
}

func TestLocationAuthorizationUsesStub(t *testing.T) {
	old := locationAuthRawFn
	defer func() { locationAuthRawFn = old }()
	locationAuthRawFn = func() int { return 2 }
	if got := LocationAuthorization(); got != LocationDenied {
		t.Fatalf("got %q", got)
	}
}
