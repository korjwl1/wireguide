package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeRelease is an httptest-backed GitHub release: the API JSON, the
// platform asset, SHA256SUMS and SHA256SUMS.sig. Fields can be tweaked
// before the first request to simulate tampering.
type fakeRelease struct {
	srv       *httptest.Server
	tag       string
	assetName string
	asset     []byte // body served for the asset
	sums      []byte // SHA256SUMS body
	sig       []byte // nil → .sig returns 404
	assetHits atomic.Int32
}

func platformAssetName() string {
	return fmt.Sprintf("WireGuide-%s-%s%s", runtime.GOOS, runtime.GOARCH, preferredExtensions(runtime.GOOS)[0])
}

// newFakeRelease serves a v99.0.0 release whose SHA256SUMS lists the
// asset's real hash. When priv is non-nil the sums are signed with it.
func newFakeRelease(t *testing.T, priv ed25519.PrivateKey) *fakeRelease {
	t.Helper()
	fr := &fakeRelease{tag: "v99.0.0", assetName: platformAssetName()}
	fr.asset = make([]byte, minAssetSize+4096)
	for i := range fr.asset {
		fr.asset[i] = byte(i % 253)
	}
	h := sha256.Sum256(fr.asset)
	fr.sums = []byte(hex.EncodeToString(h[:]) + "  " + fr.assetName + "\n")
	if priv != nil {
		fr.sig = ed25519.Sign(priv, fr.sums)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		rel := Release{
			TagName: fr.tag,
			HTMLURL: "https://github.com/korjwl1/wireguide/releases/tag/" + fr.tag,
			Assets: []Asset{
				{Name: fr.assetName, BrowserDownloadURL: fr.srv.URL + "/dl/" + fr.assetName, Size: int64(len(fr.asset))},
				{Name: "SHA256SUMS", BrowserDownloadURL: fr.srv.URL + "/dl/SHA256SUMS", Size: int64(len(fr.sums))},
				{Name: "SHA256SUMS.sig", BrowserDownloadURL: fr.srv.URL + "/dl/SHA256SUMS.sig", Size: 64},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rel)
	})
	mux.HandleFunc("/dl/"+fr.assetName, func(w http.ResponseWriter, r *http.Request) {
		fr.assetHits.Add(1)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fr.asset)))
		_, _ = w.Write(fr.asset)
	})
	mux.HandleFunc("/dl/SHA256SUMS", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(fr.sums) })
	mux.HandleFunc("/dl/SHA256SUMS.sig", func(w http.ResponseWriter, r *http.Request) {
		if fr.sig == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(fr.sig)
	})
	fr.srv = httptest.NewServer(mux)
	t.Cleanup(fr.srv.Close)

	orig := testOverrideAPIEndpoint
	testOverrideAPIEndpoint = fr.srv.URL + "/releases/latest"
	t.Cleanup(func() { testOverrideAPIEndpoint = orig })
	return fr
}

// stubPlatform replaces the platform hooks for one test. The install
// stub records what it was handed and checks the file it got really is
// the verified download.
type installCall struct {
	path    string
	info    UpdateInfo
	content []byte
}

func stubPlatform(t *testing.T, supportErr error) *[]installCall {
	t.Helper()
	var calls []installCall
	origSupport, origInstall := selfUpdateSupport, installPlatform
	selfUpdateSupport = func() error { return supportErr }
	installPlatform = func(ctx context.Context, path string, info *UpdateInfo) (*InstallResult, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("stub: read %s: %w", path, err)
		}
		calls = append(calls, installCall{path: path, info: *info, content: b})
		return &InstallResult{RelaunchPath: "relaunch-me"}, nil
	}
	t.Cleanup(func() { selfUpdateSupport, installPlatform = origSupport, origInstall })
	return &calls
}

func newTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestApply_SignedHappyPath(t *testing.T) {
	pub, priv := newTestKey(t)
	restore := withTestPublicKey(t, hex.EncodeToString(pub))
	defer restore()
	fr := newFakeRelease(t, priv)
	calls := stubPlatform(t, nil)

	var phases []string
	res, err := Apply(context.Background(), "99.0.0", func(p string) { phases = append(phases, p) })
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res == nil || res.RelaunchPath != "relaunch-me" {
		t.Errorf("InstallResult = %+v, want the platform installer's result", res)
	}
	if len(*calls) != 1 {
		t.Fatalf("platform installer called %d times, want 1", len(*calls))
	}
	c := (*calls)[0]
	if !bytes.Equal(c.content, fr.asset) {
		t.Error("installer was handed a file that differs from the verified asset")
	}
	if !c.info.HashVerified || !c.info.SignatureVerified || c.info.verifiedSHA256 == "" {
		t.Errorf("installer got unverified info: hash=%v sig=%v sha=%q",
			c.info.HashVerified, c.info.SignatureVerified, c.info.verifiedSHA256)
	}
	if strings.Join(phases, ",") != PhaseDownload+","+PhaseInstall {
		t.Errorf("phases = %v, want [download install]", phases)
	}
	if _, err := os.Stat(c.path); !os.IsNotExist(err) {
		t.Errorf("temp download not cleaned up after install: %v", err)
	}
}

// Every way the authenticity chain can break must abort before the
// platform installer runs.
func TestApply_VerificationFailuresNeverInstall(t *testing.T) {
	cases := []struct {
		name string
		// tamper mutates the release after it was built and signed with
		// trusted; other is an unrelated key.
		tamper  func(fr *fakeRelease, trusted, other ed25519.PrivateKey)
		wantErr string
	}{
		{
			name:    "signature by a different key",
			tamper:  func(fr *fakeRelease, _, other ed25519.PrivateKey) { fr.sig = ed25519.Sign(other, fr.sums) },
			wantErr: "signature",
		},
		{
			name:    "missing .sig",
			tamper:  func(fr *fakeRelease, _, _ ed25519.PrivateKey) { fr.sig = nil },
			wantErr: "SHA256SUMS.sig",
		},
		{
			name:    "truncated .sig",
			tamper:  func(fr *fakeRelease, _, _ ed25519.PrivateKey) { fr.sig = fr.sig[:10] },
			wantErr: "signature size",
		},
		{
			name: "SHA256SUMS edited after signing",
			tamper: func(fr *fakeRelease, _, _ ed25519.PrivateKey) {
				fr.sums = []byte(strings.Repeat("0", 64) + "  " + fr.assetName + "\n")
			},
			wantErr: "signature does not verify",
		},
		{
			name: "asset swapped (signed sums still genuine)",
			tamper: func(fr *fakeRelease, _, _ ed25519.PrivateKey) {
				evil := make([]byte, len(fr.asset))
				copy(evil, fr.asset)
				evil[len(evil)/2] ^= 0xff
				fr.asset = evil
			},
			wantErr: "checksum mismatch",
		},
		{
			name: "asset not listed in signed sums",
			tamper: func(fr *fakeRelease, trusted, _ ed25519.PrivateKey) {
				// Validly signed by the trusted key; only the listing is wrong.
				fr.sums = []byte(strings.Repeat("a", 64) + "  some-other-file.zip\n")
				fr.sig = ed25519.Sign(trusted, fr.sums)
			},
			wantErr: "not listed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pub, priv := newTestKey(t)
			_, otherPriv := newTestKey(t)
			restore := withTestPublicKey(t, hex.EncodeToString(pub))
			defer restore()
			fr := newFakeRelease(t, priv)
			tc.tamper(fr, priv, otherPriv)
			calls := stubPlatform(t, nil)

			_, err := Apply(context.Background(), "99.0.0", nil)
			if err == nil {
				t.Fatal("Apply succeeded on a tampered release")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantErr)
			}
			if errors.Is(err, ErrSelfUpdateUnsupported) {
				t.Error("verification failure must not look like 'unsupported' (callers would fall back silently)")
			}
			if len(*calls) != 0 {
				t.Fatalf("platform installer ran %d times on unverified content", len(*calls))
			}
		})
	}
}

func TestApply_UnsupportedInstallSkipsDownload(t *testing.T) {
	pub, priv := newTestKey(t)
	restore := withTestPublicKey(t, hex.EncodeToString(pub))
	defer restore()
	fr := newFakeRelease(t, priv)
	calls := stubPlatform(t, fmt.Errorf("%w: test", ErrSelfUpdateUnsupported))

	_, err := Apply(context.Background(), "99.0.0", nil)
	if !errors.Is(err, ErrSelfUpdateUnsupported) {
		t.Fatalf("err = %v, want ErrSelfUpdateUnsupported", err)
	}
	if n := fr.assetHits.Load(); n != 0 {
		t.Errorf("asset downloaded %d times for an install that can't self-update", n)
	}
	if len(*calls) != 0 {
		t.Error("platform installer must not run")
	}
}

// The version the user approved must still be the latest; otherwise we
// would install something they never saw in the banner.
func TestApply_VersionMismatchAborts(t *testing.T) {
	pub, priv := newTestKey(t)
	restore := withTestPublicKey(t, hex.EncodeToString(pub))
	defer restore()
	fr := newFakeRelease(t, priv)
	calls := stubPlatform(t, nil)

	_, err := Apply(context.Background(), "98.0.0", nil)
	if err == nil || !strings.Contains(err.Error(), "99.0.0") {
		t.Fatalf("err = %v, want a version-changed error", err)
	}
	if fr.assetHits.Load() != 0 || len(*calls) != 0 {
		t.Error("nothing may be downloaded or installed when the version changed")
	}
}

func TestApply_NoNewerReleaseAborts(t *testing.T) {
	pub, priv := newTestKey(t)
	restore := withTestPublicKey(t, hex.EncodeToString(pub))
	defer restore()
	fr := newFakeRelease(t, priv)
	fr.tag = "v0.0.1"
	calls := stubPlatform(t, nil)

	if _, err := Apply(context.Background(), "0.0.1", nil); err == nil {
		t.Fatal("expected error when the latest release is not newer")
	}
	if len(*calls) != 0 {
		t.Error("platform installer must not run")
	}
}

func TestApply_APIErrorAborts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	orig := testOverrideAPIEndpoint
	testOverrideAPIEndpoint = srv.URL
	defer func() { testOverrideAPIEndpoint = orig }()
	calls := stubPlatform(t, nil)

	_, err := Apply(context.Background(), "99.0.0", nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("err = %v, want HTTP 403 surfaced", err)
	}
	if len(*calls) != 0 {
		t.Error("platform installer must not run")
	}
}

// ---------------------------------------------------------------------------
// Install policy
// ---------------------------------------------------------------------------

// The JSON-visible flags can be forged by whoever builds the struct (the
// frontend passes UpdateInfo back verbatim). Only DownloadUpdate's
// unexported digest unlocks Install.
func TestInstall_RejectsForgedVerificationFlags(t *testing.T) {
	calls := stubPlatform(t, nil)
	forged := &UpdateInfo{HashVerified: true, SignatureVerified: true, Version: "99.0.0"}
	if _, err := Install(context.Background(), "whatever.exe", forged); err == nil {
		t.Fatal("Install accepted an UpdateInfo that DownloadUpdate never verified")
	}
	if _, err := Install(context.Background(), "whatever.exe", nil); err == nil {
		t.Fatal("Install accepted a nil UpdateInfo")
	}
	if len(*calls) != 0 {
		t.Fatal("platform installer ran without verification")
	}
}

func TestDownloadUpdate_ResetsCallerSuppliedFlags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	info := &UpdateInfo{
		DownloadURL:       srv.URL + "/asset.exe",
		AssetName:         "asset.exe",
		AssetSize:         minAssetSize,
		HashVerified:      true,
		SignatureVerified: true,
		verifiedSHA256:    "deadbeef",
	}
	if _, err := DownloadUpdate(info); err == nil {
		t.Fatal("expected download failure")
	}
	if info.HashVerified || info.SignatureVerified || info.verifiedSHA256 != "" {
		t.Errorf("failed download left verification state set: %+v", info)
	}
}

func TestRehashOpenFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "rehash-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("installer bytes"); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte("installer bytes"))
	if err := rehashOpenFile(f, hex.EncodeToString(h[:])); err != nil {
		t.Errorf("matching file rejected: %v", err)
	}
	if err := rehashOpenFile(f, strings.Repeat("0", 64)); err == nil {
		t.Error("file that changed after verification was accepted")
	}
}

func TestVersionCore(t *testing.T) {
	cases := map[string]string{
		"0.6.0":         "0.6.0",
		"0.6":           "0.6.0",
		"1":             "1.0.0",
		"0.6.0-rc1":     "0.6.0",
		"0.6.0+sha.123": "0.6.0",
		"01.02.03":      "1.2.3",
		"0.6.0.0":       "0.6.0",
		"abc":           "abc",
	}
	for in, want := range cases {
		if got := versionCore(in); got != want {
			t.Errorf("versionCore(%q) = %q, want %q", in, got, want)
		}
	}
}

// The frontend must name the version the user agreed to; without it Apply
// refuses before touching the network.
func TestApply_RequiresVersion(t *testing.T) {
	calls := stubPlatform(t, nil)
	if _, err := Apply(context.Background(), "", nil); err == nil {
		t.Fatal("expected an error without a version")
	}
	if len(*calls) != 0 {
		t.Error("platform installer must not run")
	}
}
