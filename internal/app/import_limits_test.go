package app

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"image"
	"image/png"
	"strings"
	"testing"

	"github.com/korjwl1/wireguide/internal/storage"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

func TestQRRejectsOversizedDimensionsBeforeDecoding(t *testing.T) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, image.NewGray(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	// Alter a real PNG's IHDR and CRC, leaving its tiny IDAT intact. The
	// decoder must reject the declared dimensions before allocating pixels.
	binary.BigEndian.PutUint32(data[16:20], 16384)
	binary.BigEndian.PutUint32(data[29:33], crc32.ChecksumIEEE(data[12:29]))
	_, err := decodeQRConfig(data)
	if err == nil || !strings.Contains(err.Error(), "dimensions") {
		t.Fatalf("did not reject image dimensions: %v", err)
	}
}

func TestQRConfigStillDecodes(t *testing.T) {
	const content = "[Interface]\nAddress = 10.0.0.2/24\n"
	img, err := qrcode.NewQRCodeWriter().Encode(content, gozxing.BarcodeFormat_QR_CODE, 256, 256, nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	got, err := decodeQRConfig(buf.Bytes())
	if err != nil || got != content {
		t.Fatalf("QR decode: %q, %v", got, err)
	}
}

func TestZipTotalExpansionBudget(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := 0; i < 33; i++ {
		entry, err := w.Create(fmt.Sprintf("vpn-%d.conf", i))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(bytes.Repeat([]byte{'#'}, 1<<20)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	s := &TunnelService{tunnelStore: storage.NewTunnelStore(t.TempDir())}
	_, err := s.ImportZipData(buf.Bytes())
	if err == nil || !strings.Contains(err.Error(), "total expanded") {
		t.Fatalf("archive expansion was not rejected: %v", err)
	}
}

func zipConfigs(t *testing.T, names []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, name := range names {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, err = entry.Write([]byte("[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.2/24\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestZipEntryBudgetIsCheckedBeforeImport(t *testing.T) {
	store := storage.NewTunnelStore(t.TempDir())
	s := &TunnelService{tunnelStore: store}
	names := make([]string, 257)
	for i := range names {
		names[i] = fmt.Sprintf("vpn-%d.conf", i)
	}
	if _, err := s.ImportZipData(zipConfigs(t, names)); err == nil {
		t.Fatal("import accepted an unbounded number of configurations")
	}
	stored, err := store.List()
	if err != nil || len(stored) != 0 {
		t.Fatalf("budget rejection partially imported configs: %v, %v", stored, err)
	}
}

func TestZipNamesRemainValidOnCollision(t *testing.T) {
	s := &TunnelService{tunnelStore: storage.NewTunnelStore(t.TempDir())}
	stem := strings.Repeat("a", 64)
	results, err := s.ImportZipData(zipConfigs(t, []string{stem + ".conf", stem + ".CONF"}))
	if err != nil || len(results) != 2 {
		t.Fatalf("import: %v, %v", results, err)
	}
	for _, result := range results {
		if result.Error != "" {
			t.Fatalf("valid filename was rejected: %+v", result)
		}
		if err := storage.ValidateTunnelName(result.Name); err != nil {
			t.Fatal(err)
		}
	}
	if results[0].Name == results[1].Name {
		t.Fatal("collision overwrote the first configuration")
	}
}
