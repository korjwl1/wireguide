package app

import (
	"bytes"
	"fmt"
	"image"
	_ "image/jpeg" // Register supported QR image decoders.
	_ "image/png"
	"io"
	"os"
	"strings"

	"github.com/korjwl1/wireguide/internal/config"
	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
	_ "golang.org/x/image/webp"
)

const maxReadFileSize = config.MaxConfigSize

// maxQRImageSize bounds the image we'll try to decode. QR images shared by
// VPN providers are typically under 200 KB; the cap protects against an
// accidentally-supplied multi-MB photo or a hostile oversize image.
const maxQRImageSize = 8 << 20

// Encoded bytes do not bound image memory. Allow ordinary 12 MP camera
// photos while rejecting extreme dimensions before the decoder allocates pixels.
const maxQRImagePixels = 16 << 20
const maxQRImageDimension = 8192

// decodeQRConfig decodes a QR code from raw image bytes and returns its
// payload. Returns a stable error message ("no WireGuard QR code...") on any
// decode failure so the frontend can show a single, consistent message
// regardless of whether the issue was an unsupported image format, a missing
// QR code, or a QR code without a [Interface] section.
func decodeQRConfig(data []byte) (string, error) {
	if len(data) > maxQRImageSize {
		return "", fmt.Errorf("image too large (%d bytes, max %d)", len(data), maxQRImageSize)
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("cannot decode image: %w", err)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxQRImageDimension || cfg.Height > maxQRImageDimension ||
		int64(cfg.Width)*int64(cfg.Height) > maxQRImagePixels {
		return "", fmt.Errorf("image dimensions too large (max %d pixels, %d per side)", maxQRImagePixels, maxQRImageDimension)
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("cannot decode image: %w", err)
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("no WireGuard QR code found in image")
	}
	res, err := qrcode.NewQRCodeReader().Decode(bmp, nil)
	if err != nil {
		return "", fmt.Errorf("no WireGuard QR code found in image")
	}
	text := res.GetText()
	if !strings.Contains(text, "[Interface]") {
		return "", fmt.Errorf("QR code does not contain a WireGuard config")
	}
	return text, nil
}

// ImportQRFromPath reads an image from disk, decodes its QR code, and imports
// the contained WireGuard config under the given name.
func (s *TunnelService) ImportQRFromPath(path, name string) (*TunnelInfo, error) {
	data, err := readImportFile(path, maxQRImageSize)
	if err != nil {
		return nil, err
	}
	return s.ImportQRFromBytes(data, name)
}

// ImportQRFromBytes decodes a QR code from raw image bytes (typically supplied
// by the file picker, which gives us bytes rather than a path) and imports the
// resulting WireGuard config.
func (s *TunnelService) ImportQRFromBytes(data []byte, name string) (*TunnelInfo, error) {
	text, err := decodeQRConfig(data)
	if err != nil {
		return nil, err
	}
	return s.ImportConfig(name, text)
}

// ReadFile reads a file from disk (used by native file drop). Returns the
// content as a string so the frontend can handle name conflicts before import.
func (s *TunnelService) ReadFile(path string) (string, error) {
	data, err := readImportFile(path, maxReadFileSize)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Read through a limit even after Stat: the file can grow between the two.
// Reject devices and directories rather than consuming an unbounded stream.
func readImportFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file too large (max %d bytes)", limit)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file too large (max %d bytes)", limit)
	}
	return data, nil
}
