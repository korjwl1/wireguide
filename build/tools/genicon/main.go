// Command genicon builds a multi-resolution Windows .ico file from a
// single PNG source, applying a rounded-corner alpha mask to each
// embedded size so the taskbar / Alt-Tab / Explorer icon all match the
// rounded look the macOS Dock gives the same source for free.
//
// Why not let `wails3 generate icons` do it: the wails3 helper produces
// an ICO with only 256×256 + 128×128 PNG entries. Windows then scales
// those down for the taskbar (typically 24-32 px), and depending on the
// render path it sometimes flattens the transparent corners to the
// taskbar background colour — what the user sees as "white square
// around the rounded red tile". Pre-baking the rounded shape into
// every embedded size sidesteps the downscale entirely.
//
// Output layout:
//
//	ICONDIR header (6B)
//	N × ICONDIRENTRY (16B each)
//	N × PNG payload (the actual image bytes, in the same order)
//
// All entries are PNG-embedded (not BMP), which is the modern format
// every Windows version since Vista understands.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"

	"golang.org/x/image/draw"
)

func main() {
	in := flag.String("in", "", "source PNG (alpha-aware)")
	out := flag.String("out", "", "destination .ico path")
	flag.Parse()
	if *in == "" || *out == "" {
		log.Fatalf("usage: genicon -in appicon.png -out windows/icon.ico")
	}

	srcBytes, err := os.ReadFile(*in)
	if err != nil {
		log.Fatalf("read %s: %v", *in, err)
	}
	srcImg, err := png.Decode(bytes.NewReader(srcBytes))
	if err != nil {
		log.Fatalf("decode %s: %v", *in, err)
	}

	// Standard Windows icon sizes. 256 and 128 are required for
	// Explorer's large-icon views; 16-48 cover taskbar / Alt-Tab /
	// title-bar at every common DPI scaling.
	sizes := []int{16, 20, 24, 32, 40, 48, 64, 128, 256}
	payloads := make([][]byte, len(sizes))
	for i, sz := range sizes {
		payloads[i] = renderRoundedPNG(srcImg, sz)
	}

	if err := writeICO(*out, sizes, payloads); err != nil {
		log.Fatalf("write %s: %v", *out, err)
	}
	fmt.Printf("genicon: wrote %s (%d sizes)\n", *out, len(sizes))
}

// renderRoundedPNG resamples src to size×size, applies an
// alpha-anti-aliased rounded-corner mask proportional to the size, and
// returns the PNG-encoded bytes.
func renderRoundedPNG(src image.Image, size int) []byte {
	dst := image.NewNRGBA(image.Rect(0, 0, size, size))
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, src.Bounds(), draw.Over, nil)

	// Radius ≈ 22% of side — the same proportion the inner red tile
	// uses on the 1024×1024 source. At small sizes we clamp to a 2-px
	// minimum so 16×16 doesn't end up looking square anyway.
	radius := int(math.Round(float64(size) * 0.22))
	if radius < 2 {
		radius = 2
	}
	applyRoundedMask(dst, radius)

	var buf bytes.Buffer
	if err := png.Encode(&buf, dst); err != nil {
		log.Fatalf("encode size %d: %v", size, err)
	}
	return buf.Bytes()
}

// applyRoundedMask zeros the alpha of pixels outside a centered rounded
// rectangle with the given corner radius. A 1-pixel ring at the corner
// boundary fades alpha so the edge is anti-aliased.
func applyRoundedMask(img *image.NRGBA, radius int) {
	if radius <= 0 {
		return
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var cx, cy int
			switch {
			case x < radius && y < radius:
				cx, cy = radius, radius
			case x >= w-radius && y < radius:
				cx, cy = w-1-radius, radius
			case x < radius && y >= h-radius:
				cx, cy = radius, h-1-radius
			case x >= w-radius && y >= h-radius:
				cx, cy = w-1-radius, h-1-radius
			default:
				continue
			}
			dx, dy := float64(x-cx), float64(y-cy)
			d := math.Sqrt(dx*dx + dy*dy)
			r := float64(radius)
			switch {
			case d > r:
				img.SetNRGBA(x, y, color.NRGBA{})
			case d > r-1:
				c := img.NRGBAAt(x, y)
				c.A = uint8(float64(c.A) * (r - d))
				img.SetNRGBA(x, y, c)
			}
		}
	}
}

// writeICO emits a Windows ICO file from N PNG payloads.
//
// Layout reference: https://en.wikipedia.org/wiki/ICO_(file_format)
// Sizes 256 are encoded as width=0 / height=0 per the spec quirk.
func writeICO(path string, sizes []int, payloads [][]byte) error {
	if len(sizes) != len(payloads) {
		return fmt.Errorf("sizes/payloads length mismatch: %d vs %d", len(sizes), len(payloads))
	}
	var buf bytes.Buffer
	// ICONDIR
	binary.Write(&buf, binary.LittleEndian, uint16(0))          // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1))          // type = icon
	binary.Write(&buf, binary.LittleEndian, uint16(len(sizes))) // count

	headerSize := 6
	entrySize := 16
	offset := headerSize + entrySize*len(sizes)
	for i, sz := range sizes {
		w := byte(sz)
		h := byte(sz)
		if sz == 256 {
			w, h = 0, 0
		}
		buf.WriteByte(w)
		buf.WriteByte(h)
		buf.WriteByte(0)                                    // colors in palette (0 = no palette)
		buf.WriteByte(0)                                    // reserved
		binary.Write(&buf, binary.LittleEndian, uint16(1))  // color planes
		binary.Write(&buf, binary.LittleEndian, uint16(32)) // bits per pixel
		binary.Write(&buf, binary.LittleEndian, uint32(len(payloads[i])))
		binary.Write(&buf, binary.LittleEndian, uint32(offset))
		offset += len(payloads[i])
	}
	for _, p := range payloads {
		buf.Write(p)
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
}
