package gui

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"

	"github.com/wailsapp/wails/v3/pkg/icons"
)

func TestMenuBarGlyphDropsFaintOutline(t *testing.T) {
	base, err := png.Decode(bytes.NewReader(icons.SystrayMacTemplate))
	if err != nil {
		t.Fatal(err)
	}
	cropped := trimAndSquare(base)
	glyph := trayGlyph(base)
	if glyph.Bounds() != cropped.Bounds() {
		t.Fatalf("glyph canvas changed from %v to %v", cropped.Bounds(), glyph.Bounds())
	}

	// The outline is the only translucent ink far from the solid W.
	solid := image.Rectangle{}
	for y := cropped.Bounds().Min.Y; y < cropped.Bounds().Max.Y; y++ {
		for x := cropped.Bounds().Min.X; x < cropped.Bounds().Max.X; x++ {
			if cropped.NRGBAAt(x, y).A >= 32 {
				solid = solid.Union(image.Rect(x, y, x+1, y+1))
			}
		}
	}
	outline := 0
	for y := cropped.Bounds().Min.Y; y < cropped.Bounds().Max.Y; y++ {
		for x := cropped.Bounds().Min.X; x < cropped.Bounds().Max.X; x++ {
			if image.Pt(x, y).In(solid.Inset(-2)) {
				continue
			}
			if cropped.NRGBAAt(x, y).A > 0 {
				outline++
			}
			if a := glyph.NRGBAAt(x, y).A; a != 0 {
				t.Fatalf("pixel (%d,%d) outside the W kept alpha %d", x, y, a)
			}
		}
	}
	if outline == 0 {
		t.Fatal("source icon has no faint outline; this test no longer covers issue #45")
	}

	var maxA uint8
	for y := glyph.Bounds().Min.Y; y < glyph.Bounds().Max.Y; y++ {
		for x := glyph.Bounds().Min.X; x < glyph.Bounds().Max.X; x++ {
			maxA = max(maxA, glyph.NRGBAAt(x, y).A)
		}
	}
	if maxA != 255 {
		t.Fatalf("W peaks at alpha %d, want full strength", maxA)
	}
}

func TestMenuBarIconsKeepColourAndBadge(t *testing.T) {
	white := color.NRGBA{255, 255, 255, 255}
	for name, data := range map[string][]byte{
		"off": buildTrayOffIcon(white),
		"on":  buildTrayOnIcon(white),
	} {
		img, err := png.Decode(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var sawWhite, sawGreen bool
		b := img.Bounds()
		for y := b.Min.Y; y < b.Max.Y; y++ {
			for x := b.Min.X; x < b.Max.X; x++ {
				c := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
				sawWhite = sawWhite || (c.A == 255 && c.R == 255 && c.G == 255 && c.B == 255)
				sawGreen = sawGreen || (c == color.NRGBA{52, 199, 89, 255})
			}
		}
		if !sawWhite {
			t.Fatalf("%s icon has no full-strength W", name)
		}
		if sawGreen != (name == "on") {
			t.Fatalf("%s icon green badge = %v", name, sawGreen)
		}
	}
}
