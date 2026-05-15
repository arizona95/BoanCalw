package imagehash

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"
)

func solid(c color.Color) *bytes.Buffer {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return &buf
}

func TestComputeDeterministic(t *testing.T) {
	h1, err := Compute(solid(color.RGBA{200, 50, 50, 255}))
	if err != nil {
		t.Fatal(err)
	}
	h2, err := Compute(solid(color.RGBA{200, 50, 50, 255}))
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 || len(h1) != 16 {
		t.Errorf("expected stable 16-hex hash, got %s vs %s", h1, h2)
	}
}

func TestEvaluateForbidden_Hits(t *testing.T) {
	h, _ := Compute(solid(color.RGBA{200, 50, 50, 255}))
	list := []Forbidden{{Hash: h, Description: "red square", Replacement: "[blocked]"}}
	matched, dist := EvaluateForbidden(h, list, 5)
	if dist != 0 || matched.Description != "red square" {
		t.Errorf("expected exact match at distance 0, got dist=%d match=%+v", dist, matched)
	}
}

func TestEvaluateForbidden_Misses(t *testing.T) {
	a, _ := Compute(solid(color.RGBA{0, 0, 0, 255}))
	b, _ := Compute(solid(color.RGBA{255, 255, 255, 255}))
	// distance between solid black and solid white is large — should not match at threshold=5
	list := []Forbidden{{Hash: a}}
	_, dist := EvaluateForbidden(b, list, 5)
	if dist >= 0 && HammingDistance(a, b) > 5 {
		t.Errorf("expected miss for dissimilar images at threshold=5, got dist=%d (full=%d)", dist, HammingDistance(a, b))
	}
}
