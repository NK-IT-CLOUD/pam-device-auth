package qr

import (
	"strings"
	"testing"
)

func TestEncode_SmallURL(t *testing.T) {
	matrix, err := Encode("https://example.com")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	if matrix == nil {
		t.Fatal("matrix is nil")
	}
	size := len(matrix)
	if size < 21 { // minimum QR version 1 is 21x21
		t.Fatalf("matrix too small: %d", size)
	}
	// Check square
	for i, row := range matrix {
		if len(row) != size {
			t.Fatalf("row %d has %d cols, expected %d", i, len(row), size)
		}
	}
}

func TestEncode_LongURL(t *testing.T) {
	// Typical device auth URL (~100 chars)
	url := "https://sso.example.com/realms/myrealm/protocol/openid-connect/auth/device?user_code=ABCD-EFGH"
	matrix, err := Encode(url)
	if err != nil {
		t.Fatalf("Encode failed for long URL: %v", err)
	}
	if matrix == nil {
		t.Fatal("matrix is nil")
	}

	// Even longer URL (~200 chars)
	longURL := "https://sso.example.com/realms/production-realm/protocol/openid-connect/auth/device?user_code=ABCD-EFGH-IJKL&session_state=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	matrix2, err := Encode(longURL)
	if err != nil {
		t.Fatalf("Encode failed for ~200 char URL: %v", err)
	}
	if matrix2 == nil {
		t.Fatal("matrix is nil for long URL")
	}
}

func TestEncode_VersionSelection(t *testing.T) {
	// Short URL should use a smaller version (smaller matrix)
	short, err := Encode("https://x.co")
	if err != nil {
		t.Fatalf("short encode failed: %v", err)
	}

	long, err := Encode("https://sso.example.com/realms/myrealm/protocol/openid-connect/auth/device?user_code=ABCD-EFGH")
	if err != nil {
		t.Fatalf("long encode failed: %v", err)
	}

	if len(short) >= len(long) {
		t.Errorf("short URL matrix (%d) should be smaller than long URL matrix (%d)",
			len(short), len(long))
	}
}

func TestEncode_Empty(t *testing.T) {
	_, err := Encode("")
	if err == nil {
		t.Error("expected error for empty data")
	}
}

func TestEncode_TooLong(t *testing.T) {
	// Create a string longer than version 10 can handle
	data := strings.Repeat("A", 300)
	_, err := Encode(data)
	if err == nil {
		t.Error("expected error for oversized data")
	}
}

func TestEncode_FinderPatterns(t *testing.T) {
	matrix, err := Encode("TEST")
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	size := len(matrix)

	// Verify finder pattern at top-left (7x7)
	checkFinder(t, matrix, 0, 0, "top-left")

	// Verify finder pattern at top-right
	checkFinder(t, matrix, 0, size-7, "top-right")

	// Verify finder pattern at bottom-left
	checkFinder(t, matrix, size-7, 0, "bottom-left")
}

func checkFinder(t *testing.T, matrix [][]bool, startRow, startCol int, name string) {
	t.Helper()

	// Top row of finder should be all dark
	for c := 0; c < 7; c++ {
		if !matrix[startRow][startCol+c] {
			t.Errorf("%s finder: top row col %d should be dark", name, c)
			return
		}
	}

	// Bottom row of finder should be all dark
	for c := 0; c < 7; c++ {
		if !matrix[startRow+6][startCol+c] {
			t.Errorf("%s finder: bottom row col %d should be dark", name, c)
			return
		}
	}

	// Left column should be all dark
	for r := 0; r < 7; r++ {
		if !matrix[startRow+r][startCol] {
			t.Errorf("%s finder: left col row %d should be dark", name, r)
			return
		}
	}

	// Right column should be all dark
	for r := 0; r < 7; r++ {
		if !matrix[startRow+r][startCol+6] {
			t.Errorf("%s finder: right col row %d should be dark", name, r)
			return
		}
	}

	// Center 3x3 should be all dark
	for r := 2; r <= 4; r++ {
		for c := 2; c <= 4; c++ {
			if !matrix[startRow+r][startCol+c] {
				t.Errorf("%s finder: center (%d,%d) should be dark", name, r, c)
				return
			}
		}
	}

	// Ring between border and center should be light
	for c := 1; c <= 5; c++ {
		if matrix[startRow+1][startCol+c] {
			t.Errorf("%s finder: inner ring row 1 col %d should be light", name, c)
		}
		if matrix[startRow+5][startCol+c] {
			t.Errorf("%s finder: inner ring row 5 col %d should be light", name, c)
		}
	}
	for r := 2; r <= 4; r++ {
		if matrix[startRow+r][startCol+1] {
			t.Errorf("%s finder: inner ring col 1 row %d should be light", name, r)
		}
		if matrix[startRow+r][startCol+5] {
			t.Errorf("%s finder: inner ring col 5 row %d should be light", name, r)
		}
	}
}

func TestRender_ProducesOutput(t *testing.T) {
	output, err := Render("https://example.com")
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}
	if output == "" {
		t.Fatal("Render produced empty output")
	}

	// Should contain block characters
	hasBlock := strings.ContainsAny(output, "\u2588\u2580\u2584")
	if !hasBlock {
		t.Error("Render output should contain Unicode block characters")
	}

	// Should have multiple lines
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) < 5 {
		t.Errorf("expected multiple lines, got %d", len(lines))
	}
}

func TestRender_Error(t *testing.T) {
	_, err := Render("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestRender_DeviceAuthURL(t *testing.T) {
	// Real-world URL that would be used in PAM device auth
	url := "https://sso.example.com/realms/nkit/protocol/openid-connect/auth/device?user_code=ABCD-EFGH"
	output, err := Render(url)
	if err != nil {
		t.Fatalf("Render failed for device auth URL: %v", err)
	}
	if output == "" {
		t.Fatal("empty output for device auth URL")
	}
	t.Logf("QR code output:\n%s", output)
}
