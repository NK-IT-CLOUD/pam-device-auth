package qr

import "strings"

// Render generates a terminal-friendly QR code string for the given URL.
// Uses Unicode half-block characters for compact display (2 rows per line).
// Returns empty string and error if encoding fails.
func Render(url string) (string, error) {
	matrix, err := Encode(url)
	if err != nil {
		return "", err
	}

	size := len(matrix)

	// Add quiet zone (1 module border)
	qzSize := size + 2
	qz := make([][]bool, qzSize)
	for i := range qz {
		qz[i] = make([]bool, qzSize)
	}
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			qz[r+1][c+1] = matrix[r][c]
		}
	}

	// Render using half-block characters
	// Process two rows at a time
	var buf strings.Builder

	for r := 0; r < qzSize; r += 2 {
		for c := 0; c < qzSize; c++ {
			top := false
			bottom := false
			if r < qzSize {
				top = qz[r][c]
			}
			if r+1 < qzSize {
				bottom = qz[r+1][c]
			}

			switch {
			case top && bottom:
				buf.WriteRune('\u2588') // Full block
			case top && !bottom:
				buf.WriteRune('\u2580') // Upper half block
			case !top && bottom:
				buf.WriteRune('\u2584') // Lower half block
			default:
				buf.WriteRune(' ') // Space
			}
		}
		buf.WriteRune('\n')
	}

	return buf.String(), nil
}
