// Package qr implements a minimal QR code encoder in pure Go (no external dependencies).
// Supports QR versions 1-10, error correction level M, byte mode encoding.
package qr

import (
	"errors"
	"fmt"
	"math"
)

// Encode generates a QR code matrix for the given data string.
// Returns a 2D boolean slice where true = dark module.
func Encode(data string) ([][]bool, error) {
	if len(data) == 0 {
		return nil, errors.New("qr: empty data")
	}

	version, err := selectVersion(len(data))
	if err != nil {
		return nil, err
	}

	encoded := encodeData(data, version)
	size := 17 + version*4
	matrix := newMatrix(size)
	reserved := newMatrix(size)

	// Place function patterns
	placeFinders(matrix, reserved, size)
	placeTimingPatterns(matrix, reserved, size)
	if version >= 2 {
		placeAlignmentPatterns(matrix, reserved, version, size)
	}
	reserveFormatArea(reserved, size)

	// Place data
	placeData(matrix, reserved, encoded, size)

	// Apply best mask
	bestMask := selectBestMask(matrix, reserved, size)
	applyMask(matrix, reserved, bestMask, size)

	// Write format info
	writeFormatInfo(matrix, bestMask, size)

	return matrix, nil
}

// --- Version selection ---

// versionCapacity holds the byte capacity for each version at ECC level M (byte mode).
var versionCapacity = [11]int{
	0,   // version 0 unused
	14,  // v1
	26,  // v2
	42,  // v3
	62,  // v4
	84,  // v5
	106, // v6
	122, // v7
	152, // v8
	180, // v9
	213, // v10
}

func selectVersion(dataLen int) (int, error) {
	for v := 1; v <= 10; v++ {
		// Byte mode overhead: 4 bits mode + character count bits + data
		ccBits := charCountBits(v)
		overhead := (4 + ccBits + 7) / 8 // ceiling
		if dataLen+overhead <= versionCapacity[v] {
			return v, nil
		}
	}
	return 0, fmt.Errorf("qr: data too long (%d bytes), max ~200 for version 10", dataLen)
}

func charCountBits(version int) int {
	if version <= 9 {
		return 8 // byte mode, versions 1-9
	}
	return 16 // byte mode, versions 10-26 (we only go to 10)
}

// --- Data encoding ---

// Total data codewords (data + ECC) per version at level M
var totalCodewords = [11]int{0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346}

// ECC codewords per block for level M
var eccPerBlock = [11]int{0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 28}

// Block structure: [numBlocks1, dataPerBlock1, numBlocks2, dataPerBlock2]
// For level M
var blockInfo = [11][4]int{
	{0, 0, 0, 0},   // v0
	{1, 16, 0, 0},  // v1
	{1, 28, 0, 0},  // v2
	{1, 44, 0, 0},  // v3
	{2, 32, 0, 0},  // v4
	{2, 43, 0, 0},  // v5
	{4, 27, 0, 0},  // v6
	{4, 31, 0, 0},  // v7
	{2, 38, 2, 39}, // v8
	{3, 36, 2, 37}, // v9
	{4, 43, 1, 44}, // v10
}

func encodeData(data string, version int) []byte {
	// Build bit stream
	bits := &bitBuffer{}

	// Mode indicator: byte mode = 0100
	bits.append(0b0100, 4)

	// Character count
	ccBits := charCountBits(version)
	bits.append(len(data), ccBits)

	// Data bytes
	for i := 0; i < len(data); i++ {
		bits.append(int(data[i]), 8)
	}

	// Terminator (up to 4 zero bits)
	totalDataBits := dataCodewordsCount(version) * 8
	remaining := totalDataBits - bits.len()
	if remaining > 4 {
		remaining = 4
	}
	if remaining > 0 {
		bits.append(0, remaining)
	}

	// Pad to byte boundary
	if bits.len()%8 != 0 {
		bits.append(0, 8-bits.len()%8)
	}

	// Pad with 0xEC, 0x11 alternation
	padBytes := []int{0xEC, 0x11}
	padIdx := 0
	for bits.len() < totalDataBits {
		bits.append(padBytes[padIdx], 8)
		padIdx ^= 1
	}

	codewords := bits.bytes()

	// Split into blocks and compute ECC
	bi := blockInfo[version]
	numBlocks1, dataPer1, numBlocks2, dataPer2 := bi[0], bi[1], bi[2], bi[3]
	eccCount := eccPerBlock[version]

	type block struct {
		data []byte
		ecc  []byte
	}

	var blocks []block
	offset := 0

	for i := 0; i < numBlocks1; i++ {
		d := codewords[offset : offset+dataPer1]
		offset += dataPer1
		e := computeECC(d, eccCount)
		blocks = append(blocks, block{data: d, ecc: e})
	}
	for i := 0; i < numBlocks2; i++ {
		d := codewords[offset : offset+dataPer2]
		offset += dataPer2
		e := computeECC(d, eccCount)
		blocks = append(blocks, block{data: d, ecc: e})
	}

	// Interleave data codewords
	var result []byte
	maxDataLen := dataPer1
	if dataPer2 > maxDataLen {
		maxDataLen = dataPer2
	}
	for i := 0; i < maxDataLen; i++ {
		for _, b := range blocks {
			if i < len(b.data) {
				result = append(result, b.data[i])
			}
		}
	}

	// Interleave ECC codewords
	for i := 0; i < eccCount; i++ {
		for _, b := range blocks {
			if i < len(b.ecc) {
				result = append(result, b.ecc[i])
			}
		}
	}

	// Add remainder bits (0 for versions 1, 7+ need some but we pad in placement)
	return result
}

func dataCodewordsCount(version int) int {
	bi := blockInfo[version]
	return bi[0]*bi[1] + bi[2]*bi[3]
}

// --- Bit buffer ---

type bitBuffer struct {
	data   []byte
	bitLen int
}

func (b *bitBuffer) append(val, numBits int) {
	for i := numBits - 1; i >= 0; i-- {
		byteIdx := b.bitLen / 8
		bitIdx := 7 - (b.bitLen % 8)
		if byteIdx >= len(b.data) {
			b.data = append(b.data, 0)
		}
		if (val>>i)&1 == 1 {
			b.data[byteIdx] |= 1 << uint(bitIdx)
		}
		b.bitLen++
	}
}

func (b *bitBuffer) len() int {
	return b.bitLen
}

func (b *bitBuffer) bytes() []byte {
	return b.data
}

// --- Reed-Solomon ECC over GF(256) ---

var gfExp [512]byte
var gfLog [256]byte

func init() {
	// Generate GF(256) lookup tables with primitive polynomial 0x11d
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x >= 256 {
			x ^= 0x11d
		}
	}
	// Repeat for convenience
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// generatorPoly returns the generator polynomial for the given number of ECC codewords.
func generatorPoly(numECC int) []byte {
	gen := []byte{1}
	for i := 0; i < numECC; i++ {
		newGen := make([]byte, len(gen)+1)
		for j := 0; j < len(gen); j++ {
			newGen[j] ^= gen[j]
			newGen[j+1] ^= gfMul(gen[j], gfExp[i])
		}
		gen = newGen
	}
	return gen
}

func computeECC(data []byte, numECC int) []byte {
	gen := generatorPoly(numECC)

	// Polynomial division
	result := make([]byte, numECC)
	for _, b := range data {
		coeff := b ^ result[0]
		// Shift result left
		copy(result, result[1:])
		result[numECC-1] = 0
		if coeff != 0 {
			for j := 0; j < numECC; j++ {
				result[j] ^= gfMul(gen[j+1], coeff)
			}
		}
	}
	return result
}

// --- Matrix construction ---

func newMatrix(size int) [][]bool {
	m := make([][]bool, size)
	for i := range m {
		m[i] = make([]bool, size)
	}
	return m
}

func setModule(matrix [][]bool, row, col int, dark bool) {
	if row >= 0 && row < len(matrix) && col >= 0 && col < len(matrix) {
		matrix[row][col] = dark
	}
}

// placeFinders places the three 7x7 finder patterns.
func placeFinders(matrix, reserved [][]bool, size int) {
	placeFinderAt(matrix, reserved, 0, 0, size)         // top-left
	placeFinderAt(matrix, reserved, 0, size-7, size)     // top-right
	placeFinderAt(matrix, reserved, size-7, 0, size)     // bottom-left

	// Separators (already handled by reserved marking)
	// Mark separator areas
	for i := 0; i < 8; i++ {
		// top-left separator
		markReserved(reserved, 7, i, size)
		markReserved(reserved, i, 7, size)
		// top-right separator
		markReserved(reserved, 7, size-8+i, size)
		markReserved(reserved, i, size-8, size)
		// bottom-left separator
		markReserved(reserved, size-8, i, size)
		markReserved(reserved, size-8+i, 7, size)
	}
}

func placeFinderAt(matrix, reserved [][]bool, row, col, size int) {
	pattern := [7][7]bool{
		{true, true, true, true, true, true, true},
		{true, false, false, false, false, false, true},
		{true, false, true, true, true, false, true},
		{true, false, true, true, true, false, true},
		{true, false, true, true, true, false, true},
		{true, false, false, false, false, false, true},
		{true, true, true, true, true, true, true},
	}
	for r := 0; r < 7; r++ {
		for c := 0; c < 7; c++ {
			rr, cc := row+r, col+c
			if rr >= 0 && rr < size && cc >= 0 && cc < size {
				matrix[rr][cc] = pattern[r][c]
				reserved[rr][cc] = true
			}
		}
	}
}

func markReserved(reserved [][]bool, row, col, size int) {
	if row >= 0 && row < size && col >= 0 && col < size {
		reserved[row][col] = true
	}
}

func placeTimingPatterns(matrix, reserved [][]bool, size int) {
	for i := 8; i < size-8; i++ {
		dark := i%2 == 0
		// Horizontal timing pattern (row 6)
		if !reserved[6][i] {
			matrix[6][i] = dark
			reserved[6][i] = true
		}
		// Vertical timing pattern (col 6)
		if !reserved[i][6] {
			matrix[i][6] = dark
			reserved[i][6] = true
		}
	}
}

// Alignment pattern center positions per version
var alignmentPositions = [11][]int{
	nil,      // v0
	nil,      // v1 (no alignment)
	{6, 18},  // v2
	{6, 22},  // v3
	{6, 26},  // v4
	{6, 30},  // v5
	{6, 34},  // v6
	{6, 22, 38}, // v7
	{6, 24, 42}, // v8
	{6, 26, 46}, // v9
	{6, 28, 50}, // v10
}

func placeAlignmentPatterns(matrix, reserved [][]bool, version, size int) {
	positions := alignmentPositions[version]
	if positions == nil {
		return
	}
	for _, row := range positions {
		for _, col := range positions {
			// Skip if overlapping with finder pattern
			if isFinderRegion(row, col, size) {
				continue
			}
			placeAlignmentAt(matrix, reserved, row, col, size)
		}
	}
}

func isFinderRegion(row, col, size int) bool {
	// Top-left finder + separator: rows 0-8, cols 0-8
	if row <= 8 && col <= 8 {
		return true
	}
	// Top-right finder + separator: rows 0-8, cols size-9 to size-1
	if row <= 8 && col >= size-9 {
		return true
	}
	// Bottom-left finder + separator: rows size-9 to size-1, cols 0-8
	if row >= size-9 && col <= 8 {
		return true
	}
	return false
}

func placeAlignmentAt(matrix, reserved [][]bool, centerRow, centerCol, size int) {
	for dr := -2; dr <= 2; dr++ {
		for dc := -2; dc <= 2; dc++ {
			r, c := centerRow+dr, centerCol+dc
			if r < 0 || r >= size || c < 0 || c >= size {
				continue
			}
			dark := dr == -2 || dr == 2 || dc == -2 || dc == 2 || (dr == 0 && dc == 0)
			matrix[r][c] = dark
			reserved[r][c] = true
		}
	}
}

func reserveFormatArea(reserved [][]bool, size int) {
	// Around top-left finder
	for i := 0; i <= 8; i++ {
		markReserved(reserved, 8, i, size)
		markReserved(reserved, i, 8, size)
	}
	// Around top-right finder
	for i := 0; i < 8; i++ {
		markReserved(reserved, 8, size-1-i, size)
	}
	// Around bottom-left finder
	for i := 0; i < 7; i++ {
		markReserved(reserved, size-1-i, 8, size)
	}
	// Dark module (always present)
	reserved[size-8][8] = true
}

// --- Data placement ---

func placeData(matrix, reserved [][]bool, data []byte, size int) {
	bitIdx := 0
	totalBits := len(data) * 8

	// Zigzag right-to-left column pairs, starting from right
	col := size - 1
	for col >= 0 {
		// Skip column 6 (timing pattern)
		if col == 6 {
			col--
		}

		// Traverse upward then downward alternating
		upward := (((size - 1 - col) / 2) % 2) == 0

		for row := 0; row < size; row++ {
			actualRow := row
			if upward {
				actualRow = size - 1 - row
			}

			for dx := 0; dx <= 1; dx++ {
				c := col - dx
				if c < 0 || c >= size {
					continue
				}
				if reserved[actualRow][c] {
					continue
				}
				if bitIdx < totalBits {
					byteIdx := bitIdx / 8
					bitPos := 7 - (bitIdx % 8)
					dark := (data[byteIdx]>>uint(bitPos))&1 == 1
					matrix[actualRow][c] = dark
					bitIdx++
				}
			}
		}
		col -= 2
	}
}

// --- Masking ---

func maskFunc(pattern int, row, col int) bool {
	switch pattern {
	case 0:
		return (row+col)%2 == 0
	case 1:
		return row%2 == 0
	case 2:
		return col%3 == 0
	case 3:
		return (row+col)%3 == 0
	case 4:
		return (row/2+col/3)%2 == 0
	case 5:
		return (row*col)%2+(row*col)%3 == 0
	case 6:
		return ((row*col)%2+(row*col)%3)%2 == 0
	case 7:
		return ((row+col)%2+(row*col)%3)%2 == 0
	}
	return false
}

func selectBestMask(matrix, reserved [][]bool, size int) int {
	bestMask := 0
	bestScore := math.MaxInt64

	for mask := 0; mask < 8; mask++ {
		// Create a copy with mask applied
		trial := copyMatrix(matrix, size)
		applyMask(trial, reserved, mask, size)
		writeFormatInfo(trial, mask, size)

		score := evaluatePenalty(trial, size)
		if score < bestScore {
			bestScore = score
			bestMask = mask
		}
	}
	return bestMask
}

func copyMatrix(matrix [][]bool, size int) [][]bool {
	m := make([][]bool, size)
	for i := range m {
		m[i] = make([]bool, size)
		copy(m[i], matrix[i])
	}
	return m
}

func applyMask(matrix, reserved [][]bool, mask, size int) {
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			if !reserved[r][c] && maskFunc(mask, r, c) {
				matrix[r][c] = !matrix[r][c]
			}
		}
	}
}

// evaluatePenalty computes the QR penalty score for mask selection.
func evaluatePenalty(matrix [][]bool, size int) int {
	score := 0

	// Rule 1: Runs of same color in row/col (5+ consecutive)
	for r := 0; r < size; r++ {
		run := 1
		for c := 1; c < size; c++ {
			if matrix[r][c] == matrix[r][c-1] {
				run++
			} else {
				if run >= 5 {
					score += run - 2
				}
				run = 1
			}
		}
		if run >= 5 {
			score += run - 2
		}
	}
	for c := 0; c < size; c++ {
		run := 1
		for r := 1; r < size; r++ {
			if matrix[r][c] == matrix[r-1][c] {
				run++
			} else {
				if run >= 5 {
					score += run - 2
				}
				run = 1
			}
		}
		if run >= 5 {
			score += run - 2
		}
	}

	// Rule 2: 2x2 blocks of same color
	for r := 0; r < size-1; r++ {
		for c := 0; c < size-1; c++ {
			v := matrix[r][c]
			if matrix[r][c+1] == v && matrix[r+1][c] == v && matrix[r+1][c+1] == v {
				score += 3
			}
		}
	}

	// Rule 3: Finder-like patterns (simplified)
	finderLike := [2][11]bool{
		{true, false, true, true, true, false, true, false, false, false, false},
		{false, false, false, false, true, false, true, true, true, false, true},
	}
	for r := 0; r < size; r++ {
		for c := 0; c <= size-11; c++ {
			for _, pattern := range finderLike {
				match := true
				for i := 0; i < 11; i++ {
					if matrix[r][c+i] != pattern[i] {
						match = false
						break
					}
				}
				if match {
					score += 40
				}
			}
		}
	}
	for c := 0; c < size; c++ {
		for r := 0; r <= size-11; r++ {
			for _, pattern := range finderLike {
				match := true
				for i := 0; i < 11; i++ {
					if matrix[r+i][c] != pattern[i] {
						match = false
						break
					}
				}
				if match {
					score += 40
				}
			}
		}
	}

	// Rule 4: Proportion of dark modules
	dark := 0
	total := size * size
	for r := 0; r < size; r++ {
		for c := 0; c < size; c++ {
			if matrix[r][c] {
				dark++
			}
		}
	}
	pct := (dark * 100) / total
	prev5 := (pct / 5) * 5
	next5 := prev5 + 5
	a := prev5 - 50
	b := next5 - 50
	if a < 0 {
		a = -a
	}
	if b < 0 {
		b = -b
	}
	minDev := a
	if b < minDev {
		minDev = b
	}
	score += (minDev / 5) * 10

	return score
}

// --- Format information ---

// Format info for level M (ECC level 00) with mask patterns 0-7
// Pre-computed with BCH error correction and XOR mask 0x5412
var formatInfoBits = [8]uint{
	0x5412 ^ bchFormat(0b00000),
	0x5412 ^ bchFormat(0b00001),
	0x5412 ^ bchFormat(0b00010),
	0x5412 ^ bchFormat(0b00011),
	0x5412 ^ bchFormat(0b00100),
	0x5412 ^ bchFormat(0b00101),
	0x5412 ^ bchFormat(0b00110),
	0x5412 ^ bchFormat(0b00111),
}

func bchFormat(data uint) uint {
	// BCH(15,5) encoding for format information
	val := data << 10
	gen := uint(0b10100110111) // generator polynomial for BCH(15,5)
	for i := 14; i >= 10; i-- {
		if val&(1<<uint(i)) != 0 {
			val ^= gen << uint(i-10)
		}
	}
	return (data << 10) | val
}

func writeFormatInfo(matrix [][]bool, mask, size int) {
	bits := formatInfoBits[mask]

	// Format info positions around top-left finder
	// Horizontal: cols 0-7 (skip col 6), row 8
	hPos := []struct{ r, c int }{
		{8, 0}, {8, 1}, {8, 2}, {8, 3}, {8, 4}, {8, 5},
		{8, 7}, {8, 8},
	}
	// Vertical: rows 0-7 (skip row 6), col 8
	vPos := []struct{ r, c int }{
		{0, 8}, {1, 8}, {2, 8}, {3, 8}, {4, 8}, {5, 8},
		{7, 8}, {8, 8},
	}

	// Write around top-left
	for i, p := range hPos {
		matrix[p.r][p.c] = (bits>>uint(14-i))&1 == 1
	}
	for i, p := range vPos {
		matrix[p.r][p.c] = (bits>>uint(i))&1 == 1
	}

	// Write along top-right (row 8, cols size-8 to size-1)
	for i := 0; i < 7; i++ {
		matrix[8][size-7+i] = (bits>>uint(14-8-i))&1 == 1
	}

	// Write along bottom-left (rows size-7 to size-1, col 8)
	for i := 0; i < 7; i++ {
		matrix[size-7+i][8] = (bits>>uint(8+i))&1 == 1
	}

	// Dark module
	matrix[size-8][8] = true
}
