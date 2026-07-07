// Package main provides an independent Go-based canonicalization check for
// adversarial test vectors in the Receipt Chain Verification Protocol v0.1.
//
// It reads receipt body JSON from test-vector files and produces canonical bytes
// following the same RFC 8785 / JCS subset rules as the Python verifier, then
// compares against expected hex values.
//
// This is NOT a complete RFC 8785 implementation. It covers the v0.1 subset
// needed for the four adversarial canonicalization vectors.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

var vectors = []string{
	"TV-012-canonical-key-ordering",
	"TV-013-canonical-unicode-string",
	"TV-016-string-escape-forms",
	"TV-017-nested-object-key-collation",
}

func main() {
	repoRoot := flag.String("repo-root", ".", "Path to the repository root")
	flag.Parse()

	allPass := true
	for _, vec := range vectors {
		pass, err := checkVector(*repoRoot, vec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR %s: %v\n", vec, err)
			allPass = false
			continue
		}
		if pass {
			fmt.Printf("PASS %s\n", vec)
		} else {
			allPass = false
		}
	}

	if !allPass {
		os.Exit(1)
	}
}

func checkVector(repoRoot, vecName string) (bool, error) {
	vecDir := filepath.Join(repoRoot, "test-vectors", vecName)

	// Load receipts.json
	receiptsPath := filepath.Join(vecDir, "receipts.json")
	receiptsData, err := os.ReadFile(receiptsPath)
	if err != nil {
		return false, fmt.Errorf("reading receipts.json: %w", err)
	}

	// Parse as generic JSON to preserve exact types
	var receipts []map[string]interface{}
	if err := json.Unmarshal(receiptsData, &receipts); err != nil {
		return false, fmt.Errorf("parsing receipts.json: %w", err)
	}

	if len(receipts) == 0 {
		return false, fmt.Errorf("no receipts found")
	}

	body, ok := receipts[0]["body"]
	if !ok {
		return false, fmt.Errorf("first receipt has no body")
	}

	// Canonicalize the body
	canonical, err := canonicalize(body)
	if err != nil {
		return false, fmt.Errorf("canonicalization: %w", err)
	}
	goHex := hex.EncodeToString(canonical)

	// Load expected.json
	expectedPath := filepath.Join(vecDir, "expected.json")
	expectedData, err := os.ReadFile(expectedPath)
	if err != nil {
		return false, fmt.Errorf("reading expected.json: %w", err)
	}

	var expected map[string]interface{}
	if err := json.Unmarshal(expectedData, &expected); err != nil {
		return false, fmt.Errorf("parsing expected.json: %w", err)
	}

	pythonHex, _ := expected["python_expected_canonical_hex"].(string)
	goExpectedHex, _ := expected["go_expected_canonical_hex"].(string)

	pass := true

	if pythonHex == "" {
		fmt.Fprintf(os.Stderr, "  SKIP %s: no python_expected_canonical_hex\n", vecName)
	} else if goHex != pythonHex {
		fmt.Fprintf(os.Stderr, "FAIL %s: Go output differs from python_expected_canonical_hex\n", vecName)
		fmt.Fprintf(os.Stderr, "  Go:     %s\n", truncate(goHex, 120))
		fmt.Fprintf(os.Stderr, "  Python: %s\n", truncate(pythonHex, 120))
		pass = false
	}

	if goExpectedHex != "" && goHex != goExpectedHex {
		fmt.Fprintf(os.Stderr, "FAIL %s: Go output differs from go_expected_canonical_hex\n", vecName)
		pass = false
	}

	return pass, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// --- JCS-subset canonicalizer ---

func canonicalize(v interface{}) ([]byte, error) {
	var sb strings.Builder
	if err := serializeValue(&sb, v); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

func serializeValue(sb *strings.Builder, v interface{}) error {
	switch val := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if val {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case float64:
		// JSON numbers from encoding/json are float64
		if math.IsNaN(val) || math.IsInf(val, 0) {
			return fmt.Errorf("NaN/Infinity not supported")
		}
		// Check if it's an integer value
		if val == math.Trunc(val) && math.Abs(val) < 1e15 {
			sb.WriteString(strconv.FormatInt(int64(val), 10))
		} else {
			return fmt.Errorf("floating-point values forbidden in v0.1")
		}
	case json.Number:
		sb.WriteString(val.String())
	case string:
		serializeString(sb, val)
	case []interface{}:
		sb.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := serializeValue(sb, item); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sortKeysJCS(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			serializeString(sb, k)
			sb.WriteByte(':')
			if err := serializeValue(sb, val[k]); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return fmt.Errorf("unsupported type: %T", v)
	}
	return nil
}

func serializeString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if r < 0x20 {
				sb.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

// sortKeysJCS sorts keys by UTF-16 code unit order per RFC 8785.
func sortKeysJCS(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		return compareUTF16(keys[i], keys[j]) < 0
	})
}

// compareUTF16 compares two strings by their UTF-16 code unit sequences.
func compareUTF16(a, b string) int {
	aUnits := toUTF16(a)
	bUnits := toUTF16(b)

	minLen := len(aUnits)
	if len(bUnits) < minLen {
		minLen = len(bUnits)
	}

	for i := 0; i < minLen; i++ {
		if aUnits[i] < bUnits[i] {
			return -1
		}
		if aUnits[i] > bUnits[i] {
			return 1
		}
	}

	if len(aUnits) < len(bUnits) {
		return -1
	}
	if len(aUnits) > len(bUnits) {
		return 1
	}
	return 0
}

func toUTF16(s string) []uint16 {
	runes := []rune(s)
	return utf16.Encode(runes)
}
