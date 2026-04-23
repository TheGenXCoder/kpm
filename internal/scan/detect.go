package scan

import (
	"math"
	"strings"
)

// NewNameDetector returns a detector that matches variable names.
func NewNameDetector(mode Mode) Detector {
	patterns := append([]string{}, namePatternsHighConfidence...)
	if mode == ModeParanoid {
		patterns = append(patterns, namePatternsParanoid...)
	}
	return &nameDetector{patterns: patterns}
}

type nameDetector struct {
	patterns []string
}

func (nameDetector) Name() string { return "name" }

func (d *nameDetector) Detect(name, _ string) (bool, string) {
	if nameDenyList[strings.ToUpper(name)] {
		return false, ""
	}
	upper := strings.ToUpper(name)
	for _, p := range d.patterns {
		if matchGlob(upper, strings.ToUpper(p)) {
			return true, "name:" + strings.ToLower(strings.Trim(p, "*_"))
		}
	}
	return false, ""
}

// matchGlob supports leading *, trailing *, both, and exact.
func matchGlob(s, pat string) bool {
	leading := strings.HasPrefix(pat, "*")
	trailing := strings.HasSuffix(pat, "*")
	core := strings.Trim(pat, "*")
	if core == "" {
		return false
	}
	switch {
	case leading && trailing:
		return strings.Contains(s, core)
	case leading:
		return strings.HasSuffix(s, core)
	case trailing:
		return strings.HasPrefix(s, core)
	default:
		return s == core
	}
}

// NewValueDetector returns a detector that matches values against vendor patterns.
func NewValueDetector(mode Mode) Detector {
	patterns := append([]valuePattern{}, valuePatternsHighConfidence...)
	if mode == ModeParanoid {
		patterns = append(patterns, valuePatternsParanoid...)
	}
	return &valueDetector{patterns: patterns}
}

type valueDetector struct {
	patterns []valuePattern
}

func (valueDetector) Name() string { return "value" }

func (d *valueDetector) Detect(_ string, value string) (bool, string) {
	for _, p := range d.patterns {
		if p.regex.MatchString(value) {
			return true, p.id
		}
	}
	return false, ""
}

// NewEntropyDetector returns a Shannon-entropy detector. Active only in paranoid.
func NewEntropyDetector(mode Mode) Detector {
	return &entropyDetector{active: mode == ModeParanoid}
}

type entropyDetector struct {
	active bool
}

func (entropyDetector) Name() string { return "entropy" }

func (d *entropyDetector) Detect(_ string, value string) (bool, string) {
	if !d.active {
		return false, ""
	}
	if len(value) < 20 {
		return false, ""
	}
	if shannonEntropy(value) > 4.5 {
		return true, "entropy"
	}
	return false, ""
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	length := float64(len([]rune(s)))
	var h float64
	for _, c := range counts {
		p := float64(c) / length
		h -= p * math.Log2(p)
	}
	return h
}

// DetectorsFor returns all detectors appropriate for the given mode.
func DetectorsFor(mode Mode) []Detector {
	return []Detector{
		NewNameDetector(mode),
		NewValueDetector(mode),
		NewEntropyDetector(mode),
	}
}
