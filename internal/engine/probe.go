package engine

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/ory/oathkeeper/driver/configuration"
)

// Probe generation. Probes are only *inputs*: whether a probe matches a rule
// is always decided by rule.Rule.IsMatching. The helpers below merely guess
// strings that are likely to sit inside, next to, or just outside each
// pattern so the real matcher has something meaningful to judge.

const (
	maxSamplesPerSegment = 48
	maxProbesPerRule     = 256
	maxGenerated         = 8
)

// segment is a piece of a pattern: literal text or the body of a <...> group.
type segment struct {
	regex bool
	text  string
}

// splitPattern splits on first-level '<' '>' like ladon's delimiterIndices.
// Only used to build probes; unbalanced patterns never get here because the
// real compiler rejects them first.
func splitPattern(p string) []segment {
	var segs []segment
	level, start, last := 0, 0, 0
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '<':
			if level++; level == 1 {
				start = i
			}
		case '>':
			if level--; level == 0 {
				if start > last {
					segs = append(segs, segment{text: p[last:start]})
				}
				segs = append(segs, segment{regex: true, text: p[start+1 : i]})
				last = i + 1
			}
		}
	}
	if last < len(p) {
		segs = append(segs, segment{text: p[last:]})
	}
	return segs
}

// hostKey returns the literal host of a pattern, or "" when the host is
// (partly) a pattern and the rule may therefore match any host. A group before
// "://" is accepted only when it is scheme-like (e.g. <https?>), because a
// broader group could swallow a host of its own.
func hostKey(p string) string {
	for _, s := range splitPattern(p) {
		if s.regex {
			if !schemeRe.MatchString(s.text) {
				return ""
			}
			continue
		}
		i := strings.Index(s.text, "://")
		if i < 0 {
			return ""
		}
		rest := s.text[i+3:]
		j := strings.IndexByte(rest, '/')
		if j < 0 {
			return "" // host continues into a group
		}
		return rest[:j]
	}
	return ""
}

var schemeRe = regexp.MustCompile(`^[A-Za-z?|()]+$`)

// baseSamples are generic values tried in every regex segment, including edge
// cases: empty, separators, nested paths, dotted names, ids.
var baseSamples = []string{
	"", "x", "a", "0", "1", "42", "abc", "http", "https", "api", "v1", "v2",
	"x/y", "a/b/c", "x.json", "index.html", "-", "_", "/", "x/", "/x",
	"health", "healthz", "admin", "login", "static/app.js",
	"3fa85f64-5717-4562-b3fc-2c963f66afa6", "localhost", "example.com",
}

var tokenRe = regexp.MustCompile(`[A-Za-z0-9_.-]{2,}`)

// corpusTokens extracts literal words from every pattern (path pieces and words
// inside regex groups such as the "health" of (?!health)), plus known hosts.
func corpusTokens(patterns, hosts []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, h := range hosts {
		add(h)
	}
	for _, p := range patterns {
		for _, s := range splitPattern(p) {
			if s.regex {
				for _, t := range tokenRe.FindAllString(stripEscapes(s.text), -1) {
					add(t)
				}
				continue
			}
			for _, part := range strings.Split(s.text, "/") {
				if part != "" && !strings.Contains(part, ":") {
					add(part)
				}
			}
		}
	}
	return out
}

// stripEscapes drops backslash escapes (\d, \w, \.) so they do not become
// tokens like "d" glued to neighbours.
func stripEscapes(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			b.WriteByte(' ')
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// segmentSamples returns candidate values that fully match one regex group on
// its own (checked with regexp2 in RE2 mode, as ladon compiles it).
func segmentSamples(body string, tokens []string) []string {
	re, err := regexp2.Compile("^(?:"+body+")$", regexp2.RE2)
	if err != nil {
		return nil
	}
	re.MatchTimeout = 50 * time.Millisecond
	seen := map[string]bool{}
	var out []string
	try := func(c string) {
		if len(out) >= maxSamplesPerSegment || seen[c] {
			return
		}
		seen[c] = true
		if ok, err := re.MatchString(c); err == nil && ok {
			out = append(out, c)
		}
	}
	for _, g := range generate(body) {
		try(g)
	}
	for _, t := range tokens {
		try(t)
		try(t + "/x")
		try(t + "x")
		try("x/" + t)
	}
	for _, b := range baseSamples {
		try(b)
	}
	return out
}

// probesFor builds probe URLs for one pattern: every group at its first sample,
// then each group walked through all its samples while the others stay fixed.
// Under glob only the dictionary is used and nothing is pre-filtered.
func probesFor(pattern string, tokens []string, strategy configuration.MatchingStrategy) []string {
	segs := splitPattern(pattern)
	samples := make([][]string, len(segs))
	var regexIdx []int
	for i, s := range segs {
		if !s.regex {
			continue
		}
		if strategy == configuration.Glob {
			samples[i] = globSamples(tokens)
		} else {
			samples[i] = segmentSamples(s.text, tokens)
		}
		if len(samples[i]) == 0 {
			samples[i] = []string{"x"}
		}
		regexIdx = append(regexIdx, i)
	}
	build := func(vary, pick int) string {
		var b strings.Builder
		for i, s := range segs {
			switch {
			case !s.regex:
				b.WriteString(s.text)
			case i == vary:
				b.WriteString(samples[i][pick])
			default:
				b.WriteString(samples[i][0])
			}
		}
		return b.String()
	}
	out := []string{build(-1, 0)}
	for _, i := range regexIdx {
		for k := range samples[i] {
			if len(out) >= maxProbesPerRule {
				return out
			}
			out = append(out, build(i, k))
		}
	}
	return out
}

func globSamples(tokens []string) []string {
	out := append([]string{}, baseSamples...)
	for _, t := range tokens {
		if len(out) >= maxSamplesPerSegment*2 {
			break
		}
		out = append(out, t, t+"/x")
	}
	return out
}

// generate derives a few example strings from the regex structure (Go's
// regexp/syntax parser, lookarounds removed first). Best effort: when the
// syntax is not understood it returns nothing and the dictionary takes over.
func generate(body string) []string {
	re, err := syntax.Parse(stripLookarounds(body), syntax.Perl)
	if err != nil {
		return nil
	}
	return gen(re.Simplify())
}

func gen(re *syntax.Regexp) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}
	case syntax.OpCharClass:
		return classReps(re.Rune)
	case syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return []string{"x", "/"}
	case syntax.OpCapture:
		return gen(re.Sub[0])
	case syntax.OpStar:
		s := gen(re.Sub[0])
		return capList(append([]string{""}, append(s, repeat(s, 2)...)...))
	case syntax.OpPlus:
		s := gen(re.Sub[0])
		return capList(append(s, repeat(s, 2)...))
	case syntax.OpQuest:
		return capList(append([]string{""}, gen(re.Sub[0])...))
	case syntax.OpRepeat:
		s := gen(re.Sub[0])
		out := repeat(s, re.Min)
		if re.Max == -1 || re.Max > re.Min {
			out = append(out, repeat(s, re.Min+1)...)
		}
		return capList(out)
	case syntax.OpConcat:
		acc := []string{""}
		for _, sub := range re.Sub {
			var next []string
			for _, a := range acc {
				for _, b := range gen(sub) {
					next = append(next, a+b)
				}
			}
			acc = capList(next)
		}
		return acc
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			out = append(out, gen(sub)...)
		}
		return capList(out)
	}
	return []string{""}
}

func repeat(s []string, n int) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		out = append(out, strings.Repeat(v, n))
	}
	return out
}

func capList(s []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, maxGenerated)
	for _, v := range s {
		if !seen[v] && len(out) < maxGenerated {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// classReps picks printable representatives of a character class, preferring
// common URL characters.
func classReps(ranges []rune) []string {
	in := func(r rune) bool {
		for i := 0; i+1 < len(ranges); i += 2 {
			if r >= ranges[i] && r <= ranges[i+1] {
				return true
			}
		}
		return false
	}
	var out []string
	for _, r := range "ax0Z-_./" {
		if in(r) && len(out) < 2 {
			out = append(out, string(r))
		}
	}
	if len(out) == 0 {
		for i := 0; i+1 < len(ranges); i += 2 {
			for r := ranges[i]; r <= ranges[i+1] && r < 0x7f; r++ {
				if r > 0x20 {
					return []string{string(r)}
				}
			}
		}
	}
	return out
}

// stripLookarounds removes (?=...) and (?!...) groups, which Go's parser does
// not support; the regexp2 check in segmentSamples re-applies them.
func stripLookarounds(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			b.WriteString(s[i : i+2])
			i++
			continue
		}
		if strings.HasPrefix(s[i:], "(?=") || strings.HasPrefix(s[i:], "(?!") {
			i = skipGroup(s, i)
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// skipGroup returns the index of the ')' closing the group opened at s[i].
func skipGroup(s string, i int) int {
	depth, inClass := 0, false
	for ; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
		case inClass:
			inClass = c != ']'
		case c == '[':
			inClass = true
		case c == '(':
			depth++
		case c == ')':
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return len(s)
}
