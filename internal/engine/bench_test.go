package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ory/oathkeeper/driver/configuration"
)

// benchRules is a Site-shaped rule set: per host an API gate (enumeration),
// a web catch-all (negative lookahead) and a preflight rule.
func benchRules(b *testing.B, hosts int) [][]byte {
	var out [][]byte
	for i := 0; i < hosts; i++ {
		h := fmt.Sprintf("app%d.dev.example.com", i)
		for _, r := range []string{
			`{"id":"%[1]s-api","match":{"url":"<https?>://%[1]s/<(api|admin)(/.*)?>","methods":["GET","POST","PUT","DELETE"]}}`,
			`{"id":"%[1]s-web","match":{"url":"<https?>://%[1]s/<(?!(api|admin)(/|$)).*>","methods":["GET","POST"]}}`,
			`{"id":"%[1]s-cors","match":{"url":"<https?>://%[1]s/<.*>","methods":["OPTIONS"]}}`,
		} {
			out = append(out, []byte(fmt.Sprintf(r, h)))
		}
	}
	return out
}

func BenchmarkOverlap150Rules(b *testing.B) {
	var raw []json.RawMessage
	for _, r := range benchRules(b, 50) {
		raw = append(raw, r)
	}
	for i := 0; i < b.N; i++ {
		rs, err := ParseRules(raw)
		if err != nil {
			b.Fatal(err)
		}
		res, err := FindOverlaps(context.Background(), rs, nil, nil, configuration.Regexp)
		if err != nil || len(res.Overlaps) != 0 {
			b.Fatalf("%v %+v", err, res.Overlaps)
		}
	}
}
