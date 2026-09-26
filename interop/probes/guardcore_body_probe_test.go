//go:build interop

package guardcore

// Body-surface probe for the interop extraction differential and body
// detect vector runners (interop/extraction_differential.py and
// interop/body_detect_vectors.py in the guard-core reference checkout).
//
// The file is NOT part of the repository: the runners mount it into the
// checkout inside the golang container (docker -v probe.go:/app/guardcore/
// guardcore_body_probe_test.go), so the audited detection code is exactly
// master and nothing is written to the working tree.
//
// Modes (env-selected):
//
//   INTEROP_EXTRACTION_INPUT / _OUTPUT: one body per vector, the values of
//   extractBodyScanValues emitted in scan order as
//   [[value_b64, context, forcedCategory], ...].
//
//   INTEROP_BODY_DETECT_INPUT / _OUTPUT: the pipeline's suspicious-activity
//   body scan (detectThreat's extraction + per-value Detect loop) emitting
//   is_threat plus the first collected categories.
//
//   INTEROP_MIDDLEWARE_INPUT / _OUTPUT: the full suspiciousActivityCheck
//   built like pipeline_test.go does, Check() on a body-carrying request,
//   emitting blocked plus the status code.
//
// Body bytes become a Go string with invalid UTF-8 mapped to U+FFFD, the
// engine's own binary-body representation.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"
	"testing"
)

func probeConfig() *SecurityConfig {
	cfg, err := NewSecurityConfig(func(c *SecurityConfig) {
		c.AutoBanThreshold = 100
		c.AutoBanDuration = 600
	})
	if err != nil {
		panic(err)
	}
	return cfg
}

type bodyProbeVector struct {
	Label       string            `json:"label"`
	BodyB64     string            `json:"body_b64"`
	ContentType string            `json:"content_type"`
	Query       map[string]string `json:"query"`
	URLPath     string            `json:"url_path"`
}

func readBodyVectors(t *testing.T, envKey string) []bodyProbeVector {
	t.Helper()
	path := os.Getenv(envKey)
	if path == "" {
		t.Fatalf("%s must be set", envKey)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", envKey, err)
	}
	var vectors []bodyProbeVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("input is not valid JSON: %v", envKey)
	}
	return vectors
}

func writeProbeOutput(t *testing.T, envKey string, payload any) {
	t.Helper()
	path := os.Getenv(envKey)
	if path == "" {
		t.Fatalf("%s must be set", envKey)
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", envKey, err)
	}
}

func TestGuardCoreBodyProbe(t *testing.T) {
	switch {
	case os.Getenv("INTEROP_EXTRACTION_INPUT") != "":
		runExtractionProbe(t)
	case os.Getenv("INTEROP_BODY_DETECT_INPUT") != "":
		runBodyDetectProbe(t)
	case os.Getenv("INTEROP_MIDDLEWARE_INPUT") != "":
		runMiddlewareProbe(t)
	default:
		t.Fatal("no probe mode selected")
	}
}

func runExtractionProbe(t *testing.T) {
	vectors := readBodyVectors(t, "INTEROP_EXTRACTION_INPUT")
	cfg := probeConfig()
	type entryOut struct {
		ValueB64 string `json:"v"`
		Context  string `json:"c"`
		Forced   string `json:"f"`
	}
	out := make([]map[string]any, 0, len(vectors))
	for _, v := range vectors {
		body, err := base64.StdEncoding.DecodeString(v.BodyB64)
		if err != nil {
			t.Fatalf("vector %q body_b64: %v", v.Label, err)
		}
		values := extractBodyScanValues(string(body), v.ContentType, cfg)
		entries := make([]entryOut, 0, len(values))
		for _, value := range values {
			entries = append(entries, entryOut{
				ValueB64: base64.StdEncoding.EncodeToString([]byte(value.content)),
				Context:  value.context,
				Forced:   value.forcedCategory,
			})
		}
		out = append(out, map[string]any{"label": v.Label, "entries": entries})
	}
	writeProbeOutput(t, "INTEROP_EXTRACTION_OUTPUT", out)
}

// runBodyDetectProbe mirrors detectThreat's body loop: first forced or
// detected value wins, and a value whose categories are all disabled ends
// the scan with no threat, exactly like pipeline.go.
func runBodyDetectProbe(t *testing.T) {
	vectors := readBodyVectors(t, "INTEROP_BODY_DETECT_INPUT")
	cfg := probeConfig()
	enabled := map[string]bool{}
	for _, category := range cfg.EnabledDetectionCategories {
		enabled[category] = true
	}
	out := make([]map[string]any, 0, len(vectors))
	for _, v := range vectors {
		body, err := base64.StdEncoding.DecodeString(v.BodyB64)
		if err != nil {
			t.Fatalf("vector %q body_b64: %v", v.Label, err)
		}
		values := extractBodyScanValues(string(body), v.ContentType, cfg)
		isThreat := false
		categories := []string{}
		threats := []map[string]string{}
		for _, value := range values {
			if value.forcedCategory != "" {
				isThreat = true
				categories = append(categories, value.forcedCategory)
				threats = append(threats, map[string]string{
					"category": value.forcedCategory,
					"pattern":  "mongo_operator_key",
				})
				break
			}
			result := Detect(value.content, "127.0.0.1", value.context)
			if !result.IsThreat {
				continue
			}
			seen := map[string]bool{}
			for _, threat := range result.Threats {
				category, _ := threat["category"].(string)
				if category == "" || !enabled[category] || seen[category] {
					continue
				}
				seen[category] = true
				categories = append(categories, category)
				pattern, _ := threat["pattern"].(string)
				threats = append(threats, map[string]string{
					"category": category,
					"pattern":  pattern,
				})
			}
			if len(categories) == 0 {
				isThreat = false
				break
			}
			isThreat = true
			break
		}
		sort.Strings(categories)
		out = append(out, map[string]any{
			"label":      v.Label,
			"is_threat":  isThreat,
			"categories": categories,
			"threats":    threats,
		})
	}
	writeProbeOutput(t, "INTEROP_BODY_DETECT_OUTPUT", out)
}

// runMiddlewareProbe builds the real suspiciousActivityCheck like
// pipeline_test.go does and runs Check() on a body-carrying request.
func runMiddlewareProbe(t *testing.T) {
	vectors := readBodyVectors(t, "INTEROP_MIDDLEWARE_INPUT")
	cfg := probeConfig()
	check := &suspiciousActivityCheck{
		cfg:    cfg,
		ban:    NewIPBanManager(nil, nil),
		counts: &suspiciousCountStore{m: map[string]map[string]int{}},
	}
	out := make([]map[string]any, 0, len(vectors))
	for _, v := range vectors {
		body, err := base64.StdEncoding.DecodeString(v.BodyB64)
		if err != nil {
			t.Fatalf("vector %q body_b64: %v", v.Label, err)
		}
		path := v.URLPath
		if path == "" {
			path = "/api"
		}
		req := &guardRequest{opts: RequestOptions{
			Path:        path,
			Scheme:      "http",
			Host:        "example.com",
			Method:      "POST",
			ClientHost:  "203.0.113.9",
			Header:      map[string]string{"Content-Type": v.ContentType},
			QueryParams: v.Query,
			Body:        body,
			State:       &RequestState{},
		}}
		resp := check.Check(req)
		blocked := resp != nil
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		out = append(out, map[string]any{
			"label":   v.Label,
			"blocked": blocked,
			"status":  status,
		})
	}
	writeProbeOutput(t, "INTEROP_MIDDLEWARE_OUTPUT", out)
}
