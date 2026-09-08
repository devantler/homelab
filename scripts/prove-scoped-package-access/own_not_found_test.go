package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An own-image 404 must not bypass the controls needed to distinguish a
// credential-specific visibility mismatch from image loss or a stale token.
func TestOwnNotFoundRechecksLiveControls(t *testing.T) {
	for _, tc := range []struct {
		fault, reason string
	}{
		{"stable", "scoped_own_manifest_not_visible_with_live_controls"},
		{"baseline-missing", "baseline_postcheck_unavailable"},
		{"baseline-disappears-after-repeat", "baseline_postcheck_unavailable"},
		{"scope-invalid", "token_repository_scope_postcheck_unverified"},
		{"scope-empty", "token_repository_scope_postcheck_unverified"},
		{"scope-partial", "token_repository_scope_postcheck_unverified"},
		{"scope-wide", "token_repository_scope_postcheck_unverified"},
		{"scope-foreign", "token_repository_scope_postcheck_unverified"},
		{"candidate-recovers", "scoped_own_postcheck_changed"},
		{"candidate-denied", "scoped_own_postcheck_changed"},
		{"candidate-unavailable", "scoped_own_postcheck_changed"},
		{"candidate-token-missing", "scoped_own_postcheck_changed"},
	} {
		t.Run(tc.fault, func(t *testing.T) {
			const manifest = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`
			digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(manifest)))
			var candidateReads, baselineChecks, scopeChecks int
			var trace []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/installation/repositories":
					if r.Header.Get("Authorization") != "Bearer scoped-secret" {
						t.Error("scope checked with the wrong identity")
					}
					if candidateReads > 0 {
						scopeChecks++
						trace = append(trace, "scope")
						switch tc.fault {
						case "scope-invalid":
							w.WriteHeader(401)
							return
						case "scope-empty":
							_, _ = fmt.Fprint(w, `{}`)
							return
						case "scope-partial":
							_, _ = fmt.Fprint(w, `{"total_count":1}`)
							return
						case "scope-wide":
							_, _ = fmt.Fprint(w, `{"total_count":2,"repositories":[{"full_name":"devantler-tech/wedding-app"},{"full_name":"devantler-tech/ascoachingogvaner"}]}`)
							return
						case "scope-foreign":
							_, _ = fmt.Fprint(w, `{"total_count":1,"repositories":[{"full_name":"devantler-tech/ascoachingogvaner"}]}`)
							return
						}
					}
					_, _ = fmt.Fprint(w, `{"total_count":1,"repositories":[{"full_name":"devantler-tech/wedding-app"}]}`)
				case strings.HasPrefix(r.URL.Path, "/orgs/devantler-tech/packages/container/"):
					repository := strings.TrimPrefix(r.URL.Path, "/orgs/devantler-tech/packages/container/")
					_, _ = fmt.Fprintf(w, `{"name":%q,"package_type":"container","visibility":"private","owner":{"login":"devantler-tech"},"repository":{"full_name":%q}}`, repository, "devantler-tech/"+repository)
				case r.URL.Path == "/token":
					_, secret, _ := r.BasicAuth()
					if secret == "scoped-secret" && candidateReads > 0 && tc.fault == "candidate-token-missing" {
						w.WriteHeader(404)
						return
					}
					if secret == "" {
						w.WriteHeader(401)
						_, _ = fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED"}]}`)
						return
					}
					_, _ = fmt.Fprintf(w, `{"token":%q}`, secret)
				case strings.Contains(r.URL.Path, "/manifests/"):
					identity := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					if identity == "scoped-secret" {
						if r.URL.Path != "/v2/devantler-tech/wedding-app/manifests/"+digest {
							t.Errorf("candidate read escaped the own immutable image: %s", r.URL.Path)
						}
						candidateReads++
						trace = append(trace, "candidate")
						if candidateReads > 1 {
							switch tc.fault {
							case "candidate-recovers":
								_, _ = fmt.Fprint(w, manifest)
								return
							case "candidate-denied":
								w.WriteHeader(403)
								_, _ = fmt.Fprint(w, `{"errors":[{"code":"DENIED"}]}`)
								return
							case "candidate-unavailable":
								w.WriteHeader(503)
								return
							}
						}
						w.WriteHeader(404)
						_, _ = fmt.Fprint(w, `{"errors":[{"code":"MANIFEST_UNKNOWN","message":"scoped-secret baseline-secret ::error::untrusted"}]}`)
						return
					}
					if candidateReads > 0 {
						baselineChecks++
						trace = append(trace, "baseline")
						if identity != "baseline-secret" || r.URL.Path != "/v2/devantler-tech/wedding-app/manifests/"+digest {
							t.Error("postcheck did not use the independent baseline and exact own digest")
						}
						if tc.fault == "baseline-missing" || (candidateReads > 1 && tc.fault == "baseline-disappears-after-repeat") {
							w.WriteHeader(404)
							return
						}
					}
					_, _ = fmt.Fprint(w, manifest)
				default:
					t.Errorf("unexpected request: %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			var output bytes.Buffer
			p := proof{apiURL: server.URL, registryURL: server.URL, client: restrictedClient(), output: &output,
				baseline: credential{"baseline-user", "baseline-secret"}, scoped: credential{"x-access-token", "scoped-secret"},
				pull: func(_ context.Context, auth credential, image string) error {
					if auth.password != "baseline-secret" || !strings.HasSuffix(image, "@"+digest) {
						t.Error("404 path attempted an unproven candidate pull or mutable image")
					}
					return nil
				}}
			if got := p.run(context.Background()); got != 2 {
				t.Errorf("own 404 became a conclusive verdict: %d", got)
			}
			if !strings.Contains(output.String(), "reason="+tc.reason) {
				t.Errorf("missing controlled diagnosis %q: %s", tc.reason, output.String())
			}
			if tc.fault == "stable" {
				if candidateReads != 2 || baselineChecks != 2 || scopeChecks != 1 || strings.Join(trace, ",") != "candidate,baseline,candidate,baseline,scope" {
					t.Errorf("stable result lacked bounded, bracketed live controls: %v", trace)
				}
				if !strings.Contains(output.String(), "registry_phase=manifest http_status=404 failure_class=http_status") {
					t.Errorf("lost original safe diagnosis: %s", output.String())
				}
			}
			for _, forbidden := range []string{"secret", "::error::", server.URL} {
				if strings.Contains(output.String(), forbidden) {
					t.Errorf("raw data leaked in proof result: %s", output.String())
				}
			}
		})
	}
}
