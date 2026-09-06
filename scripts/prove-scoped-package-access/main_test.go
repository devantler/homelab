package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMissingResultCannotPass models a runner losing the experiment's output stream.
func TestMissingResultCannotPass(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	if got := (proof{output: writer}).result(0, "own_full_pull_and_cross_package_denial_verified"); got != 2 {
		t.Fatalf("missing result returned %d, want UNKNOWN", got)
	}
}

// The registry serves the SAME immutable manifests to each identity. Only its
// authorization decision varies, so absence and availability cannot stand in
// for a working repository boundary.
func TestProofRequiresBothDirectionsAndIndependentControls(t *testing.T) {
	for _, tc := range []struct {
		name, fault string
		want        int
	}{
		{"scoped own pull and cross denial", "", 0},
		{"cross package readable is a failed boundary", "cross-readable", 1},
		{"valid scoped token cannot read its own package", "own-denied", 1},
		{"public cross package is not a negative control", "public", 2},
		{"wrong package repository association", "wrong-link", 2},
		{"missing package metadata", "metadata-404", 2},
		{"metadata permission denied", "metadata-403", 2},
		{"extra repository in installation token", "wide-token", 2},
		{"truncated repository listing", "partial-token", 2},
		{"single foreign repository in installation token", "wrong-repository-token", 2},
		{"missing independent credential", "no-baseline", 2},
		{"same credential is not an independent control", "same-token", 2},
		{"invalid scoped token", "invalid-token", 2},
		{"baseline cannot pull", "baseline-pull", 2},
		{"baseline token authorization denied", "baseline-token-denied", 2},
		{"baseline token denied after cross check", "baseline-token-denied-after-cross", 2},
		{"baseline manifest authorization denied", "baseline-manifest-denied", 2},
		{"baseline manifest denied after cross check", "baseline-manifest-denied-after-cross", 2},
		{"own full pull fails after manifest access", "own-pull", 2},
		{"cross 404 does not prove denial", "cross-404", 2},
		{"cross 429 does not prove denial", "cross-429", 2},
		{"cross 500 does not prove denial", "cross-500", 2},
		{"unclassified 403 does not prove denial", "cross-unclassified-403", 2},
		{"registry token response malformed", "bad-token", 2},
		{"manifest response malformed", "bad-manifest", 2},
		{"credential expires during experiment", "expired-after-cross", 2},
		{"baseline fails after cross denial", "baseline-after-cross", 2},
		{"empty scope postcheck cannot retain earlier fields", "empty-scope-postcheck", 2},
		{"partial scope postcheck cannot retain earlier fields", "partial-scope-postcheck", 2},
		{"redirect cannot receive a credential", "redirect", 2},
		{"own token exchange unclassified forbidden", "own-token-unclassified", 2},
		{"own token exchange throttled", "own-token-throttled", 2},
		{"own token exchange malformed", "own-token-malformed", 2},
		{"own token exchange missing token", "own-token-empty", 2},
		{"own manifest response malformed", "own-manifest-malformed", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var redirected, crossed bool
			const manifest = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":2},"layers":[]}`
			digest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(manifest)))
			sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected = true
				w.WriteHeader(http.StatusOK)
			}))
			defer sink.Close()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.fault == "redirect" {
					http.Redirect(w, r, sink.URL, http.StatusTemporaryRedirect)
					return
				}
				switch {
				case r.URL.Path == "/installation/repositories":
					if crossed && tc.fault == "empty-scope-postcheck" {
						_, _ = fmt.Fprint(w, `{}`)
						return
					}
					if crossed && tc.fault == "partial-scope-postcheck" {
						_, _ = fmt.Fprint(w, `{"total_count":1}`)
						return
					}
					if r.Header.Get("Authorization") != "Bearer scoped-secret" {
						t.Error("repository scope queried with the wrong credential")
					}
					if tc.fault == "invalid-token" {
						w.WriteHeader(401)
						return
					}
					count := 1
					listing := `{"full_name":"devantler-tech/wedding-app"}`
					if tc.fault == "wide-token" || tc.fault == "partial-token" {
						count = 2
					}
					if tc.fault == "wide-token" {
						listing += `,{"full_name":"devantler-tech/ascoachingogvaner"}`
					}
					if tc.fault == "wrong-repository-token" {
						listing = `{"full_name":"devantler-tech/ascoachingogvaner"}`
					}
					_, _ = fmt.Fprintf(w, `{"total_count":%d,"repositories":[%s]}`, count, listing)
				case strings.HasPrefix(r.URL.Path, "/orgs/devantler-tech/packages/container/"):
					if r.Header.Get("Authorization") != "Bearer baseline-secret" {
						t.Error("package association not checked independently")
					}
					if tc.fault == "metadata-404" {
						w.WriteHeader(404)
						return
					}
					if tc.fault == "metadata-403" {
						w.WriteHeader(403)
						return
					}
					name := strings.TrimPrefix(r.URL.Path, "/orgs/devantler-tech/packages/container/")
					linked := name
					if tc.fault == "wrong-link" {
						linked = "some-other-repository"
					}
					_, _ = fmt.Fprintf(w, `{"name":%q,"package_type":"container","visibility":"private","owner":{"login":"devantler-tech"},"repository":{"full_name":%q}}`, name, "devantler-tech/"+linked)
				case r.URL.Path == "/token":
					_, secret, _ := r.BasicAuth()
					if secret == "baseline-secret" && (tc.fault == "baseline-token-denied" || (crossed && tc.fault == "baseline-token-denied-after-cross")) {
						w.WriteHeader(401)
						_, _ = fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED","message":"baseline-secret ::error::untrusted"}]}`)
						return
					}
					if secret == "scoped-secret" {
						switch tc.fault {
						case "own-token-unclassified":
							w.WriteHeader(403)
							_, _ = fmt.Fprint(w, "scoped-secret baseline-secret ::error::untrusted")
							return
						case "own-token-throttled":
							w.WriteHeader(429)
							return
						case "own-token-malformed":
							_, _ = fmt.Fprint(w, "{scoped-secret")
							return
						case "own-token-empty":
							_, _ = fmt.Fprint(w, `{}`)
							return
						}
					}
					if tc.fault == "bad-token" {
						_, _ = fmt.Fprint(w, `{broken`)
						return
					}
					if secret == "" {
						secret = "anonymous"
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"token": secret})
				case strings.Contains(r.URL.Path, "/manifests/"):
					credential := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					own := strings.Contains(r.URL.Path, "/wedding-app/")
					if credential == "baseline-secret" && (tc.fault == "baseline-manifest-denied" || (crossed && tc.fault == "baseline-manifest-denied-after-cross")) {
						w.WriteHeader(403)
						_, _ = fmt.Fprint(w, `{"errors":[{"code":"DENIED","message":"baseline-secret ::error::untrusted"}]}`)
						return
					}
					if credential == "anonymous" && tc.fault != "public" {
						w.WriteHeader(401)
						_, _ = fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED"}]}`)
						return
					}
					if credential == "scoped-secret" {
						if own && tc.fault == "own-manifest-malformed" {
							_, _ = fmt.Fprint(w, "{baseline-secret")
							return
						}
						if own && (tc.fault == "own-denied" || (crossed && tc.fault == "expired-after-cross")) {
							w.WriteHeader(403)
							_, _ = fmt.Fprint(w, `{"errors":[{"code":"DENIED"}]}`)
							return
						}
						if !own {
							crossed = true
							switch tc.fault {
							case "cross-readable":
							case "cross-404":
								w.WriteHeader(404)
								return
							case "cross-429":
								w.WriteHeader(429)
								return
							case "cross-500":
								w.WriteHeader(500)
								return
							case "cross-unclassified-403":
								w.WriteHeader(403)
								_, _ = fmt.Fprint(w, "proxy unavailable")
								return
							default:
								w.WriteHeader(403)
								_, _ = fmt.Fprint(w, `{"errors":[{"code":"DENIED"}]}`)
								return
							}
						}
					}
					if credential == "baseline-secret" && crossed && tc.fault == "baseline-after-cross" {
						w.WriteHeader(503)
						return
					}
					w.Header().Set("Docker-Content-Digest", digest)
					if tc.fault == "bad-manifest" {
						_, _ = fmt.Fprint(w, `{broken`)
						return
					}
					_, _ = fmt.Fprint(w, manifest)
				default:
					t.Errorf("unexpected request %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			var output bytes.Buffer
			var pulls []string
			p := proof{apiURL: server.URL, registryURL: server.URL, client: restrictedClient(), output: &output,
				baseline: credential{"baseline-user", "baseline-secret"}, scoped: credential{"x-access-token", "scoped-secret"},
				pull: func(ctx context.Context, auth credential, image string) error {
					if !strings.HasSuffix(image, "@"+digest) {
						t.Errorf("pull is not bound to measured digest: %s", image)
					}
					pulls = append(pulls, auth.password+":"+image)
					if (auth.password == "baseline-secret" && tc.fault == "baseline-pull") || (auth.password == "scoped-secret" && tc.fault == "own-pull") {
						return fmt.Errorf("secret-containing raw failure baseline-secret scoped-secret")
					}
					return nil
				}}
			if tc.fault == "no-baseline" {
				p.baseline = credential{}
			}
			if tc.fault == "same-token" {
				p.baseline = p.scoped
			}
			got := p.run(context.Background())
			if got != tc.want {
				t.Errorf("exit=%d want=%d, output=%s", got, tc.want, output.String())
			}
			if tc.fault == "wrong-repository-token" && (len(pulls) != 0 || !strings.Contains(output.String(), "reason=token_repository_scope_unverified\n")) {
				t.Errorf("foreign repository scope was not rejected before any pull: pulls=%d output=%s", len(pulls), output.String())
			}
			// Losing the failed stage/status must fail these cases; raw response text cannot substitute for the classification.
			wantDiagnostic := map[string]string{
				"baseline-token-denied":                "registry_phase=token_exchange http_status=401 failure_class=authorization_denial",
				"baseline-token-denied-after-cross":    "registry_phase=token_exchange http_status=401 failure_class=authorization_denial",
				"baseline-manifest-denied":             "registry_phase=manifest http_status=403 failure_class=authorization_denial",
				"baseline-manifest-denied-after-cross": "registry_phase=manifest http_status=403 failure_class=authorization_denial",
				"expired-after-cross":                  "registry_phase=manifest http_status=403 failure_class=authorization_denial",
				"own-token-unclassified":               "registry_phase=token_exchange http_status=403 failure_class=unclassified_denial",
				"own-token-throttled":                  "registry_phase=token_exchange http_status=429 failure_class=http_status",
				"own-token-malformed":                  "registry_phase=token_exchange http_status=200 failure_class=invalid_json",
				"own-token-empty":                      "registry_phase=token_exchange http_status=200 failure_class=missing_token",
				"own-manifest-malformed":               "registry_phase=manifest http_status=200 failure_class=invalid_json",
				"cross-unclassified-403":               "registry_phase=manifest http_status=403 failure_class=unclassified_denial",
				"cross-429":                            "registry_phase=manifest http_status=429 failure_class=http_status",
				"cross-500":                            "registry_phase=manifest http_status=500 failure_class=http_status",
				"cross-404":                            "registry_phase=manifest http_status=404 failure_class=http_status",
			}[tc.fault]
			if wantDiagnostic != "" && !strings.Contains(output.String(), wantDiagnostic+"\n") {
				t.Errorf("missing safe failure diagnosis %q in %q", wantDiagnostic, output.String())
			}
			if strings.Contains(output.String(), "::error::") || strings.Contains(output.String(), server.URL) {
				t.Errorf("raw response or endpoint leaked: %q", output.String())
			}
			if strings.Contains(output.String(), "secret") {
				t.Errorf("credential or raw error leaked: %s", output.String())
			}
			if redirected {
				t.Error("followed redirect with a credential")
			}
			if tc.want == 0 && len(pulls) < 4 {
				t.Errorf("success without independent baseline pulls and repeated scoped own pull: %v", pulls)
			}
		})
	}
}

// TestInlineBaselineCredentialValidation rejects implicit or incomplete registry identities.
func TestInlineBaselineCredentialValidation(t *testing.T) {
	for _, tc := range []struct {
		name, data string
		valid      bool
	}{
		{"encoded", `{"auths":{"ghcr.io":{"auth":"dTpw"}}}`, true},
		{"explicit", `{"auths":{"ghcr.io":{"username":"u","password":"p"}}}`, true},
		{"legacy", `{"auths":{"https://ghcr.io/v1/":{"auth":"dTpw"}}}`, true},
		{"absent", `{}`, false},
		{"malformed", `{broken`, false},
		{"half", `{"auths":{"ghcr.io":{"username":"u"}}}`, false},
		{"bad encoded", `{"auths":{"ghcr.io":{"auth":"%%%%"}}}`, false},
		{"helper", `{"credsStore":"osxkeychain","auths":{"ghcr.io":{"auth":"dTpw"}}}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, "config.json"), []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			credential, err := readBaseline(directory)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, err=%v", tc.valid, err)
			}
			if tc.valid && (credential.username != "u" || credential.password != "p") {
				t.Fatal("wrong synthetic credential")
			}
		})
	}
}

// TestFullPullUsesFreshPrivateConfigAndNoAmbientCredentials exercises the subprocess boundary and cleanup.
func TestFullPullUsesFreshPrivateConfigAndNoAmbientCredentials(t *testing.T) {
	for _, exit := range []int{0, 1} {
		t.Run(fmt.Sprint(exit), func(t *testing.T) {
			directory := t.TempDir()
			capture := filepath.Join(directory, "capture")
			// Use a process fixture so argv, environment and actual file cleanup are
			// tested at the transport boundary, not through an injected classifier.
			program := fmt.Sprintf(`#!/bin/sh
set -eu
printf '%%s\n' "$@" > '%s.args'
printf '%%s' "$DOCKER_CONFIG" > '%s.path'
env > '%s.env'
cat "$DOCKER_CONFIG/config.json" > '%s.config'
printf 'fixture image tarball' > "$5"
exit %d
`, capture, capture, capture, capture, exit)
			if err := os.WriteFile(filepath.Join(directory, "crane"), []byte(program), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("SCOPED_APP_TOKEN", "ambient-secret")
			t.Setenv("DOCKER_AUTH_CONFIG", "ambient-secret")
			t.Setenv("DOCKER_CONFIG", "must-not-be-used")
			image := "ghcr.io/devantler-tech/wedding-app@sha256:" + strings.Repeat("a", 64)
			err := pullImage(context.Background(), credential{"u", "p"}, image)
			if (err == nil) != (exit == 0) {
				t.Fatalf("unexpected pull result: %v", err)
			}
			read := func(suffix string) string {
				data, err := os.ReadFile(capture + suffix)
				if err != nil {
					t.Fatal(err)
				}
				return string(data)
			}
			configPath := read(".path")
			if _, err := os.Stat(configPath); !os.IsNotExist(err) {
				t.Fatal("temporary credential/image directory survived")
			}
			if read(".args") != "pull\n--platform\nlinux/amd64\n"+image+"\n"+configPath+"/image.tar\n" {
				t.Fatalf("unexpected argv: %s", read(".args"))
			}
			if strings.Contains(read(".env"), "ambient-secret") || strings.Contains(read(".env"), "must-not-be-used") {
				t.Fatal("ambient auth forwarded")
			}
			if read(".config") != `{"auths":{"ghcr.io":{"auth":"dTpw"}}}` {
				t.Fatal("wrong pull identity")
			}
		})
	}
}

// roundTripFunc injects transport faults below the real request and manifest logic.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type failingResponseBody struct{ err error }

func (b failingResponseBody) Read([]byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	return 0, errors.New("scoped-secret ::error::raw read failure")
}
func (failingResponseBody) Close() error { return nil }

// TestRegistryRequestFailuresKeepTheirPhaseAndSafeClass catches discarded request
// status/error classes without permitting network errors or response contents into output.
func TestRegistryRequestFailuresKeepTheirPhaseAndSafeClass(t *testing.T) {
	for _, phase := range []string{"token_exchange", "manifest"} {
		for _, tc := range []struct {
			name   string
			status int
			class  string
		}{
			{"transport", 0, "transport"},
			{"timeout", 0, "timeout"},
			{"read", 200, "response_read"},
			{"read-timeout", 200, "timeout"},
			{"oversized", 200, "response_size"},
		} {
			t.Run(phase+"/"+tc.name, func(t *testing.T) {
				client := restrictedClient()
				client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if phase == "manifest" && req.URL.Path == "/token" {
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"token":"scoped-secret"}`)), Header: make(http.Header)}, nil
					}
					switch tc.name {
					case "transport":
						return nil, errors.New("scoped-secret ::error::raw transport failure")
					case "timeout":
						return nil, fmt.Errorf("scoped-secret: %w", context.DeadlineExceeded)
					case "read":
						return &http.Response{StatusCode: 200, Body: failingResponseBody{}, Header: make(http.Header)}, nil
					case "read-timeout":
						return &http.Response{StatusCode: 200, Body: failingResponseBody{err: fmt.Errorf("scoped-secret: %w", context.DeadlineExceeded)}, Header: make(http.Header)}, nil
					default:
						return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", (4<<20)+1))), Header: make(http.Header)}, nil
					}
				})
				var out bytes.Buffer
				p := proof{registryURL: "https://registry.invalid", client: client, output: &out}
				read := p.manifest(context.Background(), credential{"synthetic-user", "scoped-secret"}, "synthetic-package", "latest")
				if read.status != 0 || read.digest != "" {
					t.Fatal("request failure became an accepted manifest or denial")
				}
				if got := p.result(2, "registry_read_unavailable", read.diagnostic); got != 2 {
					t.Fatalf("exit=%d", got)
				}
				want := fmt.Sprintf("scoped_package_proof=UNKNOWN reason=registry_read_unavailable registry_phase=%s http_status=%d failure_class=%s\n", phase, tc.status, tc.class)
				if out.String() != want {
					t.Fatalf("safe classification=%q, want %q", out.String(), want)
				}
			})
		}
	}
}
