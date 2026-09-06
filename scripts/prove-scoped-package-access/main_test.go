package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
		{"missing independent credential", "no-baseline", 2},
		{"same credential is not an independent control", "same-token", 2},
		{"invalid scoped token", "invalid-token", 2},
		{"baseline cannot pull", "baseline-pull", 2},
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
						fmt.Fprint(w, `{}`)
						return
					}
					if crossed && tc.fault == "partial-scope-postcheck" {
						fmt.Fprint(w, `{"total_count":1}`)
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
					if tc.fault == "wide-token" || tc.fault == "partial-token" {
						count = 2
					}
					fmt.Fprintf(w, `{"total_count":%d,"repositories":[{"full_name":"devantler-tech/wedding-app"}]}`, count)
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
					fmt.Fprintf(w, `{"name":%q,"package_type":"container","visibility":"private","owner":{"login":"devantler-tech"},"repository":{"full_name":%q}}`, name, "devantler-tech/"+linked)
				case r.URL.Path == "/token":
					_, secret, _ := r.BasicAuth()
					if tc.fault == "bad-token" {
						fmt.Fprint(w, `{broken`)
						return
					}
					if secret == "" {
						secret = "anonymous"
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"token": secret})
				case strings.Contains(r.URL.Path, "/manifests/"):
					credential := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
					own := strings.Contains(r.URL.Path, "/wedding-app/")
					if credential == "anonymous" && tc.fault != "public" {
						w.WriteHeader(401)
						fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED"}]}`)
						return
					}
					if credential == "scoped-secret" {
						if own && (tc.fault == "own-denied" || (crossed && tc.fault == "expired-after-cross")) {
							w.WriteHeader(403)
							fmt.Fprint(w, `{"errors":[{"code":"DENIED"}]}`)
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
								fmt.Fprint(w, "proxy unavailable")
								return
							default:
								w.WriteHeader(403)
								fmt.Fprint(w, `{"errors":[{"code":"DENIED"}]}`)
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
						fmt.Fprint(w, `{broken`)
						return
					}
					fmt.Fprint(w, manifest)
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
