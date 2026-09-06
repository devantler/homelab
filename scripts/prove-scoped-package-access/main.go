package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type credential struct{ username, password string }
type proof struct {
	apiURL, registryURL string
	client              *http.Client
	output              io.Writer
	baseline, scoped    credential
	pull                func(context.Context, credential, string) error
}

// restrictedClient bounds each request and prevents credentials following redirects.
func restrictedClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// URLs and repositories are deliberately fixed in main: this credential-bearing
// experiment is not a general registry client or an arbitrary URL fetcher.
func (p proof) request(ctx context.Context, endpoint, authorization string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, errors.New("invalid request")
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.github+json")
	response, err := p.client.Do(req)
	if err != nil {
		return 0, nil, errors.New("request unavailable")
	}
	// A read-only response has no pending write to commit on close.
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return 0, nil, errors.New("response unavailable or oversized")
	}
	return response.StatusCode, data, nil
}

// metadata accepts only a complete successful API response that decodes into target.
func (p proof) metadata(ctx context.Context, endpoint, token string, target any) bool {
	status, data, err := p.request(ctx, p.apiURL+endpoint, "Bearer "+token)
	return err == nil && status == http.StatusOK && json.Unmarshal(data, target) == nil
}

// denied classifies the authorization statuses returned by manifest after validation.
func denied(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// authorizationDenial distinguishes registry authorization failures from proxy errors.
func authorizationDenial(status int, data []byte) bool {
	if !denied(status) {
		return false
	}
	var response struct {
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if json.Unmarshal(data, &response) != nil || len(response.Errors) == 0 {
		return false
	}
	for _, failure := range response.Errors {
		if failure.Code != "UNAUTHORIZED" && failure.Code != "DENIED" {
			return false
		}
	}
	return true
}

// Resolve a manifest through GHCR's token exchange using a single identity. A
// missing tag, throttling, a redirect, malformed JSON or transport failure is
// never treated as an authorization denial.
func (p proof) manifest(ctx context.Context, auth credential, repository, ref string) (int, string) {
	authorization := ""
	if auth.password != "" {
		authorization = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth.username+":"+auth.password))
	}
	query := url.Values{"service": {"ghcr.io"}, "scope": {"repository:devantler-tech/" + repository + ":pull"}}
	status, data, err := p.request(ctx, p.registryURL+"/token?"+query.Encode(), authorization)
	if err != nil {
		return 0, ""
	}
	if authorizationDenial(status, data) {
		return status, ""
	}
	var token struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if status != 200 || json.Unmarshal(data, &token) != nil {
		return 0, ""
	}
	if token.Token == "" {
		token.Token = token.AccessToken
	}
	if token.Token == "" {
		return 0, ""
	}
	status, data, err = p.request(ctx, p.registryURL+"/v2/devantler-tech/"+repository+"/manifests/"+ref, "Bearer "+token.Token)
	if err != nil {
		return 0, ""
	}
	if denied(status) && !authorizationDenial(status, data) {
		return 0, ""
	}
	if status != 200 {
		return status, ""
	}
	var manifest struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.SchemaVersion != 2 {
		return 0, ""
	}
	switch manifest.MediaType {
	case "application/vnd.oci.image.index.v1+json", "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json", "application/vnd.docker.distribution.manifest.v2+json":
	default:
		return 0, ""
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
	if strings.HasPrefix(ref, "sha256:") && ref != digest {
		return 0, ""
	}
	return status, digest
}

// result emits only the fixed verdict and reason; missing output cannot count as success.
func (p proof) result(code int, reason string) int {
	verdict := []string{"PASS", "FAIL", "UNKNOWN"}[code]
	if _, err := fmt.Fprintf(p.output, "scoped_package_proof=%s reason=%s\n", verdict, reason); err != nil {
		return 2
	}
	return code
}

// run compares immutable private packages with independent baseline and anonymous controls.
func (p proof) run(ctx context.Context) int {
	if p.baseline.username == "" || p.baseline.password == "" || p.scoped.password == "" || p.baseline.password == p.scoped.password {
		return p.result(2, "independent_credentials_required")
	}
	var scope struct {
		TotalCount   int `json:"total_count"`
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if !p.metadata(ctx, "/installation/repositories?per_page=100", p.scoped.password, &scope) || scope.TotalCount != 1 || len(scope.Repositories) != 1 || scope.Repositories[0].FullName != "devantler-tech/wedding-app" {
		return p.result(2, "token_repository_scope_unverified")
	}
	repositories := []string{"wedding-app", "ascoachingogvaner"}
	digests := make([]string, 2)
	for i, repository := range repositories {
		var metadata struct {
			Name        string `json:"name"`
			PackageType string `json:"package_type"`
			Visibility  string `json:"visibility"`
			Owner       struct {
				Login string `json:"login"`
			} `json:"owner"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		}
		if !p.metadata(ctx, "/orgs/devantler-tech/packages/container/"+repository, p.baseline.password, &metadata) || metadata.Name != repository || metadata.PackageType != "container" || metadata.Visibility != "private" || metadata.Owner.Login != "devantler-tech" || metadata.Repository.FullName != "devantler-tech/"+repository {
			return p.result(2, "private_package_association_unverified")
		}
		status, digest := p.manifest(ctx, p.baseline, repository, "latest")
		if status != 200 {
			return p.result(2, "baseline_manifest_unavailable")
		}
		digests[i] = digest
		status, _ = p.manifest(ctx, credential{}, repository, digest)
		if !denied(status) {
			return p.result(2, "anonymous_denial_unverified")
		}
		if p.pull(ctx, p.baseline, "ghcr.io/devantler-tech/"+repository+"@"+digest) != nil {
			return p.result(2, "baseline_full_pull_unavailable")
		}
	}
	// A successful own pull includes the image's blobs, not just its manifest.
	ownStatus, _ := p.manifest(ctx, p.scoped, repositories[0], digests[0])
	if ownStatus != 200 && !denied(ownStatus) {
		return p.result(2, "scoped_own_read_unavailable")
	}
	ownImage := "ghcr.io/devantler-tech/" + repositories[0] + "@" + digests[0]
	if ownStatus == 200 && p.pull(ctx, p.scoped, ownImage) != nil {
		return p.result(2, "scoped_own_full_pull_unavailable")
	}
	crossStatus, _ := p.manifest(ctx, p.scoped, repositories[1], digests[1])
	if crossStatus != 200 && !denied(crossStatus) {
		return p.result(2, "scoped_cross_read_unavailable")
	}
	// Repeat both baselines and the scoped positive after the negative. An expired
	// token or registry incident during the comparison cannot pass the boundary.
	for i, repository := range repositories {
		status, _ := p.manifest(ctx, p.baseline, repository, digests[i])
		if status != 200 {
			return p.result(2, "baseline_postcheck_unavailable")
		}
	}
	postOwnStatus, _ := p.manifest(ctx, p.scoped, repositories[0], digests[0])
	if postOwnStatus != ownStatus {
		return p.result(2, "scoped_own_postcheck_changed")
	}
	// Rebind the installation identity too; otherwise two denied reads from an
	// expired token would falsely refute an otherwise usable authentication path.
	scope.TotalCount = 0
	scope.Repositories = nil
	if !p.metadata(ctx, "/installation/repositories?per_page=100", p.scoped.password, &scope) || scope.TotalCount != 1 || len(scope.Repositories) != 1 || scope.Repositories[0].FullName != "devantler-tech/wedding-app" {
		return p.result(2, "token_repository_scope_postcheck_unverified")
	}
	if denied(ownStatus) {
		return p.result(1, "scoped_own_package_denied")
	}
	if p.pull(ctx, p.scoped, ownImage) != nil {
		return p.result(2, "scoped_own_full_pull_postcheck_unavailable")
	}
	if crossStatus == 200 {
		return p.result(1, "out_of_scope_package_readable")
	}
	return p.result(0, "own_full_pull_and_cross_package_denial_verified")
}

// readBaseline requires an explicit inline GHCR identity without ambient credential helpers.
func readBaseline(directory string) (credential, error) {
	if directory == "" {
		return credential{}, errors.New("explicit Docker config required")
	}
	data, err := os.ReadFile(filepath.Join(directory, "config.json"))
	if err != nil {
		return credential{}, errors.New("docker config unavailable")
	}
	var config struct {
		CredsStore  string                                               `json:"credsStore"`
		CredHelpers map[string]string                                    `json:"credHelpers"`
		Auths       map[string]struct{ Auth, Username, Password string } `json:"auths"`
	}
	if json.Unmarshal(data, &config) != nil || config.CredsStore != "" || len(config.CredHelpers) != 0 {
		return credential{}, errors.New("inline credential required")
	}
	for _, key := range []string{"ghcr.io", "https://ghcr.io/v1/"} {
		entry, exists := config.Auths[key]
		if !exists {
			continue
		}
		user, password := entry.Username, entry.Password
		if entry.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
			if err != nil {
				return credential{}, errors.New("malformed credential")
			}
			user, password, _ = strings.Cut(string(decoded), ":")
		}
		if user == "" || password == "" {
			return credential{}, errors.New("incomplete credential")
		}
		return credential{user, password}, nil
	}
	return credential{}, errors.New("ghcr credential missing")
}

// pullImage downloads all image blobs using a fresh private credential and destination directory.
func pullImage(ctx context.Context, auth credential, image string) (result error) {
	directory, err := os.MkdirTemp("", "scoped-package-pull-")
	if err != nil {
		return errors.New("private config unavailable")
	}
	defer func() {
		if os.RemoveAll(directory) != nil {
			result = errors.New("private config cleanup unavailable")
		}
	}()
	data, err := json.Marshal(map[string]map[string]map[string]string{"auths": {"ghcr.io": {
		"auth": base64.StdEncoding.EncodeToString([]byte(auth.username + ":" + auth.password)),
	}}})
	if err != nil || os.WriteFile(filepath.Join(directory, "config.json"), data, 0600) != nil {
		return errors.New("private config unavailable")
	}
	// A fresh destination and no cache are essential: a Docker daemon could reuse
	// the baseline's layers and let the candidate pass without downloading them.
	command := exec.CommandContext(ctx, "crane", "pull", "--platform", "linux/amd64", image, filepath.Join(directory, "image.tar"))
	// No ambient credential helper, cloud credential, token, or raw tool error is
	// forwarded. Pulling downloads data only; no container is created or executed.
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "DOCKER_CONFIG=" + directory}
	if command.Run() != nil {
		return errors.New("full pull unavailable")
	}
	return nil
}

// main fixes the credential-bearing endpoints and imposes an overall experiment deadline.
func main() {
	baseline, err := readBaseline(os.Getenv("DOCKER_CONFIG"))
	if err != nil {
		fmt.Println("scoped_package_proof=UNKNOWN reason=baseline_credential_unavailable")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	p := proof{apiURL: "https://api.github.com", registryURL: "https://ghcr.io", client: restrictedClient(), output: os.Stdout,
		baseline: baseline, scoped: credential{"x-access-token", os.Getenv("SCOPED_APP_TOKEN")}, pull: pullImage}
	os.Exit(p.run(ctx))
}
