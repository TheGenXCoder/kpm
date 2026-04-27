package kpm_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TheGenXCoder/kpm/internal/kpm"
)

// ── Test server helpers ───────────────────────────────────────────────────────

// bindingStore is a minimal in-memory store for test servers.
type bindingStore struct {
	bindings map[string]kpm.CredentialBinding
}

func newBindingStore() *bindingStore {
	return &bindingStore{bindings: make(map[string]kpm.CredentialBinding)}
}

// newBindingTestServer returns an httptest.Server that mimics /bindings/* endpoints.
func newBindingTestServer(t *testing.T) (*httptest.Server, *bindingStore) {
	t.Helper()
	store := newBindingStore()
	mux := http.NewServeMux()

	// POST /bindings
	mux.HandleFunc("POST /bindings", func(w http.ResponseWriter, r *http.Request) {
		var b kpm.CredentialBinding
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		store.bindings[b.Name] = b
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(b)
	})

	// GET /bindings
	mux.HandleFunc("GET /bindings", func(w http.ResponseWriter, r *http.Request) {
		tag := r.URL.Query().Get("tag")
		summaries := make([]kpm.BindingSummary, 0)
		for _, b := range store.bindings {
			if tag != "" && !containsTag(b.Metadata.Tags, tag) {
				continue
			}
			summaries = append(summaries, kpm.BindingSummary{
				Name:             b.Name,
				ProviderKind:     b.ProviderKind,
				DestinationCount: len(b.Destinations),
				LastRotatedAt:    b.Metadata.LastRotatedAt,
				Tags:             b.Metadata.Tags,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"bindings": summaries})
	})

	// GET /bindings/{name}
	mux.HandleFunc("GET /bindings/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		b, ok := store.bindings[name]
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{"error": "not found", "code": "key_not_found"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(b)
	})

	// DELETE /bindings/{name}
	mux.HandleFunc("DELETE /bindings/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, ok := store.bindings[name]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(store.bindings, name)
		w.WriteHeader(http.StatusNoContent)
	})

	// POST /bindings/{name}/rotate
	mux.HandleFunc("POST /bindings/{name}/rotate", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		b, ok := store.bindings[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		b.Metadata.LastGeneration++
		b.Metadata.LastRotatedAt = "2026-04-25T12:00:00Z"
		store.bindings[name] = b

		results := make([]kpm.DestinationResult, len(b.Destinations))
		for i, d := range b.Destinations {
			results[i] = kpm.DestinationResult{
				Kind:     d.Kind,
				TargetID: d.TargetID,
				Success:  true,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(kpm.RotateResponse{
			Name:       name,
			Generation: b.Metadata.LastGeneration,
			RotatedAt:  b.Metadata.LastRotatedAt,
			Results:    results,
		})
	})

	// POST /auth/session — auth endpoint needed by kpm.Client.ensureAuth.
	mux.HandleFunc("POST /auth/session", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": "test-token"})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, store
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

// newTestClient creates a Client against the given test server.
// Uses NewClientInsecure (no mTLS for unit tests).
func newTestClient(t *testing.T, srv *httptest.Server) *kpm.Client {
	t.Helper()
	c, err := kpm.NewClientInsecure(srv.URL)
	if err != nil {
		t.Fatalf("NewClientInsecure: %v", err)
	}
	return c
}

// validTestBinding returns a minimal CredentialBinding for test calls.
func validTestBinding(name string) kpm.CredentialBinding {
	return kpm.CredentialBinding{
		Name:         name,
		ProviderKind: "github-app-token",
		Scope:        kpm.BindingScope{Kind: "llm-session"},
		Destinations: []kpm.DestinationSpec{
			{Kind: "github-secret", TargetID: "owner/repo:MY_SECRET"},
		},
		RotationPolicy: kpm.RotationPolicy{ManualOnly: true},
	}
}

// ── Client method tests ───────────────────────────────────────────────────────

func TestClient_RegisterBinding(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	b := validTestBinding("test-binding")
	got, err := c.RegisterBinding(context.Background(), b)
	if err != nil {
		t.Fatalf("RegisterBinding: %v", err)
	}
	if got.Name != "test-binding" {
		t.Errorf("name: got %q", got.Name)
	}
	if got.ProviderKind != "github-app-token" {
		t.Errorf("provider_kind: got %q", got.ProviderKind)
	}
}

func TestClient_ListBindings_Empty(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	bindings, err := c.ListBindings(context.Background(), "")
	if err != nil {
		t.Fatalf("ListBindings: %v", err)
	}
	if len(bindings) != 0 {
		t.Errorf("expected 0 bindings, got %d", len(bindings))
	}
}

func TestClient_ListBindings_AfterRegister(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	for _, name := range []string{"alpha", "beta"} {
		if _, err := c.RegisterBinding(context.Background(), validTestBinding(name)); err != nil {
			t.Fatalf("RegisterBinding %q: %v", name, err)
		}
	}

	bindings, err := c.ListBindings(context.Background(), "")
	if err != nil {
		t.Fatalf("ListBindings: %v", err)
	}
	if len(bindings) != 2 {
		t.Errorf("expected 2 bindings, got %d", len(bindings))
	}
}

func TestClient_GetBinding(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	c.RegisterBinding(context.Background(), validTestBinding("inspect-me"))

	got, err := c.GetBinding(context.Background(), "inspect-me")
	if err != nil {
		t.Fatalf("GetBinding: %v", err)
	}
	if got.Name != "inspect-me" {
		t.Errorf("name: got %q", got.Name)
	}
}

func TestClient_GetBinding_NotFound(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	_, err := c.GetBinding(context.Background(), "does-not-exist")
	if err == nil {
		t.Fatal("expected error for not-found binding")
	}
}

func TestClient_RotateBinding(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	c.RegisterBinding(context.Background(), validTestBinding("rotate-me"))

	result, err := c.RotateBinding(context.Background(), "rotate-me")
	if err != nil {
		t.Fatalf("RotateBinding: %v", err)
	}
	if result.Name != "rotate-me" {
		t.Errorf("name: got %q", result.Name)
	}
	if result.Generation != 1 {
		t.Errorf("generation: got %d want 1", result.Generation)
	}
	if len(result.Results) != 1 {
		t.Fatalf("results: got %d want 1", len(result.Results))
	}
	if !result.Results[0].Success {
		t.Errorf("destination result: expected success")
	}
}

func TestClient_RemoveBinding(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	c.RegisterBinding(context.Background(), validTestBinding("to-delete"))

	if err := c.RemoveBinding(context.Background(), "to-delete", false); err != nil {
		t.Fatalf("RemoveBinding: %v", err)
	}

	// Now get should fail.
	if _, err := c.GetBinding(context.Background(), "to-delete"); err == nil {
		t.Fatal("expected error after remove")
	}
}

// ── RunCred CLI tests ─────────────────────────────────────────────────────────

func TestRunCredRegister_OK(t *testing.T) {
	srv, store := newBindingTestServer(t)
	c := newTestClient(t, srv)

	var w, errW bytes.Buffer
	args := []string{
		"register", "my-binding",
		"--provider", "github-app-token",
		"--scope", "llm-session",
		"--destination", "github-secret:owner/repo:MY_SECRET",
	}
	code := kpm.RunCred(context.Background(), &w, &errW, c, args)
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errW.String())
	}
	if _, ok := store.bindings["my-binding"]; !ok {
		t.Error("binding not saved to store")
	}
	if !strings.Contains(w.String(), "my-binding") {
		t.Errorf("output doesn't mention binding name: %q", w.String())
	}
}

func TestRunCredRegister_MissingProvider(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	var w, errW bytes.Buffer
	args := []string{"register", "x", "--destination", "github-secret:owner/repo:S"}
	code := kpm.RunCred(context.Background(), &w, &errW, c, args)
	if code == 0 {
		t.Fatal("expected non-zero exit code for missing --provider")
	}
}

func TestRunCredRegister_MissingDestination(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	var w, errW bytes.Buffer
	args := []string{"register", "x", "--provider", "github-app-token"}
	code := kpm.RunCred(context.Background(), &w, &errW, c, args)
	if code == 0 {
		t.Fatal("expected non-zero exit code for missing --destination")
	}
}

func TestRunCredList_Empty(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	var w, errW bytes.Buffer
	code := kpm.RunCred(context.Background(), &w, &errW, c, []string{"list"})
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errW.String())
	}
	if !strings.Contains(w.String(), "No credential bindings") {
		t.Errorf("expected empty message, got: %q", w.String())
	}
}

func TestRunCredList_AfterRegister(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	// Register first.
	kpm.RunCred(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, c, []string{
		"register", "my-binding",
		"--provider", "github-app-token",
		"--destination", "github-secret:owner/repo:S",
	})

	var w, errW bytes.Buffer
	code := kpm.RunCred(context.Background(), &w, &errW, c, []string{"list"})
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errW.String())
	}
	if !strings.Contains(w.String(), "my-binding") {
		t.Errorf("expected binding in output, got: %q", w.String())
	}
}

func TestRunCredInspect_Pretty(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	kpm.RunCred(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, c, []string{
		"register", "to-inspect",
		"--provider", "github-app-token",
		"--destination", "github-secret:owner/repo:SECRET",
	})

	var w, errW bytes.Buffer
	code := kpm.RunCred(context.Background(), &w, &errW, c, []string{"inspect", "to-inspect"})
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errW.String())
	}
	out := w.String()
	if !strings.Contains(out, "to-inspect") {
		t.Errorf("expected name in output: %q", out)
	}
	if !strings.Contains(out, "github-app-token") {
		t.Errorf("expected provider_kind in output: %q", out)
	}
}

func TestRunCredInspect_JSON(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	kpm.RunCred(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, c, []string{
		"register", "json-inspect",
		"--provider", "github-app-token",
		"--destination", "github-secret:owner/repo:SECRET",
	})

	var w, errW bytes.Buffer
	code := kpm.RunCred(context.Background(), &w, &errW, c, []string{"inspect", "json-inspect", "--json"})
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errW.String())
	}
	var got kpm.CredentialBinding
	if err := json.Unmarshal(w.Bytes(), &got); err != nil {
		t.Fatalf("JSON output not parseable: %v\noutput: %q", err, w.String())
	}
	if got.Name != "json-inspect" {
		t.Errorf("name: got %q", got.Name)
	}
}

func TestRunCredRotate_OK(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	kpm.RunCred(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, c, []string{
		"register", "to-rotate",
		"--provider", "github-app-token",
		"--destination", "github-secret:owner/repo:SECRET",
	})

	var w, errW bytes.Buffer
	code := kpm.RunCred(context.Background(), &w, &errW, c, []string{"rotate", "to-rotate"})
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errW.String())
	}
	out := w.String()
	if !strings.Contains(out, "to-rotate") {
		t.Errorf("expected binding name in output: %q", out)
	}
}

func TestRunCredRotate_ParsesResults(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	kpm.RunCred(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, c, []string{
		"register", "with-dest",
		"--provider", "github-app-token",
		"--destination", "github-secret:owner/repo:MY_SECRET",
	})

	var w, errW bytes.Buffer
	code := kpm.RunCred(context.Background(), &w, &errW, c, []string{"rotate", "with-dest"})
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	out := w.String()
	if !strings.Contains(out, "OK") {
		t.Errorf("expected OK in rotate output: %q", out)
	}
}

func TestRunCredRemove_OK(t *testing.T) {
	srv, store := newBindingTestServer(t)
	c := newTestClient(t, srv)

	kpm.RunCred(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, c, []string{
		"register", "to-remove",
		"--provider", "github-app-token",
		"--destination", "github-secret:owner/repo:SECRET",
	})

	var w, errW bytes.Buffer
	code := kpm.RunCred(context.Background(), &w, &errW, c, []string{"remove", "to-remove"})
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errW.String())
	}
	if _, ok := store.bindings["to-remove"]; ok {
		t.Error("binding still exists after remove")
	}
}

func TestRunCredUnknownSubcommand(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	var w, errW bytes.Buffer
	code := kpm.RunCred(context.Background(), &w, &errW, c, []string{"unknown-sub"})
	if code == 0 {
		t.Fatal("expected non-zero exit code for unknown subcommand")
	}
}

// ── parseDestination unit tests ───────────────────────────────────────────────

func TestParseDestination_Simple(t *testing.T) {
	cases := []struct {
		input    string
		wantKind string
		wantID   string
	}{
		{"github-secret:owner/repo:MY_SECRET", "github-secret", "owner/repo:MY_SECRET"},
		{"k8s-secret:namespace/secret:key", "k8s-secret", "namespace/secret:key"},
		{"env-file:/etc/app/prod.env:API_KEY", "env-file", "/etc/app/prod.env:API_KEY"},
	}

	for _, tc := range cases {
		dests, err := kpm.ParseDestinations([]string{tc.input})
		if err != nil {
			t.Errorf("parseDestinations(%q): %v", tc.input, err)
			continue
		}
		if len(dests) != 1 {
			t.Errorf("expected 1 dest, got %d", len(dests))
			continue
		}
		if dests[0].Kind != tc.wantKind {
			t.Errorf("kind: got %q want %q", dests[0].Kind, tc.wantKind)
		}
		if dests[0].TargetID != tc.wantID {
			t.Errorf("target_id: got %q want %q", dests[0].TargetID, tc.wantID)
		}
	}
}

func TestParseDestination_WithParams(t *testing.T) {
	input := `github-secret:owner/repo:MY_SECRET:{"visibility":"all"}`
	dests, err := kpm.ParseDestinations([]string{input})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(dests) != 1 {
		t.Fatalf("expected 1 dest, got %d", len(dests))
	}
	if dests[0].Params == nil {
		t.Fatal("expected non-nil params")
	}
	if v, ok := dests[0].Params["visibility"]; !ok || v != "all" {
		t.Errorf("params: got %v", dests[0].Params)
	}
}

func TestParseDestination_Invalid(t *testing.T) {
	cases := []string{
		"no-colon",
		":no-kind",
	}
	for _, tc := range cases {
		_, err := kpm.ParseDestinations([]string{tc})
		if err == nil {
			t.Errorf("expected error for %q, got nil", tc)
		}
	}
}

// ── --github-app / --target sugar flag tests ─────────────────────────────────

// TestRunCredRegister_GithubApp_Sugar verifies that --github-app sets
// provider_kind=github-pat and provider_params={"app_name":"..."} in the
// request body, producing the same binding as the long-form equivalent.
func TestRunCredRegister_GithubApp_Sugar(t *testing.T) {
	srv, store := newBindingTestServer(t)
	c := newTestClient(t, srv)

	var w, errW bytes.Buffer
	args := []string{
		"register", "blog-audit",
		"--github-app", "agentkms-blog-audit-rotator",
		"--target", "github-secret:TheGenXCoder/blog:CODE_REPO_READ_PAT",
	}
	code := kpm.RunCred(context.Background(), &w, &errW, c, args)
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errW.String())
	}

	b, ok := store.bindings["blog-audit"]
	if !ok {
		t.Fatal("binding not saved")
	}
	if b.ProviderKind != "github-pat" {
		t.Errorf("provider_kind: got %q want %q", b.ProviderKind, "github-pat")
	}
	appName, _ := b.ProviderParams["app_name"].(string)
	if appName != "agentkms-blog-audit-rotator" {
		t.Errorf("provider_params.app_name: got %q want %q", appName, "agentkms-blog-audit-rotator")
	}
	if b.RotationPolicy.TTLHintSeconds != 3600 {
		t.Errorf("ttl_hint_seconds: got %d want 3600", b.RotationPolicy.TTLHintSeconds)
	}
}

// TestRunCredRegister_GithubApp_LongFormEquivalence verifies that the sugar
// form produces an identical binding to the explicit long-form flags.
func TestRunCredRegister_GithubApp_LongFormEquivalence(t *testing.T) {
	srv, store := newBindingTestServer(t)
	c := newTestClient(t, srv)

	// Register via sugar.
	var w, errW bytes.Buffer
	kpm.RunCred(context.Background(), &w, &errW, c, []string{
		"register", "sugar-binding",
		"--github-app", "my-rotator",
		"--target", "github-secret:owner/repo:MY_SECRET",
		"--ttl", "3600",
	})

	// Register via explicit long-form.
	kpm.RunCred(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, c, []string{
		"register", "explicit-binding",
		"--provider", "github-pat",
		"--provider-params", `{"app_name":"my-rotator"}`,
		"--destination", "github-secret:owner/repo:MY_SECRET",
		"--ttl", "3600",
	})

	sugar := store.bindings["sugar-binding"]
	explicit := store.bindings["explicit-binding"]

	if sugar.ProviderKind != explicit.ProviderKind {
		t.Errorf("provider_kind mismatch: sugar=%q explicit=%q", sugar.ProviderKind, explicit.ProviderKind)
	}
	sugarApp, _ := sugar.ProviderParams["app_name"].(string)
	explicitApp, _ := explicit.ProviderParams["app_name"].(string)
	if sugarApp != explicitApp {
		t.Errorf("app_name mismatch: sugar=%q explicit=%q", sugarApp, explicitApp)
	}
	if sugar.RotationPolicy.TTLHintSeconds != explicit.RotationPolicy.TTLHintSeconds {
		t.Errorf("ttl mismatch: sugar=%d explicit=%d",
			sugar.RotationPolicy.TTLHintSeconds, explicit.RotationPolicy.TTLHintSeconds)
	}
	if len(sugar.Destinations) != len(explicit.Destinations) {
		t.Fatalf("destination count mismatch: sugar=%d explicit=%d",
			len(sugar.Destinations), len(explicit.Destinations))
	}
	if sugar.Destinations[0].Kind != explicit.Destinations[0].Kind {
		t.Errorf("destination kind mismatch: sugar=%q explicit=%q",
			sugar.Destinations[0].Kind, explicit.Destinations[0].Kind)
	}
	if sugar.Destinations[0].TargetID != explicit.Destinations[0].TargetID {
		t.Errorf("destination target_id mismatch: sugar=%q explicit=%q",
			sugar.Destinations[0].TargetID, explicit.Destinations[0].TargetID)
	}
}

// TestRunCredRegister_GithubApp_ConflictsWithProvider verifies that
// --github-app + --provider produces an error.
func TestRunCredRegister_GithubApp_ConflictsWithProvider(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	var w, errW bytes.Buffer
	args := []string{
		"register", "x",
		"--github-app", "foo",
		"--provider", "some-other-provider",
		"--destination", "github-secret:owner/repo:S",
	}
	code := kpm.RunCred(context.Background(), &w, &errW, c, args)
	if code == 0 {
		t.Fatal("expected non-zero exit code when --github-app conflicts with --provider")
	}
	if !strings.Contains(errW.String(), "--github-app") || !strings.Contains(errW.String(), "--provider") {
		t.Errorf("error message should mention both flags; got: %q", errW.String())
	}
}

// TestRunCredRegister_GithubApp_ConflictsWithProviderParams verifies that
// --github-app + --provider-params produces an error.
func TestRunCredRegister_GithubApp_ConflictsWithProviderParams(t *testing.T) {
	srv, _ := newBindingTestServer(t)
	c := newTestClient(t, srv)

	var w, errW bytes.Buffer
	args := []string{
		"register", "x",
		"--github-app", "foo",
		"--provider-params", `{"app_name":"bar"}`,
		"--destination", "github-secret:owner/repo:S",
	}
	code := kpm.RunCred(context.Background(), &w, &errW, c, args)
	if code == 0 {
		t.Fatal("expected non-zero exit code when --github-app conflicts with --provider-params")
	}
	if !strings.Contains(errW.String(), "--github-app") || !strings.Contains(errW.String(), "--provider-params") {
		t.Errorf("error message should mention both flags; got: %q", errW.String())
	}
}

// TestRunCredRegister_Target_NoParams verifies that --target produces a
// destination with an empty Params map (no inline params).
func TestRunCredRegister_Target_NoParams(t *testing.T) {
	srv, store := newBindingTestServer(t)
	c := newTestClient(t, srv)

	var w, errW bytes.Buffer
	args := []string{
		"register", "target-test",
		"--provider", "github-pat",
		"--target", "github-secret:owner/repo:MY_SECRET",
	}
	code := kpm.RunCred(context.Background(), &w, &errW, c, args)
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errW.String())
	}

	b := store.bindings["target-test"]
	if len(b.Destinations) != 1 {
		t.Fatalf("expected 1 destination, got %d", len(b.Destinations))
	}
	if len(b.Destinations[0].Params) != 0 {
		t.Errorf("expected empty Params for --target destination, got %v", b.Destinations[0].Params)
	}
	if b.Destinations[0].Kind != "github-secret" {
		t.Errorf("kind: got %q want %q", b.Destinations[0].Kind, "github-secret")
	}
	if b.Destinations[0].TargetID != "owner/repo:MY_SECRET" {
		t.Errorf("target_id: got %q want %q", b.Destinations[0].TargetID, "owner/repo:MY_SECRET")
	}
}

// TestRunCredRegister_Target_Multiple verifies that multiple --target flags
// each produce a separate destination.
func TestRunCredRegister_Target_Multiple(t *testing.T) {
	srv, store := newBindingTestServer(t)
	c := newTestClient(t, srv)

	var w, errW bytes.Buffer
	args := []string{
		"register", "multi-target",
		"--provider", "github-pat",
		"--target", "github-secret:owner/repo-a:SECRET_A",
		"--target", "github-secret:owner/repo-b:SECRET_B",
	}
	code := kpm.RunCred(context.Background(), &w, &errW, c, args)
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errW.String())
	}

	b := store.bindings["multi-target"]
	if len(b.Destinations) != 2 {
		t.Fatalf("expected 2 destinations, got %d", len(b.Destinations))
	}
}

// TestRunCredRegister_Target_AndDestination verifies that --target and
// --destination together both contribute to the binding's destinations.
func TestRunCredRegister_Target_AndDestination(t *testing.T) {
	srv, store := newBindingTestServer(t)
	c := newTestClient(t, srv)

	var w, errW bytes.Buffer
	args := []string{
		"register", "mixed-dest",
		"--provider", "github-pat",
		"--destination", `github-secret:owner/repo-a:SECRET_A:{"visibility":"all"}`,
		"--target", "github-secret:owner/repo-b:SECRET_B",
	}
	code := kpm.RunCred(context.Background(), &w, &errW, c, args)
	if code != 0 {
		t.Fatalf("exit code %d: %s", code, errW.String())
	}

	b := store.bindings["mixed-dest"]
	if len(b.Destinations) != 2 {
		t.Fatalf("expected 2 destinations, got %d; out=%q err=%q", len(b.Destinations), w.String(), errW.String())
	}
}

// TestRunCredRegister_GithubApp_DefaultTTL verifies that --github-app without
// an explicit --ttl defaults to 3600 seconds.
func TestRunCredRegister_GithubApp_DefaultTTL(t *testing.T) {
	srv, store := newBindingTestServer(t)
	c := newTestClient(t, srv)

	kpm.RunCred(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, c, []string{
		"register", "ttl-default",
		"--github-app", "my-app",
		"--target", "github-secret:owner/repo:S",
	})

	b := store.bindings["ttl-default"]
	if b.RotationPolicy.TTLHintSeconds != 3600 {
		t.Errorf("ttl_hint_seconds: got %d want 3600", b.RotationPolicy.TTLHintSeconds)
	}
}

// TestRunCredRegister_GithubApp_ExplicitTTL verifies that an explicit --ttl
// overrides the github-app sugar default.
func TestRunCredRegister_GithubApp_ExplicitTTL(t *testing.T) {
	srv, store := newBindingTestServer(t)
	c := newTestClient(t, srv)

	kpm.RunCred(context.Background(), &bytes.Buffer{}, &bytes.Buffer{}, c, []string{
		"register", "ttl-explicit",
		"--github-app", "my-app",
		"--target", "github-secret:owner/repo:S",
		"--ttl", "7200",
	})

	b := store.bindings["ttl-explicit"]
	if b.RotationPolicy.TTLHintSeconds != 7200 {
		t.Errorf("ttl_hint_seconds: got %d want 7200", b.RotationPolicy.TTLHintSeconds)
	}
}
