package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	seedTaskTimeout  = 30 * time.Minute
	seedPollInterval = 2 * time.Second
)

// seedServices reconciles the host-side Pulp RPM and Harbor control planes.
// It intentionally runs after both Compose stacks are healthy and before the
// service state is persisted as running.
func seedServices(ctx context.Context, profile Profile, root string, bindIP net.IP, client *http.Client) (ClientConfig, error) {
	normalizeProfile(&profile)
	if err := profile.Validate(); err != nil {
		return ClientConfig{}, err
	}
	if bindIP == nil || bindIP.IsUnspecified() {
		return ClientConfig{}, errors.New("service seed bind IP is required")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	fingerprint, err := profile.Fingerprint()
	if err != nil {
		return ClientConfig{}, err
	}
	host := bindIP.String()
	pulpBase := "http://" + net.JoinHostPort(host, "8080") + "/pulp/api/v3"
	harborBase := "http://" + net.JoinHostPort(host, strconv.Itoa(profile.Harbor.HTTPPort)) + "/api/v2.0"
	adminPassword, err := readHarborAdminPassword(root)
	if err != nil {
		return ClientConfig{}, err
	}
	pulpPassword, err := readPulpAdminPassword(root)
	if err != nil {
		return ClientConfig{}, err
	}

	rpmURLs := make(map[string]string, len(profile.RPM.Repos))
	for _, repo := range profile.RPM.Repos {
		remote, err := reconcilePulpRemote(ctx, client, pulpBase, profile.Name, repo, pulpPassword)
		if err != nil {
			return ClientConfig{}, err
		}
		repository, err := reconcilePulpRepository(ctx, client, pulpBase, profile.Name, repo, remote, pulpPassword)
		if err != nil {
			return ClientConfig{}, err
		}
		if err := syncPulpRepositoryIfEmpty(ctx, client, pulpBase, repository, remote, pulpPassword); err != nil {
			return ClientConfig{}, err
		}
		if _, err := reconcilePulpDistribution(ctx, client, pulpBase, profile.Name, repo, repository, pulpPassword); err != nil {
			return ClientConfig{}, err
		}
		rpmURLs[repo.Name] = fmt.Sprintf("http://%s:8080/pulp/content/%s/%s", serviceHostname, profile.Name, repo.Name)
	}

	projects := make(map[string]string, len(profile.OCI.Registries))
	for _, registry := range profile.OCI.Registries {
		registryID, err := reconcileHarborRegistry(ctx, client, harborBase, registry, adminPassword)
		if err != nil {
			return ClientConfig{}, err
		}
		if err := reconcileHarborProject(ctx, client, harborBase, registry, registryID, profile.Storage.MaxBytes, adminPassword); err != nil {
			return ClientConfig{}, err
		}
		projects[registry.Name] = fmt.Sprintf("http://%s:%d/%s", serviceHostname, profile.Harbor.HTTPPort, registry.ProxyProject)
	}
	baseURL := ""
	for _, repo := range profile.RPM.Repos {
		baseURL = rpmURLs[repo.Name]
		break
	}
	return ClientConfig{
		Profile:           profile.Name,
		Fingerprint:       fingerprint,
		HostIP:            host,
		Hostname:          serviceHostname,
		AptProxyURL:       fmt.Sprintf("http://%s:%d", serviceHostname, profile.Apt.Port),
		RPMBaseURL:        baseURL,
		RPMRepositories:   rpmURLs,
		RegistryMirrorURL: fmt.Sprintf("http://%s:%d", serviceHostname, profile.Harbor.HTTPPort),
		RegistryProjects:  projects,
		CAPEM:             "",
	}, nil
}

func readHarborAdminPassword(root string) (string, error) {
	b, err := os.ReadFile(path.Join(root, "harbor", "secrets", "admin-password"))
	if err != nil {
		return "", fmt.Errorf("read Harbor admin password: %w", err)
	}
	password := strings.TrimSpace(string(b))
	if password == "" {
		return "", errors.New("read Harbor admin password: admin password is empty")
	}
	return password, nil
}

func readPulpAdminPassword(root string) (string, error) {
	b, err := os.ReadFile(path.Join(root, "pulp", "secrets", "admin-password"))
	if err != nil {
		return "", fmt.Errorf("read Pulp admin password: %w", err)
	}
	password := strings.TrimSpace(string(b))
	if password == "" {
		return "", errors.New("read Pulp admin password: admin password is empty")
	}
	return password, nil
}

type pulpRemote struct {
	Href   string `json:"pulp_href"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Policy string `json:"policy"`
}

type pulpRepository struct {
	Href              string `json:"pulp_href"`
	Name              string `json:"name"`
	Remote            string `json:"remote"`
	LatestVersionHref string `json:"latest_version_href"`
}

type pulpDistribution struct {
	Href       string `json:"pulp_href"`
	Name       string `json:"name"`
	BasePath   string `json:"base_path"`
	Repository string `json:"repository"`
}

type pulpList[T any] struct {
	Results []T `json:"results"`
}

// harborList accepts both Harbor's current array response and older API
// responses wrapped in a results object.
type harborList[T any] struct {
	Results []T
}

func (l *harborList[T]) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		return json.Unmarshal(data, &l.Results)
	}
	var wrapped struct {
		Results []T `json:"results"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return err
	}
	l.Results = wrapped.Results
	return nil
}

func reconcilePulpRemote(ctx context.Context, client *http.Client, base, profileName string, repo RPMRepository, password string) (pulpRemote, error) {
	name := seedName(profileName, repo.Name)
	var list pulpList[pulpRemote]
	if err := apiJSON(ctx, client, http.MethodGet, base+"/remotes/rpm/rpm/", nil, password, &list); err != nil {
		return pulpRemote{}, fmt.Errorf("seed Pulp remote %s: %w", name, err)
	}
	for _, existing := range list.Results {
		if existing.Name != name {
			continue
		}
		if existing.URL != repo.Upstream || existing.Policy != "on_demand" {
			return pulpRemote{}, fmt.Errorf("seed Pulp remote %s conflicts with existing configuration", name)
		}
		return existing, nil
	}
	var created pulpRemote
	err := apiJSON(ctx, client, http.MethodPost, base+"/remotes/rpm/rpm/", map[string]any{
		"name": name, "url": repo.Upstream, "policy": "on_demand",
	}, password, &created)
	if err != nil {
		return pulpRemote{}, fmt.Errorf("create Pulp remote %s: %w", name, err)
	}
	return created, nil
}

func reconcilePulpRepository(ctx context.Context, client *http.Client, base, profileName string, repo RPMRepository, remote pulpRemote, password string) (pulpRepository, error) {
	name := seedName(profileName, repo.Name)
	var list pulpList[pulpRepository]
	if err := apiJSON(ctx, client, http.MethodGet, base+"/repositories/rpm/rpm/", nil, password, &list); err != nil {
		return pulpRepository{}, fmt.Errorf("seed Pulp repository %s: %w", name, err)
	}
	for _, existing := range list.Results {
		if existing.Name != name {
			continue
		}
		if existing.Remote != "" && existing.Remote != remote.Href {
			return pulpRepository{}, fmt.Errorf("seed Pulp repository %s conflicts with existing remote", name)
		}
		return existing, nil
	}
	var created pulpRepository
	err := apiJSON(ctx, client, http.MethodPost, base+"/repositories/rpm/rpm/", map[string]any{
		"name": name, "remote": remote.Href, "retain_repo_versions": 1, "autopublish": true,
	}, password, &created)
	if err != nil {
		return pulpRepository{}, fmt.Errorf("create Pulp repository %s: %w", name, err)
	}
	return created, nil
}

func syncPulpRepositoryIfEmpty(ctx context.Context, client *http.Client, base string, repository pulpRepository, remote pulpRemote, password string) error {
	if !pulpRepositoryEmpty(repository) {
		return nil
	}
	var response struct {
		Task string `json:"task"`
	}
	if err := apiJSON(ctx, client, http.MethodPost, absoluteHref(base, repository.Href)+"sync/", map[string]any{
		"remote": remote.Href, "sync_policy": "mirror_content_only", "optimize": true,
	}, password, &response); err != nil {
		return fmt.Errorf("sync Pulp repository %s: %w", repository.Name, err)
	}
	if response.Task == "" {
		return fmt.Errorf("sync Pulp repository %s: response has no task", repository.Name)
	}
	_, err := waitPulpTask(ctx, client, absoluteHref(base, response.Task), password)
	return err
}

func pulpRepositoryEmpty(repository pulpRepository) bool {
	href := strings.TrimRight(repository.LatestVersionHref, "/")
	return href == "" || strings.HasSuffix(href, "/versions/0")
}

func waitPulpTask(ctx context.Context, client *http.Client, taskURL, password string) ([]string, error) {
	deadline := time.NewTimer(seedTaskTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(seedPollInterval)
	defer ticker.Stop()
	for {
		var task struct {
			State            string   `json:"state"`
			Name             string   `json:"name"`
			CreatedResources []string `json:"created_resources"`
		}
		if err := apiJSON(ctx, client, http.MethodGet, taskURL, nil, password, &task); err != nil {
			return nil, fmt.Errorf("poll Pulp task: %w", err)
		}
		switch task.State {
		case "completed":
			return task.CreatedResources, nil
		case "failed", "canceled":
			return nil, fmt.Errorf("Pulp task ended in state %s", task.State)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("Pulp task timed out")
		case <-ticker.C:
		}
	}
}

func reconcilePulpDistribution(ctx context.Context, client *http.Client, base, profileName string, repo RPMRepository, repository pulpRepository, password string) (pulpDistribution, error) {
	name := seedName(profileName, repo.Name)
	basePath := profileName + "/" + repo.Name
	var list pulpList[pulpDistribution]
	if err := apiJSON(ctx, client, http.MethodGet, base+"/distributions/rpm/rpm/", nil, password, &list); err != nil {
		return pulpDistribution{}, fmt.Errorf("seed Pulp distribution %s: %w", name, err)
	}
	for _, existing := range list.Results {
		if existing.Name != name {
			continue
		}
		if existing.BasePath != basePath || (existing.Repository != "" && existing.Repository != repository.Href) {
			return pulpDistribution{}, fmt.Errorf("seed Pulp distribution %s conflicts with existing configuration", name)
		}
		return existing, nil
	}
	var response struct {
		pulpDistribution
		Task             string   `json:"task"`
		CreatedResources []string `json:"created_resources"`
	}
	_, err := apiJSONResponse(ctx, client, http.MethodPost, base+"/distributions/rpm/rpm/", map[string]any{
		"name": name, "base_path": basePath, "repository": repository.Href, "generate_repo_config": true,
	}, password, &response)
	if err != nil {
		return pulpDistribution{}, fmt.Errorf("create Pulp distribution %s: %w", name, err)
	}
	if response.Href == "" && response.Task != "" {
		resources, waitErr := waitPulpTask(ctx, client, absoluteHref(base, response.Task), password)
		if waitErr != nil {
			return pulpDistribution{}, fmt.Errorf("create Pulp distribution %s: %w", name, waitErr)
		}
		response.CreatedResources = resources
		if len(resources) > 0 {
			response.Href = resources[0]
		}
	}
	if response.Href == "" {
		return pulpDistribution{}, fmt.Errorf("create Pulp distribution %s: response has no pulp_href", name)
	}
	return response.pulpDistribution, nil
}

type harborRegistry struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
	URL  string `json:"url"`
}

type harborProject struct {
	Name       string            `json:"project_name"`
	RegistryID int64             `json:"registry_id"`
	Metadata   map[string]string `json:"metadata"`
}

func (p *harborProject) UnmarshalJSON(data []byte) error {
	var value struct {
		Name        string            `json:"name"`
		ProjectName string            `json:"project_name"`
		RegistryID  int64             `json:"registry_id"`
		Metadata    map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	p.Name = value.Name
	if p.Name == "" {
		p.Name = value.ProjectName
	}
	p.RegistryID = value.RegistryID
	p.Metadata = value.Metadata
	return nil
}

func reconcileHarborRegistry(ctx context.Context, client *http.Client, base string, registry OCIRegistry, password string) (int64, error) {
	var list harborList[harborRegistry]
	if err := apiJSON(ctx, client, http.MethodGet, base+"/registries", nil, password, &list); err != nil {
		return 0, fmt.Errorf("seed Harbor registry %s: %w", registry.Name, err)
	}
	for _, existing := range list.Results {
		if existing.Name != registry.Name {
			continue
		}
		if existing.Type != registry.Type || strings.TrimRight(existing.URL, "/") != strings.TrimRight(registry.Upstream, "/") {
			return 0, fmt.Errorf("seed Harbor registry %s conflicts with existing configuration", registry.Name)
		}
		return existing.ID, nil
	}
	var created harborRegistry
	headers, err := apiJSONResponse(ctx, client, http.MethodPost, base+"/registries", map[string]any{
		"name": registry.Name, "type": registry.Type, "url": registry.Upstream, "insecure": false,
	}, password, &created)
	if err != nil {
		return 0, fmt.Errorf("create Harbor registry %s: %w", registry.Name, err)
	}
	if created.ID == 0 {
		created.ID = harborIDFromLocation(headers.Get("Location"))
	}
	if created.ID == 0 {
		return 0, fmt.Errorf("create Harbor registry %s: response has no id", registry.Name)
	}
	return created.ID, nil
}

func harborIDFromLocation(location string) int64 {
	location = strings.TrimRight(location, "/")
	if location == "" {
		return 0
	}
	last := location[strings.LastIndex(location, "/")+1:]
	id, err := strconv.ParseInt(last, 10, 64)
	if err != nil {
		return 0
	}
	return id
}

func reconcileHarborProject(ctx context.Context, client *http.Client, base string, registry OCIRegistry, registryID, storageLimit int64, password string) error {
	var list harborList[harborProject]
	if err := apiJSON(ctx, client, http.MethodGet, base+"/projects", nil, password, &list); err != nil {
		return fmt.Errorf("seed Harbor project %s: %w", registry.ProxyProject, err)
	}
	for _, existing := range list.Results {
		if existing.Name != registry.ProxyProject {
			continue
		}
		if existing.RegistryID != registryID {
			return fmt.Errorf("seed Harbor project %s conflicts with existing registry", registry.ProxyProject)
		}
		return nil
	}
	if err := apiJSON(ctx, client, http.MethodPost, base+"/projects", map[string]any{
		"project_name":  registry.ProxyProject,
		"registry_id":   registryID,
		"storage_limit": storageLimit,
		"metadata":      map[string]string{"public": "true"},
	}, password, nil); err != nil {
		return fmt.Errorf("create Harbor project %s: %w", registry.ProxyProject, err)
	}
	return nil
}

func apiJSON(ctx context.Context, client *http.Client, method, rawURL string, payload any, password string, output any) error {
	_, err := apiJSONResponse(ctx, client, method, rawURL, payload, password, output)
	return err
}

func apiJSONResponse(ctx context.Context, client *http.Client, method, rawURL string, payload any, password string, output any) (http.Header, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = strings.NewReader(string(b))
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if password != "" {
		req.SetBasicAuth("admin", password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if readErr != nil {
		return nil, readErr
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	if output == nil || len(b) == 0 {
		return resp.Header, nil
	}
	if err := json.Unmarshal(b, output); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return resp.Header, nil
}

func absoluteHref(base, href string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return strings.TrimRight(href, "/") + "/"
	}
	u, err := url.Parse(base)
	if err != nil {
		return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(href, "/")
	}
	if strings.HasPrefix(href, "/") {
		u.Path = href
	} else {
		u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(href, "/")
	}
	return strings.TrimRight(u.String(), "/") + "/"
}

func seedName(profile, name string) string {
	return profile + "-" + name
}
