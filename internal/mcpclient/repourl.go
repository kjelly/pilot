package mcpclient

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// RepoID is the host/owner/repo a Git URL points at.
type RepoID struct {
	Host, Owner, Repo string
}

var scpLikePattern = regexp.MustCompile(`^git@([A-Za-z0-9.-]+):([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(\.git)?$`)

// allowLocalGitRemote lets tests use a local bare repository. It is a
// package-level test seam, never a user setting (spec §5.3).
var allowLocalGitRemote = false

// ValidateRepoURL accepts git@host:owner/repo, ssh://git@host[:port]/owner/repo
// and https://host/owner/repo (each optionally ending in .git).
func ValidateRepoURL(raw string) error {
	if allowLocalGitRemote && strings.HasPrefix(raw, "/") {
		return nil
	}
	_, err := ParseRepoURL(raw)
	return err
}

// ParseRepoURL splits a supported Git URL into its repository identity.
func ParseRepoURL(raw string) (RepoID, error) {
	if raw == "" {
		return RepoID{}, errors.New("is required")
	}
	if strings.HasPrefix(raw, "-") {
		return RepoID{}, fmt.Errorf("%q must not start with '-'", raw)
	}
	if m := scpLikePattern.FindStringSubmatch(raw); m != nil {
		return RepoID{Host: strings.ToLower(m[1]), Owner: m[2], Repo: m[3]}, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return RepoID{}, fmt.Errorf("%q is not a supported Git URL", raw)
	}
	switch u.Scheme {
	case "https":
		if u.User != nil {
			return RepoID{}, fmt.Errorf("https URLs must not carry credentials; use a Git credential helper")
		}
	case "ssh":
		if u.User == nil || u.User.Username() != "git" {
			return RepoID{}, fmt.Errorf("ssh URLs must use the git user (ssh://git@host/owner/repo)")
		}
		if _, hasPassword := u.User.Password(); hasPassword {
			return RepoID{}, fmt.Errorf("ssh URLs must not carry a password")
		}
	default:
		return RepoID{}, fmt.Errorf("%q: only git@host:owner/repo, ssh://git@host/owner/repo and https://host/owner/repo are supported", raw)
	}
	if u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return RepoID{}, fmt.Errorf("%q is not a supported Git URL", raw)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return RepoID{}, fmt.Errorf("%q must name exactly <owner>/<repo>", raw)
	}
	return RepoID{Host: strings.ToLower(u.Hostname()), Owner: parts[0], Repo: strings.TrimSuffix(parts[1], ".git")}, nil
}

// SameRepo reports whether two Git URLs name the same repository,
// whichever of the supported forms each uses (spec §5.6 step 4).
func SameRepo(a, b string) bool {
	if allowLocalGitRemote && strings.HasPrefix(a, "/") {
		return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
	}
	ra, errA := ParseRepoURL(a)
	rb, errB := ParseRepoURL(b)
	if errA != nil || errB != nil {
		return false
	}
	return ra.Host == rb.Host && strings.EqualFold(ra.Owner, rb.Owner) && strings.EqualFold(ra.Repo, rb.Repo)
}
