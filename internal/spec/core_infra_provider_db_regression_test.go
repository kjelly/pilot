package spec

import (
	"strings"
	"testing"
)

// TestRegression_CoreInfraProviderDbSpec locks the structure of
// docs/verification/core-infra-provider-db.md (v2.0 — docker-based PG).
//
// Where the previous version of this spec was about host postgresql,
// v2.0 moves PG into a docker container (`pilot-postgres` on
// `pilot-infra` network, bind-mounted to /var/lib/pilot/postgres).
// All rows now query the container state via `docker inspect` /
// `docker exec` instead of host systemd / dpkg / psql.
//
// C1–C11 cover:
//
//	C1      container running
//	C2      image is postgres:16
//	C3      host 5432/tcp LISTEN (port mapping 127.0.0.1:5432:5432)
//	C4–C6   keycloak database + role exist, role owns the db
//	C7      keycloak role can TCP-login and SELECT 1
//	C8      host bind-mount is wired to /var/lib/postgresql/data
//	C9      container healthcheck status = healthy
//	C10     pg_isready inside the container
//	C11     DB size < 10 GiB (capacity tripwire)
//
// Cross-row invariants locked below:
//
//   - C1 + C2 must query docker (NOT systemctl / dpkg).
//   - C7 must reference $KEYCLOAK_DB_PASSWORD.
//   - C8 must reference the host bind-mount path /var/lib/pilot/postgres.
//   - C9 must query docker healthcheck status (.State.Health.Status).
//   - C11 must use pg_database_size with an explicit `::bigint` cast
//     (the literal 10737418240 exceeds int4; lesson learned in v1.0).
func TestRegression_CoreInfraProviderDbSpec(t *testing.T) {
	const specPath = "../../docs/verification/core-infra-provider-db.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	// 1. C1..C11 inclusive, no gaps, no duplicates.
	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11"}
	if len(s.Rows) != 11 {
		t.Fatalf("rows=%d want=11", len(s.Rows))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	// 2. No vague expected values.
	for _, r := range s.Rows {
		if strings.Contains(strings.ToLower(strings.TrimSpace(r.Expected)), "ok") {
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// 3. C1 + C2 must query docker (either docker ps or docker inspect).
	//    We use `docker ps` because it doesn't need Go-template syntax
	//    (which collides with ansible's Jinja2 templating).
	for _, r := range s.Rows {
		if r.ID == "C1" && !strings.Contains(r.Command, "docker ") {
			t.Errorf("C1 must use docker; got %q", r.Command)
		}
		if r.ID == "C2" && !strings.Contains(r.Command, "docker ") {
			t.Errorf("C2 must use docker; got %q", r.Command)
		}
	}

	// 4. C7 must reference $KEYCLOAK_DB_PASSWORD.
	for _, r := range s.Rows {
		if r.ID == "C7" && !strings.Contains(r.Command, "KEYCLOAK_DB_PASSWORD") {
			t.Errorf("C7 must use $KEYCLOAK_DB_PASSWORD; got %q", r.Command)
		}
	}

	// 5. C8 must reference the host bind-mount path — either in the
	//    command (the docker inspect + grep pattern) or in the expected
	//    value (the substring `~pilot` matches `/var/lib/pilot/postgres`
	//    in the inspect output).
	for _, r := range s.Rows {
		if r.ID == "C8" {
			hasCmd := strings.Contains(r.Command, "/var/lib/pilot/postgres")
			hasExp := strings.Contains(r.Expected, "pilot")
			if !hasCmd && !hasExp {
				t.Errorf("C8 must reference /var/lib/pilot/postgres (in command or expected); got command=%q expected=%q", r.Command, r.Expected)
			}
		}
	}

	// 6. C9 must use docker ps and check the "(healthy)" substring
	//    (or similar). Avoid docker inspect --format=... because the
	//    Go template syntax {{...}} collides with ansible's Jinja2.
	for _, r := range s.Rows {
		if r.ID == "C9" {
			if !strings.Contains(r.Command, "docker ") {
				t.Errorf("C9 must use docker; got %q", r.Command)
			}
			if !strings.Contains(r.Command, "healthy") && !strings.Contains(r.Expected, "healthy") {
				t.Errorf("C9 must reference healthy status (in cmd or expected); got %q", r.Command)
			}
		}
	}

	// 7. C11 must use pg_database_size with ::bigint cast.
	for _, r := range s.Rows {
		if r.ID == "C11" {
			if !strings.Contains(r.Command, "pg_database_size") {
				t.Errorf("C11 must use pg_database_size; got %q", r.Command)
			}
			if !strings.Contains(r.Command, "::bigint") {
				t.Errorf("C11 must use ::bigint cast; got %q", r.Command)
			}
		}
	}

	// 8. Lint must not produce errors.
	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}
}
