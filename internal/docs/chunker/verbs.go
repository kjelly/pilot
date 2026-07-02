// Verb mapping: which English verb describes a parameter? Used to
// build natural-language search hints that the LLM-style query
// "how to enable service at boot" can hit the `enabled` parameter.
//
// Why we have this: BM25 is keyword-based. If the LLM asks
// "how to restart nginx if it fails", we want that to land on
// `service.state=restarted`. The bare param name `state` is too
// short to anchor the match. So we emit search text like
// "How to restart a service using the state parameter" — that
// matches the LLM's question and bleve scores it highly.
//
// Heuristic-only; not exhaustive. The fallback "configure <name>"
// covers anything unknown. Add mappings as new LLM usage patterns
// surface.
package chunker

// VerbFor returns a short natural-language verb phrase for the given
// parameter name. Lower-case, suitable for embedding in a sentence
// like "How to <verb>".
func VerbFor(paramName string) string {
	if v, ok := verbTable[paramName]; ok {
		return v
	}
	return "configure " + paramName
}

// SynonymsFor returns alternative phrasings the LLM might use. These
// are merged into the query at search time (conjunction), so an LLM
// asking for "restart" finds chunks mentioning "state=restarted".
func SynonymsFor(paramName string) []string {
	if s, ok := synonymTable[paramName]; ok {
		return s
	}
	return nil
}

var verbTable = map[string]string{
	// service
	"enabled":       "control whether a service starts at boot",
	"state":         "control the desired state (started/stopped/restarted/reloaded)",
	"name":          "specify which service to manage",
	"use":           "choose the service manager backend",
	"daemon_reload": "reload systemd manager configuration after changes",

	// package
	"pkg":          "specify the package name",
	"package":      "specify the package name",
	"update_cache": "refresh the package manager cache before installing",

	// copy / file / template
	"src":     "specify the source path on the controller",
	"dest":    "specify the destination path on the target host",
	"path":    "specify the target filesystem path",
	"mode":    "set file permissions (octal like 0644)",
	"owner":   "set the file owner user",
	"group":   "set the file owner group",
	"content": "set the literal file content",
	"force":   "force overwrite if the destination exists and differs",
	"backup":  "create a backup file before changing it",
	"follow":  "follow symbolic links",

	// lineinfile
	"regexp":       "match an existing line with a regular expression",
	"line":         "specify the line of text to insert",
	"insertafter":  "insert the line after a matched line",
	"insertbefore": "insert the line before a matched line",
	"create":       "create the file if it does not exist",

	// user / group
	"uid":      "specify the numeric user ID",
	"gid":      "specify the numeric group ID",
	"shell":    "set the login shell",
	"home":     "set the home directory",
	"password": "set the encrypted password hash",
	"groups":   "set supplementary group memberships",
	"append":   "add to existing list instead of replacing",
	"system":   "create a system account (low UID)",
	"remove":   "remove the user/group",
	"expires":  "set the account expiration epoch",

	// iptables / firewall / network
	"chain":       "specify the iptables chain",
	"source":      "specify the source IP or CIDR",
	"destination": "specify the destination IP or CIDR",
	"protocol":    "specify the IP protocol (tcp/udp/icmp)",
	"jump":        "specify the iptables target action",
	"comment":     "add a comment to the rule",

	// common
	"become":        "escalate privileges for this task",
	"become_user":   "run the task as a different user",
	"ignore_errors": "continue past failures",
	"register":      "capture the result into a variable",
	"when":          "conditionally run the task",
	"loop":          "iterate over a list of items",
	"with_items":    "iterate over a list of items (deprecated form)",
	"tags":          "tag the task for selective execution",
	"notify":        "trigger a handler when the task changes",
	"delegate_to":   "run the task on a different host",
	"run_once":      "run the task only once across all hosts",
}

var synonymTable = map[string][]string{
	"enabled":  {"start at boot", "enable at boot", "autostart", "boot enabled"},
	"state":    {"restart", "stop", "start", "reload"},
	"name":     {"service name", "package name", "user name"},
	"dest":     {"destination", "target path", "remote path"},
	"src":      {"source path", "local path", "controller path"},
	"path":     {"target path", "destination path"},
	"mode":     {"permissions", "chmod", "file mode"},
	"owner":    {"file owner", "user owner"},
	"group":    {"group owner", "file group"},
	"regexp":   {"regex", "regular expression", "match pattern"},
	"line":     {"text to insert", "line content"},
	"password": {"passwd", "encrypted password"},
	"uid":      {"user id", "userid"},
	"gid":      {"group id", "groupid"},
	"become":   {"sudo", "privilege escalation", "root"},
}
