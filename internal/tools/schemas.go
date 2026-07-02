package tools

import "encoding/json"

// Arg schemas for tools. Kept here so all tool definitions live in one place.

var readFileArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "path": {
      "type": "string",
      "description": "Absolute path of the file to read on the target host (localhost for now)"
    }
  },
  "required": ["path"]
}`)

var runCommandArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "command": {
      "type": "string",
      "description": "Shell command to execute. Must be on the approved whitelist."
    },
    "timeout_sec": {
      "type": "integer",
      "description": "Timeout in seconds (default 30)"
    }
  },
  "required": ["command"]
}`)

var runPlaybookArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "playbook": {
      "type": "string",
      "description": "Absolute path to the playbook YAML file"
    },
    "inventory": {
      "type": "string",
      "description": "Absolute path to the inventory file"
    },
    "limit": {
      "type": "string",
      "description": "Optional host pattern to limit execution (e.g. 'web01' or 'webservers')"
    },
    "check": {
      "type": "boolean",
      "description": "If true, run with --check --diff and do not make changes (default true for safety)"
    },
    "tags": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Only run plays and tasks tagged with these values (passed as --tags tag1,tag2)"
    },
    "skip_tags": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Skip plays and tasks tagged with these values (passed as --skip-tags tag1,tag2)"
    },
    "extra_vars": {
      "type": "object",
      "additionalProperties": true,
      "description": "Object form of --extra-vars; written to a temp JSON file and passed via -e @<file>. Supports nested values."
    },
    "extra_vars_raw": {
      "type": "string",
      "description": "Raw --extra-vars string (e.g. 'env=prod version=1.2'). Mutually exclusive with extra_vars."
    },
    "become": {
      "type": "boolean",
      "description": "Run with privilege escalation (--become). Default: not set, ansible uses its own default."
    },
    "forks": {
      "type": "integer",
      "minimum": 1,
      "description": "Number of parallel processes to use (--forks N)."
    },
    "user": {
      "type": "string",
      "description": "Connect as this user (--user)."
    },
    "connection": {
      "type": "string",
      "enum": ["local", "ssh", "paramiko", "docker"],
      "description": "Connection type to use (--connection). Restricted to safe values to avoid arbitrary plugins."
    },
    "vault_password_file": {
      "type": "string",
      "description": "Absolute path to a vault password file. Must live under one of the configured allowed_roots. The file contents are never read by pilot; ansible-playbook reads them directly."
    },
    "diff": {
      "type": "boolean",
      "description": "Show file changes (--diff). Usually combined with check=true."
    },
    "timeout": {
      "type": "integer",
      "minimum": 1,
      "description": "Override the per-run timeout in seconds. Default is 1800 (30m)."
    },
    "flush_cache": {
      "type": "boolean",
      "description": "Clear the fact cache for every host in the inventory before running (--flush-cache)."
    }
  },
  "required": ["playbook"]
}`)

var generateTaskArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "description": {
      "type": "string",
      "description": "What the Ansible task should accomplish"
    },
    "cis_control": {
      "type": "string",
      "description": "Optional CIS control number this task addresses (e.g. '5.2.1')"
    },
    "target_file": {
      "type": "string",
      "description": "Optional file the task will modify (helps the LLM pick the right module)"
    }
  },
  "required": ["description"]
}`)

var askUserArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "question": {
      "type": "string",
      "description": "The question to present to the user"
    },
    "options": {
      "type": "array",
      "items": {"type": "string"},
      "description": "Optional list of acceptable answer choices"
    }
  },
  "required": ["question"]
}`)

var runInSpecArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "profile": {
      "type": "string",
      "description": "InSpec profile name or path (default 'cis-ubuntu')"
    },
    "target": {
      "type": "string",
      "description": "ssh://user@host or local (default 'local://')"
    }
  }
}`)

var gatherFactsArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "inventory": {
      "type": "string",
      "description": "Absolute path to the inventory file"
    },
    "limit": {
      "type": "string",
      "description": "Optional host pattern to limit fact gathering (e.g. 'web01' or 'webservers')"
    },
    "filter": {
      "type": "string",
      "description": "Shell-style glob pattern to filter the gathered facts (e.g. 'ansible_distribution*', 'ansible_mounts*')"
    },
    "become": {
      "type": "boolean",
      "description": "Run with privilege escalation (--become)"
    }
  }
}`)

var vaultEncryptArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "plaintext": {
      "type": "string",
      "description": "The plaintext secret string to encrypt"
    },
    "name": {
      "type": "string",
      "description": "The name of the variable (e.g. 'db_password')"
    },
    "vault_password_file": {
      "type": "string",
      "description": "Absolute path to the vault password file. Must live under allowed_roots."
    }
  },
  "required": ["plaintext", "name"]
}`)
