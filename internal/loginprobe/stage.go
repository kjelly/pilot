package loginprobe

// Stage is where a probe attempt ended. Exactly one stage describes every
// attempt; it is the `stage` label of pilot_login_probe_last_stage and
// pilot_login_probe_failures_total, so the set is fixed and small.
type Stage string

// The stage values, in the order a login progresses.
const (
	// StageTransport: no SSH transport could be established (resolve,
	// connect, proxy, banner) — the host or its sshd is unreachable.
	StageTransport Stage = "transport"
	// StageHostKey: the transport came up but the host key did not verify
	// against SSSD/FreeIPA (host not enrolled, re-installed, or spoofed).
	StageHostKey Stage = "hostkey"
	// StageAuth: sshd refused the canary's public key (account unknown, key
	// not published, authorized-keys lookup failed).
	StageAuth Stage = "auth"
	// StageAccount: the key was accepted but PAM account management denied
	// the session (HBAC, disabled account, pam_sss unable to decide).
	StageAccount Stage = "account"
	// StageSession: authentication succeeded but the session or the probe
	// command failed (pam_session, shell, command exit status).
	StageSession Stage = "session"
	// StageTimeout: the attempt did not finish within total_timeout.
	StageTimeout Stage = "timeout"
	// StageOK: full login and command success.
	StageOK Stage = "ok"
)

// AllStages lists every stage so metric series can be pre-seeded at 0.
var AllStages = []Stage{StageOK, StageTransport, StageHostKey, StageAuth, StageAccount, StageSession, StageTimeout}

// FailureStages is AllStages without StageOK.
var FailureStages = []Stage{StageTransport, StageHostKey, StageAuth, StageAccount, StageSession, StageTimeout}
