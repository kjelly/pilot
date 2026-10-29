# Prints a logrotate policy file with one log path (awk -v drop=<path>) removed.
# Used by audit-log-forwarding-apply.yml Step 5c on the distro's own
# /etc/logrotate.d/rsyslog.
#
# A stanza is: path lines, then "{", then a body, then "}". The path may be the
# stanza's only one (Ubuntu 22.04+: "/var/log/syslog" alone before its "{"),
# in which case removing just that line would leave a stanza with no filename
# and logrotate would reject the whole file: the whole stanza goes then. When
# other paths share the stanza (Debian's older file, RHEL's), only the path goes.
# Anything outside a stanza (comments, blank lines, include) is copied as is.
function flush_stanza(   i) {
    if (remaining > 0) {
        for (i = 1; i <= nhdr; i++) if (hdr[i] != "") print hdr[i]
        for (i = 1; i <= nbody; i++) print body[i]
    } else {
        skip_blank = 1
    }
    nhdr = 0; nbody = 0; remaining = 0; in_stanza = 0; in_script = 0
}
function add_header(line,   n, t, i, kept, has_brace, out) {
    n = split(line, t, /[ \t]+/)
    kept = ""; has_brace = 0; changed = 0
    for (i = 1; i <= n; i++) {
        if (t[i] == "") continue
        if (t[i] == "{") { has_brace = 1; continue }
        if (t[i] == drop) { changed = 1; continue }
        kept = kept (kept == "" ? "" : " ") t[i]
        remaining++
    }
    if (!changed) { hdr[++nhdr] = line; return }
    out = kept
    if (has_brace) out = out (out == "" ? "{" : " {")
    hdr[++nhdr] = out
}
BEGIN { if (drop == "") { print "logrotate-drop-path.awk: -v drop=<path> is required" > "/dev/stderr"; exit 2 } }
{
    if (in_stanza) {
        body[++nbody] = $0
        if (in_script) { if ($0 ~ /^[ \t]*endscript[ \t]*$/) in_script = 0; next }
        if ($0 ~ /^[ \t]*(prerotate|postrotate|firstaction|lastaction)[ \t]*$/) { in_script = 1; next }
        if ($0 ~ /^[ \t]*\}[ \t]*$/) flush_stanza()
        next
    }
    if (nhdr == 0 && ($0 ~ /^[ \t]*$/ || $0 ~ /^[ \t]*#/ || $0 ~ /^[ \t]*(include|tabooext)[ \t]/)) {
        if (skip_blank && $0 ~ /^[ \t]*$/) { skip_blank = 0; next }
        skip_blank = 0
        print; next
    }
    skip_blank = 0
    add_header($0)
    if ($0 ~ /\{[ \t]*$/ || $0 ~ /^[ \t]*\{/) in_stanza = 1
}
END { for (i = 1; i <= nhdr; i++) if (hdr[i] != "") print hdr[i]; for (i = 1; i <= nbody; i++) print body[i] }
