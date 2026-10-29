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
# Every line that is kept goes through here. The caller's validate only parses
# this one file, so a path that survives (because this parser lost track of a
# stanza) would later collide with the managed /etc/logrotate.d/syslog and
# break rotation for every log while the apply still looks successful: fail
# instead, so the task stops and the run rolls back.
function emit(line,   t) {
    split(line, t, /[ \t]+/)
    if (t[1] == "") t[1] = t[2]
    if (t[1] == drop) leftover++
    print line
}
function flush_stanza(   i) {
    if (remaining > 0) {
        for (i = 1; i <= nhdr; i++) if (hdr[i] != "") emit(hdr[i])
        for (i = 1; i <= nbody; i++) emit(body[i])
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
        # logrotate takes the first word of the line as the directive, so
        # "endscript # why" closes a script as much as a bare "endscript" does;
        # missing it would treat every later stanza as script body and leave the
        # path in place. Same for a comment after the opening keyword.
        if (in_script) { if ($0 ~ /^[ \t]*endscript([ \t]+#.*|[ \t]*)$/) in_script = 0; next }
        if ($0 ~ /^[ \t]*(prerotate|postrotate|firstaction|lastaction)([ \t]+#.*|[ \t]*)$/) { in_script = 1; next }
        if ($0 ~ /^[ \t]*\}[ \t]*$/) flush_stanza()
        next
    }
    if (nhdr == 0 && ($0 ~ /^[ \t]*$/ || $0 ~ /^[ \t]*#/ || $0 ~ /^[ \t]*(include|tabooext)[ \t]/)) {
        if (skip_blank && $0 ~ /^[ \t]*$/) { skip_blank = 0; next }
        skip_blank = 0
        emit($0); next
    }
    skip_blank = 0
    add_header($0)
    if ($0 ~ /\{[ \t]*$/ || $0 ~ /^[ \t]*\{/) in_stanza = 1
}
END {
    for (i = 1; i <= nhdr; i++) if (hdr[i] != "") emit(hdr[i])
    for (i = 1; i <= nbody; i++) emit(body[i])
    if (leftover > 0) {
        print "logrotate-drop-path.awk: " drop " is still declared after the rewrite; refusing to write a policy that would duplicate it" > "/dev/stderr"
        exit 3
    }
}
