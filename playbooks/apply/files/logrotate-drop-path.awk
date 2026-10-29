# Prints a logrotate policy file with one log path (awk -v drop=<path>) removed.
# Used by audit-log-forwarding-apply.yml Step 5c on the distro's own
# /etc/logrotate.d/rsyslog.
#
# A stanza is: path lines, then "{", then a body, then "}". The path may be the
# stanza's only one (Ubuntu 22.04+: "/var/log/syslog" alone before its "{"),
# in which case removing just that line would leave a stanza with no filename
# and logrotate would reject the whole file: the whole stanza goes then. When
# other paths share the stanza (Debian's older file, RHEL's), only the path goes.
# Anything outside a stanza (comments, blank lines, include, global options) is
# copied as is.
#
# The stanza boundaries are found the way logrotate 3.22 finds them (each rule
# below was checked against `logrotate -d`, not assumed):
#  - a script (prerotate, postrotate, firstaction, lastaction, preremove) runs
#    from the end of its keyword, so the rest of the keyword's line is script
#    text, until a line whose first word, after blanks (space and tab only), is
#    "endscript" with no ASCII letter right behind it. "endscript;", "endscript #
#    c", "endscript x" and "endscript_x" end it; "endscriptx" and "ENDSCRIPT" do
#    not, and "endscript" in the middle of a line does not either.
#  - logrotate then drops ONE character after "endscript" and reads the rest of
#    the line as a new statement: "endscript }" closes the stanza, "endscript}"
#    does not (the brace is the dropped character), "endscript postrotate" opens
#    another script.
#  - a script keyword is followed by a blank, "=" or the end of the line; with a
#    letter behind it, it is some other (unknown) option.
#  - outside a stanza a line starts a log path when it begins with / ~ " or ';
#    otherwise it is a global option, which is not a path. Between a stanza's
#    path lines and its "{" every word is a path, "daily" included, except on a
#    whole-line comment. The paths end at the first "{" outside quotes, with or
#    without a blank before it, and what follows it on the line ("{ # c",
#    "{ postrotate") is a statement of the body.
#  - a path may be quoted with " or '; the quotes are not part of the name.
# Every line that is kept goes through here. The caller's validate only parses
# this one file, so a path that survives (because this parser lost track of a
# stanza) would later collide with the managed /etc/logrotate.d/syslog and
# break rotation for every log while the apply still looks successful: fail
# instead, so the task stops and the run rolls back.
#
# Portable on purpose (gawk, mawk, busybox awk): no regex intervals, no
# gensub/RT, no character ranges (they follow the locale); characters are
# compared one at a time.

function is_ws(c) { return c != "" && index(WS, c) > 0 }
function is_alpha(c) { return c != "" && index(ALPHA, c) > 0 }
# Blanks that logrotate skips before a directive: space and tab only.
function ltrim(s,   i, n) {
    n = length(s); i = 1
    while (i <= n && (substr(s, i, 1) == " " || substr(s, i, 1) == "\t")) i++
    return substr(s, i)
}
function unquote(t,   f, l) {
    l = length(t)
    if (l >= 2) {
        f = substr(t, 1, 1)
        if ((f == "\"" || f == "'") && substr(t, l, 1) == f) return substr(t, 2, l - 2)
    }
    return t
}
# The path words of a header line, up to the first "{" that is not in quotes.
# Sets tok[1..ntok], has_brace and tail (the text after the "{").
function tokenize(line,   i, n, c, tk, q) {
    split("", tok); ntok = 0; has_brace = 0; tail = ""
    n = length(line); i = 1
    while (i <= n) {
        c = substr(line, i, 1)
        if (is_ws(c)) { i++; continue }
        if (c == "{") { has_brace = 1; tail = substr(line, i + 1); return }
        if (c == "\"" || c == "'") {
            q = c; tk = c; i++
            while (i <= n && substr(line, i, 1) != q) { tk = tk substr(line, i, 1); i++ }
            if (i <= n) { tk = tk q; i++ }
            tok[++ntok] = tk
            continue
        }
        tk = ""
        while (i <= n) {
            c = substr(line, i, 1)
            if (is_ws(c) || c == "{") break
            tk = tk c; i++
        }
        tok[++ntok] = tk
    }
}
# A line that is kept but is not a header line: only its first word can be the
# path (script text, a global option, an include).
function emit(line,   s, i, n, c, w) {
    s = ltrim(line); n = length(s); w = ""
    for (i = 1; i <= n; i++) { c = substr(s, i, 1); if (is_ws(c)) break; w = w c }
    if (w != "" && unquote(w) == drop) leftover++
    print line
}
# A kept header line: every path word counts, a comment line has none.
function emit_hdr(line,   i, s) {
    s = ltrim(line)
    if (s != "" && substr(s, 1, 1) != "#") {
        tokenize(line)
        for (i = 1; i <= ntok; i++) if (unquote(tok[i]) == drop) leftover++
    }
    print line
}
function flush_stanza(   i) {
    if (remaining == 0 && hit > 0) {
        skip_blank = 1
    } else {
        for (i = 1; i <= nhdr; i++) if (hdr[i] != "") emit_hdr(hdr[i])
        for (i = 1; i <= nbody; i++) emit(body[i])
    }
    nhdr = 0; nbody = 0; remaining = 0; hit = 0; in_stanza = 0; in_script = 0
}
# Adds a header line (path words, possibly the "{"), dropping the path from it.
# Returns 1 when the line holds the "{"; the text behind it is left in btail.
function add_header(line,   s, i, kept, out, changed) {
    btail = ""
    s = ltrim(line)
    if (s == "" || substr(s, 1, 1) == "#") { hdr[++nhdr] = line; return 0 }
    tokenize(line)
    btail = tail
    kept = ""; changed = 0
    for (i = 1; i <= ntok; i++) {
        if (unquote(tok[i]) == drop) { changed = 1; hit++; continue }
        kept = kept (kept == "" ? "" : " ") tok[i]
        remaining++
    }
    if (!changed) { hdr[++nhdr] = line; return has_brace }
    out = kept
    if (has_brace) out = out (out == "" ? "{" : " {") btail
    hdr[++nhdr] = out
    return has_brace
}
# One statement, outside a script: a stanza's "}" or a script keyword matter,
# any other directive (and a comment) takes the rest of the line.
function stmt(text,   s, c, i, kw, l) {
    s = ltrim(text)
    c = substr(s, 1, 1)
    if (c == "" || c == "#") return
    if (c == "}") { if (in_stanza) close_pending = 1; return }
    for (i = 1; i <= nkw; i++) {
        kw = KW[i]; l = length(kw)
        if (substr(s, 1, l) != kw) continue
        c = substr(s, l + 1, 1)
        if (c != "" && c != "=" && !is_ws(c)) continue
        in_script = 1
        s = substr(s, l + 1)
        if (c == "=") s = substr(s, 2)
        script_text(s)
        return
    }
}
# Script text up to the end of a line (or of the keyword's line): ends it when
# the first word is "endscript", then the rest is a new statement.
function script_text(text,   s, c) {
    s = ltrim(text)
    if (substr(s, 1, 9) != "endscript") return
    c = substr(s, 10, 1)
    if (is_alpha(c)) return
    in_script = 0
    if (c != "") stmt(substr(s, 11))
}
function header(line,   br, t) {
    skip_blank = 0
    br = add_header(line)
    t = btail
    if (br) { in_stanza = 1; stmt(t) }
}
BEGIN {
    if (drop == "") { print "logrotate-drop-path.awk: -v drop=<path> is required" > "/dev/stderr"; exit 2 }
    WS = " \t" sprintf("%c", 11) sprintf("%c", 12) sprintf("%c", 13)
    ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    nkw = split("prerotate postrotate firstaction lastaction preremove", KW, " ")
}
{
    if (in_script) {
        if (in_stanza) body[++nbody] = $0; else emit($0)
        script_text($0)
    } else if (in_stanza) {
        body[++nbody] = $0
        stmt($0)
    } else if (nhdr == 0) {
        s0 = ltrim($0); c0 = substr(s0, 1, 1)
        if (c0 == "/" || c0 == "~" || c0 == "\"" || c0 == "'") {
            header($0)
        } else {
            # blank, comment, include, or a global option (which may open a script)
            if (skip_blank && s0 == "") { skip_blank = 0; next }
            skip_blank = 0
            emit($0)
            stmt($0)
        }
    } else {
        header($0)
    }
    if (close_pending) { close_pending = 0; flush_stanza() }
}
END {
    for (i = 1; i <= nhdr; i++) if (hdr[i] != "") emit_hdr(hdr[i])
    for (i = 1; i <= nbody; i++) emit(body[i])
    if (leftover > 0) {
        print "logrotate-drop-path.awk: " drop " is still declared after the rewrite; refusing to write a policy that would duplicate it" > "/dev/stderr"
        exit 3
    }
}
