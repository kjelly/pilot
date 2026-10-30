# Prints a logrotate policy file with one log path (awk -v drop=<path>) removed.
# Used by audit-log-forwarding-apply.yml Step 5c on the distro's own
# /etc/logrotate.d/rsyslog.
#
# A stanza is: path words, then "{", then a body, then "}". The path may be the
# stanza's only one (Ubuntu 22.04+: "/var/log/syslog" alone before its "{"),
# in which case removing just that line would leave a stanza with no filename
# and logrotate would reject the whole file: the whole stanza goes then. When
# other paths share the stanza (Debian's older file, RHEL's), only the path goes.
# Everything else is copied byte for byte: comments, blank lines, global
# options, stanza bodies, scripts, the other paths of a header (their quoting
# and escapes stay as written).
#
# Only the path words of a stanza header are ever read or rewritten. A script
# body, a directive's value, a comment may contain the path text (a tab-indented
# "/var/log/syslog" inside a postrotate script is valid) and none of that is a
# declaration.
#
# Everything below mirrors logrotate 3.19 to 3.22 (config.c readConfigFile,
# parseGlobString and popt's poptParseArgvString); each rule was checked against
# `logrotate -d`, not assumed:
#  - outside a stanza a line (after blanks: space and tab only) starts a
#    header when it begins with / ~ " or '; this holds in the middle of a line
#    too ("compress /var/log/x {"). Inside a stanza such a line is an error.
#  - the header text runs to the first "{" that is not on a whole-line comment
#    (a comment line is one whose first non-space character is "#"), wherever
#    that "{" is: after a blank or glued to a path. A "#" anywhere else is data
#    ("/var/log/a # c" declares the logs "#" and "c"). What follows the "{" on
#    its line is a statement of the body.
#  - that text is split into words like popt does: blanks separate words unless
#    quoted; " and ' open a quoted part that may start in the middle of a word
#    and ends at the same quote character, quotes are not part of the name;
#    outside quotes a backslash makes the next character literal (including a
#    newline, so "a\<newline>b" is one word with a newline in it); inside quotes
#    a backslash only protects the quote character itself ("\"" is a quote, "\\"
#    stays two backslashes). A quoted part may span lines. A word whose
#    decoded name is empty ("") is no log at all.
#  - in a body a statement is a keyword (letters only, then a blank, "=" or the
#    end of the line), a "}" or a comment. A flag keyword (compress, missingok,
#    daily, ...) ends right after itself and one more character is dropped:
#    "missingok }" closes the stanza. Any other known keyword takes the rest
#    of the line as its value, and so does an unknown one ("ignoring line").
#  - a script keyword (prerotate, postrotate, firstaction, lastaction,
#    preremove) opens a script that runs from the end of the keyword (one
#    character dropped) until a line whose first word, after blanks, is
#    "endscript" with no ASCII letter right behind it ("endscript;", "endscript
#    # c", "endscript x" and "endscript_x" end it; "endscriptx" and "ENDSCRIPT"
#    do not; "endscript" in the middle of a line does not either). logrotate
#    then drops ONE character after "endscript" and reads the rest of the line
#    as a new statement: "endscript }" closes the stanza, "endscript}" does not,
#    "endscript postrotate" opens another script. Script lines are kept
#    verbatim and never read as declarations.
#  - a quote still open at the "{" is closed there (popt accepts that); a
#    backslash right before the "{" is an error. logrotate 3.22 drops the
#    blanks at the end of the header text, older versions keep them, so an
#    escaped blank or an open quote there names another file per version: if
#    that decides whether the last word is the path, the helper fails.
# Lines this parser cannot place (a path-looking statement inside a stanza,
# which logrotate itself rejects, a header with no "{" or with a backslash
# before it, a script with no endscript) are copied as they are, but if the
# path is declared in one of them the helper fails: the caller's validate only parses this one file, so a path
# that survives would later collide with the managed /etc/logrotate.d/syslog and
# break rotation for every log while the apply still looks successful. A failed
# task stops the run and rolls back.
#
# Portable on purpose (gawk, mawk, busybox awk): no regex intervals, no
# gensub/RT, no character ranges (they follow the locale); characters are
# compared one at a time.

function is_ws(c) { return c != "" && index(WS, c) > 0 }
function is_blank(c) { return c == " " || c == "\t" }
function is_alpha(c) { return c != "" && index(ALPHA, c) > 0 }
function is_path_start(c) { return c == "/" || c == "~" || c == "\"" || c == "'" }
function blank_only(s,   i, n) {
    n = length(s)
    for (i = 1; i <= n; i++) if (!is_blank(substr(s, i, 1))) return 0
    return 1
}
function rtrim_blank(s,   n) {
    n = length(s)
    while (n > 0 && is_blank(substr(s, n, 1))) n--
    return substr(s, 1, n)
}
function word_at(line, pos,   n, j) {
    n = length(line); j = pos
    while (j <= n && is_alpha(substr(line, j, 1))) j++
    return substr(line, pos, j - pos)
}

# --- popt word splitting, one character at a time -------------------------
# State: pq (open quote character), pesc (1: the next character is literal, 2:
# the same inside quotes), popen (a word has begun), pval (its decoded name),
# wid (its number). While a header is read (track), each word's raw pieces are
# recorded per line as runs: rs/re (columns, end exclusive), rw (word number),
# rcn (the run continues a word from the previous line).
function start_word(i) {
    popen = 1; nw++; wid = nw; pval = ""; rstart = i; rcont = 0
}
function close_run(e,   k) {
    if (track) {
        k = ++nr[nh]
        rs[nh, k] = rstart; re[nh, k] = e; rw[nh, k] = wid; rcn[nh, k] = rcont
    }
    rstart = 0; rcont = 0
}
function finish_word() {
    if (track) wval[wid] = pval
    else if (pval == drop) leftover++
    popen = 0; pval = ""
}
function pstep(c, i) {
    if (pesc) {
        if (pesc == 2 && c != pq) pval = pval "\\"
        pval = pval c; pesc = 0
        return
    }
    if (pq != "") {
        if (c == pq) { pq = ""; return }
        if (c == "\\") { pesc = 2; return }
        pval = pval c
        return
    }
    if (is_ws(c)) {
        if (popen) { if (rstart) close_run(i); finish_word() }
        return
    }
    if (!popen) start_word(i)
    if (c == "\"" || c == "'") { pq = c; return }
    if (c == "\\") { pesc = 1; return }
    pval = pval c
}
function reset_words() {
    pq = ""; pesc = 0; popen = 0; pval = ""; rstart = 0; rcont = 0
}

# A path-looking statement where logrotate takes none (inside a stanza): the
# policy is already one it rejects, but the path in it must not survive.
function lost_track(text,   i, n, c) {
    track = 0; reset_words()
    n = length(text)
    for (i = 1; i <= n; i++) {
        c = substr(text, i, 1)
        if (c == "{") break
        pstep(c, i)
    }
    if (popen) finish_word()
    reset_words(); track = 1
}

# --- stanza headers --------------------------------------------------------
# Reads one line of header text from column "from". Returns the column of the
# "{" that ends the header, or 0.
function hdr_scan(line, from,   n, i, c, b) {
    nh++; hl[nh] = line; nr[nh] = 0; hcom[nh] = 0
    n = length(line); b = 0
    if (nh > 1) {
        i = 1
        while (i <= n && is_ws(substr(line, i, 1))) i++
        if (substr(line, i, 1) == "#") {
            # logrotate drops the comment's text; its newline is still read
            hcom[nh] = 1
            pstep("\n", 1)
            return 0
        }
    }
    if (popen) { rstart = 1; rcont = 1 }
    for (i = from; i <= n; i++) {
        c = substr(line, i, 1)
        if (c == "{") { b = i; break }
        pstep(c, i)
    }
    if (b) {
        lastw = 0
        if (popen) { lastw = wid; if (rstart) close_run(b); finish_word() }
        # popt takes a quote that is still open at the end of the text as closed
        # there; only a backslash with nothing behind it is an error.
        hbad = (pesc != 0)
        return b
    }
    if (popen && rstart) close_run(n + 1)
    pstep("\n", n + 1)
    return 0
}
# The header is complete: find the words to drop and rewrite the lines that
# hold one.
function finish_header(b,   w, v, vt, n) {
    hit = 0; remaining = 0
    if (!hbad && lastw > 0) {
        # logrotate 3.22 strips the blanks at the very end of the header text
        # (before the "{"), older versions keep them: an escaped blank or an
        # open quote there gives the last word another name depending on the
        # version. When that decides whether it is the path, no rewrite is
        # right for every version.
        v = wval[lastw]; n = length(v)
        while (n > 0 && is_ws(substr(v, n, 1))) n--
        vt = substr(v, 1, n)
        if (v != vt && ((v == drop) != (vt == drop))) { ambiguous++; wval[lastw] = "" }
    }
    for (w = 1; w <= nw; w++) {
        v = wval[w]
        if (v == "") continue
        if (v == drop) { wdrop[w] = 1; hit++ } else remaining++
    }
    if (hbad) {
        # a backslash right before the "{": logrotate rejects the file
        leftover += hit; hit = 0; remaining = 1
        return
    }
    if (hit > 0 && remaining > 0) rewrite_hdr(b)
}
function rewrite_hdr(b,   j, k, line, out, cnt, hasdrop, txt, sep) {
    for (j = 1; j <= nh; j++) {
        if (hcom[j]) continue
        hasdrop = 0
        for (k = 1; k <= nr[j]; k++) if (wdrop[rw[j, k]]) hasdrop = 1
        if (!hasdrop) continue
        line = hl[j]
        out = ""
        if (j == 1) out = substr(line, 1, hstart - 1)
        cnt = 0
        for (k = 1; k <= nr[j]; k++) {
            if (wdrop[rw[j, k]]) continue
            txt = substr(line, rs[j, k], re[j, k] - rs[j, k])
            sep = (cnt > 0 && !rcn[j, k]) ? " " : ""
            out = out sep txt
            cnt++
        }
        if (j == nh) {
            sep = (cnt > 0) ? " {" : "{"
            out = out sep substr(line, b + 1)
        } else if (cnt == 0) {
            if (j == 1 && !blank_only(out)) out = rtrim_blank(out)
            else hdel[j] = 1
        }
        hl[j] = out
    }
}
function begin_header(line, pos,   b) {
    nh = 0; nw = 0; nbody = 0
    split("", hl); split("", hdel); split("", hcom); split("", nr)
    split("", rs); split("", re); split("", rw); split("", rcn)
    split("", wval); split("", wdrop)
    reset_words(); hbad = 0; hit = 0; remaining = 0; track = 1
    hstart = pos; hpre = substr(line, 1, pos - 1)
    cap = 1; mode = M_HDR
    b = hdr_scan(line, pos)
    if (b) { finish_header(b); mode = M_STANZA; in_stanza = 1; return b + 1 }
    return 0
}
function flush_stanza(   i) {
    if (remaining == 0 && hit > 0) {
        if (!blank_only(hpre)) print rtrim_blank(hpre)
        skip_blank = 1
    } else {
        for (i = 1; i <= nh; i++) if (!hdel[i]) print hl[i]
        for (i = 1; i <= nbody; i++) print body[i]
    }
    nh = 0; nbody = 0; remaining = 0; hit = 0; in_stanza = 0; mode = M_TOP
}

# --- statements ------------------------------------------------------------
# Reads the statements of one line from column pos, in the current mode: M_TOP
# (outside a stanza), M_STANZA (a body) or M_SCRIPT (script text).
function scan(line, pos,   n, c, w, r) {
    n = length(line)
    while (1) {
        while (pos <= n && is_blank(substr(line, pos, 1))) pos++
        if (mode == M_SCRIPT) {
            if (word_at(line, pos) != "endscript") return
            mode = in_stanza ? M_STANZA : M_TOP
            pos += 10   # the word and the one character logrotate drops
            continue
        }
        if (pos > n) return
        c = substr(line, pos, 1)
        if (c == "#") return
        if (c == "}") { if (mode == M_STANZA) close_pending = 1; return }
        if (is_path_start(c)) {
            if (mode == M_STANZA) { lost_track(substr(line, pos)); return }
            r = begin_header(line, pos)
            if (r == 0) return
            pos = r
            continue
        }
        w = word_at(line, pos)
        if (w == "") return
        pos += length(w)
        c = substr(line, pos, 1)
        if (c != "" && c != "=" && !is_ws(c)) return
        if (w in SCRIPTKW) { mode = M_SCRIPT; pos++; continue }
        if (w in FLAGKW) { pos++; continue }
        return
    }
}

BEGIN {
    if (drop == "") { print "logrotate-drop-path.awk: -v drop=<path> is required" > "/dev/stderr"; exit 2 }
    WS = " \t" sprintf("%c", 10) sprintf("%c", 11) sprintf("%c", 12) sprintf("%c", 13)
    ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    split("prerotate postrotate firstaction lastaction preremove", kws, " ")
    for (i in kws) SCRIPTKW[kws[i]] = 1
    split("compress nocompress delaycompress nodelaycompress shred noshred allowhardlink noallowhardlink sharedscripts nosharedscripts copytruncate nocopytruncate renamecopy norenamecopy copy nocopy ifempty notifempty dateext nodateext dateyesterday datehourago noolddir mailfirst maillast nocreateolddir nocreate hourly daily monthly yearly errors nomail missingok nomissingok ignoreduplicates", kwf, " ")
    for (i in kwf) FLAGKW[kwf[i]] = 1
    M_TOP = 1; M_STANZA = 2; M_SCRIPT = 3; M_HDR = 4
    mode = M_TOP; track = 1
}
{
    cap = 0
    if (mode == M_HDR) {
        cap = 1
        r0 = hdr_scan($0, 1)
        if (r0) { finish_header(r0); mode = M_STANZA; in_stanza = 1; scan($0, r0 + 1) }
    } else {
        if (mode == M_TOP && skip_blank) {
            skip_blank = 0
            if (blank_only($0)) next
        }
        ins = in_stanza
        scan($0, 1)
        if (!cap) { if (ins) body[++nbody] = $0; else print $0 }
    }
    if (close_pending) { close_pending = 0; flush_stanza() }
}
END {
    if (mode == M_HDR) {
        # no "{" before the end of the file: logrotate rejects it
        if (popen) finish_word()
        for (w0 = 1; w0 <= nw; w0++) if (wval[w0] == drop) leftover++
        for (i0 = 1; i0 <= nh; i0++) print hl[i0]
    } else {
        unended = (mode == M_SCRIPT)
        if (in_stanza) flush_stanza()
    }
    if (leftover > 0) {
        print "logrotate-drop-path.awk: " drop " is still declared after the rewrite; refusing to write a policy that would duplicate it" > "/dev/stderr"
        exit 3
    }
    if (ambiguous > 0) {
        print "logrotate-drop-path.awk: " drop " is spelled so that the logrotate versions disagree on it (blank or open quote right before the brace); refusing to rewrite the policy" > "/dev/stderr"
        exit 3
    }
    if (unended) {
        print "logrotate-drop-path.awk: a script never ends (no endscript); refusing to rewrite a policy logrotate cannot parse" > "/dev/stderr"
        exit 3
    }
}
