# Prints a logrotate policy file with one log path (awk -v drop=<path>) removed.
# Used by audit-log-forwarding-apply.yml Step 5b on the distro's own
# /etc/logrotate.d/rsyslog. The playbook writes what this prints (Step 5c), or
# removes the file when nothing but blank lines and comments is printed (Step 5d).
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
# The rewrite is checked, not trusted. Removing the managed word changes the text
# logrotate sees in more ways than the word itself (a kept word that starts with "#"
# turns into a comment when it ends up first on a line, a kept "daily" can become the
# first word and then no longer opens a header, a continuation backslash can end up
# last in the text, where logrotate 3.22 strips the blanks that protected it). So the
# header text of the result is split again the way logrotate splits it, for the 3.22
# reading and the older one, and must give exactly the original words minus the
# managed one. If plain removal fails that, the managed word is replaced by "" (an
# empty word is no log at all to logrotate 3.19, 3.21 and 3.22; a second run finds no
# managed word and leaves it alone); if that fails too the helper refuses.
# A kept word that is a glob matching the path (/var/log/sys*) would still declare
# it for logrotate, which globs every word: the helper refuses (exit 3), since the
# managed policy for the path would then be a duplicate. (Known limits: only this one
# file is read, so a glob in another file of /etc/logrotate.d is not seen; the
# match is by pattern, whether the file exists is not asked.) A byte in the policy
# that is not valid UTF-8 makes the playbook task fail when it reads this output;
# that is fail-closed too, nothing is written.
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
    # A kept word that is a glob matching the path would still declare it.
    for (w = 1; w <= nw; w++) {
        v = wval[w]
        if (v != "" && v != drop && has_glob(v) && fnm(v, 1, drop, 1)) globhit++
    }
}

# --- rewrite, and a check that logrotate reads the result the same way -------
# Removing the managed word changes the text logrotate sees, and not only by that
# word: a kept word that starts with "#" becomes a comment when it is moved to the
# start of a line, a kept "daily" can become the first word and no longer starts a
# header, and logrotate 3.22 strips the blanks at the end of the header text, which
# can leave a backslash dangling. So the rewrite is never trusted: the header text
# of the rewritten lines is split again the way logrotate does and must give
# exactly the words of the original minus the managed one, for the 3.22 and the
# older (no stripping) reading alike. If the plain removal fails that, the managed
# word is replaced by "" instead (an empty word is no log at all to logrotate 3.19,
# 3.21 and 3.22, and keeps every other word where it was); if that fails too the
# helper refuses.
function rewrite_hdr(b,   j, k) {
    for (j = 1; j <= nh; j++) ol[j] = hl[j]
    h1only = 0
    build_removed(b)
    if (hdr_ok()) return
    for (j = 1; j <= nh; j++) { hl[j] = ol[j]; hdel[j] = 0 }
    h1only = 0
    build_blanked()
    if (hdr_ok()) return
    for (j = 1; j <= nh; j++) { hl[j] = ol[j]; hdel[j] = 0 }
    h1only = 0
    unsafe++
}
# Plain removal of the managed words: the other words of a line are joined by one
# blank (their own bytes untouched), a line left empty goes.
function build_removed(b,   j, k, line, out, cnt, hasdrop, txt, sep) {
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
            if (j == 1 && !blank_only(out)) { out = rtrim_blank(out); h1only = 1 }
            else hdel[j] = 1
        }
        hl[j] = out
    }
}
# Replacement of each managed word by "", everything else byte for byte.
function build_blanked(   j, k, line, out, pos) {
    for (j = 1; j <= nh; j++) {
        if (hcom[j]) continue
        line = hl[j]; out = ""; pos = 1
        for (k = 1; k <= nr[j]; k++) {
            if (!wdrop[rw[j, k]]) continue
            out = out substr(line, pos, rs[j, k] - pos) "\"\""
            pos = re[j, k]
        }
        if (pos > 1) hl[j] = out substr(line, pos)
    }
}
# The text logrotate hands to popt (parseGlobString) for the header held in ol[]
# (useorig) or in hl[]/hdel[]: from the first path character to the first "{",
# comment lines reduced to their newline. BADTEXT when the lines no longer form a
# header (a first word that is not a path start, no brace).
function glob_of(useorig,   j, line, text, started, c, s, i, n, k, g) {
    g = ""; started = 0
    for (j = 1; j <= nh; j++) {
        if (!useorig && hdel[j]) continue
        line = useorig ? ol[j] : hl[j]
        if (!started) {
            if (j == 1 && (useorig || !h1only)) {
                text = substr(line, hstart)
                if (!is_path_start(substr(text, 1, 1))) return BADTEXT
            } else {
                n = length(line); i = 1
                while (i <= n && is_blank(substr(line, i, 1))) i++
                s = substr(line, i); c = substr(s, 1, 1)
                if (s == "" || c == "#") continue
                if (!is_path_start(c)) return BADTEXT
                text = s
            }
            started = 1
        } else {
            n = length(line); i = 1
            while (i <= n && is_ws(substr(line, i, 1))) i++
            if (substr(line, i, 1) == "#") { g = g "\n"; continue }
            text = line
        }
        k = index(text, "{")
        if (k > 0) return g substr(text, 1, k - 1)
        g = g text "\n"
    }
    return BADTEXT
}
# popt's words of a glob string, the non-empty ones, in pw[1..]; returns their
# number, or -1 when popt fails (a backslash with nothing behind it). strip: the
# blanks at the end are dropped first, as logrotate 3.22 does (3.19 and 3.21 keep
# them).
function popt_words(g, strip, pw,   n, i, c, q, e, v, cnt) {
    split("", pw); cnt = 0; q = ""; e = 0; v = ""
    n = length(g)
    if (strip) while (n > 1 && is_ws(substr(g, n, 1))) n--
    for (i = 1; i <= n; i++) {
        c = substr(g, i, 1)
        if (e) {
            if (e == 2 && c != q) v = v "\\"
            v = v c; e = 0
        } else if (q != "") {
            if (c == q) q = ""
            else if (c == "\\") e = 2
            else v = v c
        } else if (is_ws(c)) {
            if (v != "") pw[++cnt] = v
            v = ""
        } else if (c == "\"" || c == "'") q = c
        else if (c == "\\") e = 1
        else v = v c
    }
    if (e) return -1
    if (v != "") pw[++cnt] = v
    return cnt
}
function join_words(pw, cnt, skip,   i, r) {
    r = ""
    for (i = 1; i <= cnt; i++) if (pw[i] != skip) r = r pw[i] SEP
    return r
}
function hdr_ok(   m, go, gn, co, cn, want) {
    go = glob_of(1); gn = glob_of(0)
    if (go == BADTEXT) return 1   # cannot happen: the header was read from these lines
    if (gn == BADTEXT) return 0
    for (m = 0; m <= 1; m++) {
        co = popt_words(go, m, ow)
        if (co < 0) continue      # logrotate of that reading rejects the original anyway
        want = join_words(ow, co, drop)
        cn = popt_words(gn, m, nwd)
        if (cn < 0 || join_words(nwd, cn, "") != want) return 0
    }
    return 1
}

# --- shell-style matching, for a kept word that is a glob ------------------------
# logrotate runs glob() on every word, so a kept "/var/log/sys*" still declares
# /var/log/syslog once the file exists, and the managed stanza would be a duplicate.
# Wildcards never match "/". Characters outside ASCII in a bracket expression and
# unknown [:classes:] count as matching, so that an unclear case refuses rather than
# passes.
function has_glob(w) { return index(w, "*") > 0 || index(w, "?") > 0 || index(w, "[") > 0 }
function ord(c) { return index(ASCII, c) + 31 }
function in_class(name, c) {
    if (name == "alpha") return is_alpha(c)
    if (name == "digit") return c != "" && index("0123456789", c) > 0
    if (name == "alnum") return is_alpha(c) || (c != "" && index("0123456789", c) > 0)
    if (name == "upper") return c != "" && index("ABCDEFGHIJKLMNOPQRSTUVWXYZ", c) > 0
    if (name == "lower") return c != "" && index("abcdefghijklmnopqrstuvwxyz", c) > 0
    if (name == "space") return is_ws(c)
    if (name == "blank") return is_blank(c)
    if (name == "xdigit") return c != "" && index("0123456789abcdefABCDEF", c) > 0
    if (name == "punct") return c != "" && index("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", c) > 0
    return 1
}
# Matches the bracket expression of p that starts at pi against c. Sets bnext to
# the index behind it and returns 1/0, or returns -1 when it has no closing "]"
# (then the "[" is an ordinary character).
function bracket(p, pi, c,   i, n, neg, ok, lo, hi, first, a, name, e) {
    n = length(p); i = pi + 1; neg = 0; ok = 0; first = 1
    if (substr(p, i, 1) == "!" || substr(p, i, 1) == "^") { neg = 1; i++ }
    while (i <= n) {
        a = substr(p, i, 1)
        if (a == "]" && !first) {
            bnext = i + 1
            if (c == "/") return 0
            return neg ? !ok : ok
        }
        first = 0
        if (a == "[" && substr(p, i + 1, 1) == ":") {
            e = index(substr(p, i + 2), ":]")
            if (e > 0) {
                name = substr(p, i + 2, e - 1)
                if (in_class(name, c)) ok = 1
                i = i + 2 + e + 1
                continue
            }
        }
        if (a == "\\" && i < n) { i++; a = substr(p, i, 1) }
        lo = a
        if (substr(p, i + 1, 1) == "-" && i + 2 <= n && substr(p, i + 2, 1) != "]") {
            hi = substr(p, i + 2, 1)
            if (hi == "\\" && i + 3 <= n) { hi = substr(p, i + 3, 1); i++ }
            if (ord(lo) == 31 || ord(hi) == 31 || ord(c) == 31) ok = 1
            else if (ord(c) >= ord(lo) && ord(c) <= ord(hi)) ok = 1
            i += 3
            continue
        }
        if (lo == c) ok = 1
        i++
    }
    return -1
}
function fnm(p, pi, s, si,   pc, sc, r, k, ns, np) {
    np = length(p); ns = length(s)
    while (1) {
        if (pi > np) return si > ns
        pc = substr(p, pi, 1)
        if (pc == "*") {
            while (substr(p, pi + 1, 1) == "*") pi++
            for (k = si; k <= ns + 1; k++) {
                if (fnm(p, pi + 1, s, k)) return 1
                if (k > ns || substr(s, k, 1) == "/") break
            }
            return 0
        }
        if (si > ns) return 0
        sc = substr(s, si, 1)
        if (pc == "?") { if (sc == "/") return 0; pi++; si++; continue }
        if (pc == "[") {
            r = bracket(p, pi, sc)
            if (r >= 0) { if (!r) return 0; pi = bnext; si++; continue }
        }
        if (pc == "\\" && pi < np) { pi++; pc = substr(p, pi, 1) }
        if (pc != sc) return 0
        pi++; si++
    }
}
function begin_header(line, pos,   b) {
    nh = 0; nw = 0; nbody = 0
    split("", hl); split("", hdel); split("", hcom); split("", nr)
    split("", rs); split("", re); split("", rw); split("", rcn)
    split("", wval); split("", wdrop); split("", ol)
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
    BADTEXT = sprintf("%c", 1) "BAD" sprintf("%c", 1); SEP = sprintf("%c", 28)
    ASCII = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
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
    if (globhit > 0) {
        print "logrotate-drop-path.awk: a glob in the policy also matches " drop "; the managed policy for it would be a duplicate; refusing to rewrite the policy" > "/dev/stderr"
        exit 3
    }
    if (unsafe > 0) {
        print "logrotate-drop-path.awk: cannot remove " drop " from a stanza header without changing what logrotate reads there; refusing to rewrite the policy" > "/dev/stderr"
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
