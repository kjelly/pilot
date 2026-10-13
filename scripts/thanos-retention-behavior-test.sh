#!/usr/bin/env bash
# Runs the Thanos Compactor with the retention defaults from
# playbooks/apply/thanos-query-apply.yml against synthetic blocks and checks
# that no data younger than 90 days is lost (docs/verification/thanos-query.md
# §1.5).
#
# The Compactor only downsamples a raw block that spans at least 40h; how old
# the data is does not matter. Blocks that never reach 40h stay raw-only, so
# when raw retention is shorter than the downsampled retention they are
# deleted with no low-resolution copy left. The scenarios:
#
#   short-lived  a site that ran for 2h, 45 days ago            -> kept
#   stopped      a site that ran ~74h and stopped 45 days ago;
#                its last 26h never reach 40h                   -> kept
#   relabelled   a site that changed its site label 45 days ago;
#                the old label's last 10h                       -> kept
#   expired      a site that ran for 2h, 95 days ago            -> deleted
#
# "expired" shows that retention ran and that a deletion is detected. The
# stopped site's first 48h must have a 5m block, which shows that
# downsampling ran.
#
# Usage: scripts/thanos-retention-behavior-test.sh
# The retention flags can be overridden to compare other settings, e.g.
#   RETENTION_RAW=30d scripts/thanos-retention-behavior-test.sh   # fails
# Needs docker and python3. Uses the image versions the playbooks deploy.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
thanos_pb="$repo/playbooks/apply/thanos-query-apply.yml"
prom_pb="$repo/playbooks/apply/prometheus-apply.yml"

retention_default() {
	sed -n "s/.*--retention\.resolution-$1={{ thanos_compact_retention_$1 | default('\([0-9]*[a-z]\)', true) }}.*/\1/p" "$thanos_pb"
}
play_var() {
	sed -n "s/^    $1: \"\(.*\)\"$/\1/p" "$2" | head -n 1
}

raw=${RETENTION_RAW:-$(retention_default raw)}
res5m=${RETENTION_5M:-$(retention_default 5m)}
res1h=${RETENTION_1H:-$(retention_default 1h)}
thanos_image="thanosio/thanos:$(play_var thanos_version "$thanos_pb")"
prom_image="prom/prometheus:$(play_var prometheus_version "$prom_pb")"
for v in "$raw" "$res5m" "$res1h" "$thanos_image" "$prom_image"; do
	case $v in "" | *:)
		echo "could not read the retention defaults or image versions from the playbooks" >&2
		exit 2 ;;
	esac
done
echo "Compactor retention: raw=$raw 5m=$res5m 1h=$res1h ($thanos_image, promtool from $prom_image)"

work=$(mktemp -d "${TMPDIR:-/tmp}/thanos-retention.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/om" "$work/blocks" "$work/bucket" "$work/compact"
printf 'type: FILESYSTEM\nconfig:\n  directory: /work/bucket\n' >"$work/objstore.yml"

docker_run() {
	docker run --rm --user "$(id -u):$(id -g)" -v "$work:/work" "$@"
}

# Sample ranges, as "<site> <start> <end>" in Unix seconds. The stopped and
# relabelled sites end inside a 2-day compaction window, so their last
# blocks stay short.
python3 - "$work" <<'PY' >"$work/ranges.txt"
import sys, time
work = sys.argv[1]
H, D = 3600, 86400
W = 2 * D                                  # the Compactor's 2d range
k = (int(time.time()) - 45 * D) // W * W   # a 2d boundary ~45 days ago
two_h = (int(time.time()) - 45 * D) // (2 * H) * (2 * H)
ranges = [
    ("short-lived", two_h - 2 * H, two_h),
    ("stopped", k - W, k + 26 * H),
    ("relabel-old", k - W, k + 10 * H),
    ("relabel-new", k + 10 * H, k + 58 * H),
    ("expired", two_h - 50 * D - 2 * H, two_h - 50 * D),
]
for site, start, end in ranges:
    with open(f"{work}/om/{site}.om", "w") as f:
        f.write("# TYPE retention_probe gauge\n")
        for t in range(start, end, 30):
            f.write(f'retention_probe{{job="probe"}} {t % 1000} {t}\n')
        f.write("# EOF\n")
    print(site, start, end)
PY

while read -r site _ _; do
	docker_run --entrypoint promtool "$prom_image" \
		tsdb create-blocks-from openmetrics "/work/om/$site.om" "/work/blocks/$site" >/dev/null
	docker_run "$thanos_image" tools bucket upload-blocks \
		--objstore.config-file=/work/objstore.yml --path="/work/blocks/$site" \
		--label="site=\"$site\"" --log.level=error
done <"$work/ranges.txt"

# One Compactor iteration (no --wait): compaction, downsampling, then
# retention. The default --delete-delay (48h) only marks blocks; a marked
# block counts as deleted below. --consistency-delay=0s because the blocks
# were just made.
if ! docker_run "$thanos_image" compact \
	--data-dir=/work/compact --objstore.config-file=/work/objstore.yml \
	--consistency-delay=0s \
	--retention.resolution-raw="$raw" \
	--retention.resolution-5m="$res5m" \
	--retention.resolution-1h="$res1h" >"$work/compact.log" 2>&1; then
	cat "$work/compact.log" >&2
	echo "thanos compact failed" >&2
	exit 1
fi
if grep -q 'critical error detected; halting' "$work/compact.log"; then
	cat "$work/compact.log" >&2
	echo "thanos compact halted" >&2
	exit 1
fi

python3 - "$work" <<'PY'
import json, os, sys, time
work = sys.argv[1]
bucket = f"{work}/bucket"
blocks = []
for ulid in sorted(os.listdir(bucket)):
    d = os.path.join(bucket, ulid)
    if not os.path.isfile(os.path.join(d, "meta.json")):
        continue
    m = json.load(open(os.path.join(d, "meta.json")))
    blocks.append({
        "site": m["thanos"]["labels"].get("site"),
        "min": m["minTime"] // 1000,
        "max": m["maxTime"] // 1000,
        "res": m["thanos"]["downsample"]["resolution"],
        "marked": os.path.exists(os.path.join(d, "deletion-mark.json")),
    })

# True when the unmarked blocks of a site cover every sample in
# [start, end). Samples are 30s apart, so adjacent blocks may leave a 30s gap.
def covered(site, start, end):
    t = start
    for b in sorted((b for b in blocks if b["site"] == site and not b["marked"]), key=lambda b: b["min"]):
        if b["min"] <= t + 30 and b["max"] >= t:
            t = b["max"]
    return t >= end - 30

expect = {"short-lived": True, "stopped": True, "relabel-old": True, "relabel-new": True, "expired": False}
now = time.time()
failed = False
print(f"{'site':<12} {'data':<22} {'blocks left (raw/5m/1h, marked)':<34} {'want':<8} result")
for line in open(f"{work}/ranges.txt"):
    site, start, end = line.split()
    start, end = int(start), int(end)
    mine = [b for b in blocks if b["site"] == site]
    left = {r: sum(1 for b in mine if b["res"] == r and not b["marked"]) for r in (0, 300000, 3600000)}
    marked = sum(1 for b in mine if b["marked"])
    kept = covered(site, start, end)
    ok = kept == expect[site]
    failed |= not ok
    age = f"{(now - end) / 86400:.1f}d ago, {(end - start) / 3600:.0f}h"
    counts = f"{left[0]}/{left[300000]}/{left[3600000]}, {marked} marked"
    print(f"{site:<12} {age:<22} {counts:<34} {'kept' if expect[site] else 'deleted':<8} "
          f"{'ok' if ok else 'FAIL: ' + ('lost' if expect[site] else 'still there')}")
first_window_5m = any(b["site"] == "stopped" and b["res"] == 300000 for b in blocks)
if not first_window_5m:
    print("FAIL: the stopped site's first 48h has no 5m block; downsampling did not run")
    failed = True
sys.exit(1 if failed else 0)
PY
