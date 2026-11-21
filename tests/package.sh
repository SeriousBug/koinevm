#!/bin/bash
# A package installed two ways: by our runtime, and by a real kernel through chroot in a container.
# What a package install is, is a set of files appearing with the modes the package gives them and a
# database that says so, so the two trees are compared file by file: the same paths, the same modes,
# the same bytes.
#
# Timestamps are not compared. A guest's clock is a fixed epoch, so `var/log/dpkg.log` records a
# different date than the container's, and that difference is the clock, not the install.
set -uo pipefail
cd "$(dirname "$0")/.."

rootfs=${KOINEVM_ROOTFS:-rootfs/debian}
deb=${DEB:-target/tmp/debs/hello_2.10-3_arm64.deb}

if [ ! -f "$deb" ]; then
    echo "skip: no package at $deb"
    exit 0
fi
if ! command -v docker > /dev/null; then
    echo "skip: no docker for the native run"
    exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

copy_tree() {
    mkdir -p "$1"
    # On APFS a clone is instant and shares the blocks, so two copies of a rootfs cost nothing.
    cp -a -c "$rootfs/." "$1/" 2> /dev/null || cp -a "$rootfs/." "$1/"
}

echo "== installing $(basename "$deb")"
for side in ours native; do
    copy_tree "$work/$side"
    cp "$deb" "$work/$side/tmp/pkg.deb"
done

fail=0

KOINEVM_ROOTFS="$work/ours" timeout "${GUEST_TIMEOUT:-600}" \
    bash tools/run-rootfs.sh /usr/bin/dpkg -i /tmp/pkg.deb > "$work/ours.out" 2>&1
ours=$?
timeout "${GUEST_TIMEOUT:-600}" docker run --rm -v "$work/native:/r" debian:bookworm \
    chroot /r /usr/bin/dpkg -i /tmp/pkg.deb > "$work/native.out" 2>&1
native=$?

if [ "$ours" != 0 ]; then
    echo "FAIL our run exited $ours:"; head -10 "$work/ours.out" "$work/native.out"; fail=1
fi
if [ "$native" != 0 ]; then
    echo "FAIL the native run exited $native:"; head -10 "$work/native.out"; fail=1
fi
if ! diff -q "$work/ours.out" "$work/native.out" > /dev/null; then
    echo "FAIL the two runs printed different things:"
    diff "$work/native.out" "$work/ours.out" | head -20
    fail=1
fi

python3 - "$work/ours" "$work/native" <<'EOF' || fail=1
import hashlib, os, stat, sys

# The package's own log is the only thing in the tree whose content is a timestamp.
SKIP = ("var/log/",)

def tree(root):
    found = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if rel.startswith(SKIP):
                continue
            st = os.lstat(full)
            mode = stat.S_IMODE(st.st_mode)
            kind = stat.S_IFMT(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                found[rel] = (kind, mode, os.readlink(full))
            elif stat.S_ISREG(st.st_mode):
                found[rel] = (kind, mode, hashlib.sha256(open(full, "rb").read()).hexdigest())
            else:
                found[rel] = (kind, mode, None)
    return found

ours, native = tree(sys.argv[1]), tree(sys.argv[2])
bad = 0
for rel in sorted(set(native) | set(ours)):
    if rel not in ours:
        print(f"  only the native install has {rel}"); bad = 1
    elif rel not in native:
        print(f"  only our install has {rel}"); bad = 1
    elif ours[rel] != native[rel]:
        a, b = ours[rel], native[rel]
        what = "mode" if a[:2] == b[:2] else "content"
        print(f"  {rel}: {what} differs: ours {a[:2]} {a[2]}, native {b[:2]} {b[2]}")
        bad = 1
print(f"  {len(ours)} paths, {sum(1 for v in ours.values() if v[2])} with content")
sys.exit(bad)
EOF

if [ "$fail" -eq 0 ]; then
    echo "ok   dpkg -i $(basename "$deb")"
    echo "ok   the tree it left"
fi
[ "$fail" -eq 0 ]
