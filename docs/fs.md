# The files a guest sees

A guest path is its own: `/` is the rootfs directory on the host, and the kernel maps one to the
other. The mapping walks the components itself instead of handing the path to the host, because the
tree's symbolic links name paths in the *guest's* root: `/usr/bin/awk` is a link to
`/etc/alternatives/awk`, which exists in a Debian rootfs and not at this machine's root. An absolute
target restarts at the rootfs, a relative one is joined to the directory the link sits in, forty
links are the limit, and `..` at the root is the root, the way a chroot behaves. The translator
resolves the same way, for the image it loads and the loader that image asks for.

The forms that do not follow their last component - `unlink`, `rename`, `lstat`, `readlink`,
`symlink`, `link`, and `chmod`/`utimens` with `AT_SYMLINK_NOFOLLOW` - say so to the resolver, so they
name the link rather than what it points at.

## Open files

A descriptor is an entry in a per-process table; the thing behind it is an open file description,
with the position, the flags and a reference count, so a `dup` or `fork` shares one description and
a read through either moves both.

A description also holds a descriptor of the host's own, opened when the file is opened and kept
until the last guest descriptor on it is closed. Reading and writing go through it rather than
through the path, because a program makes a temporary file by writing it, unlinking it and reading
it back: `apt` does that with the lists it downloads, and a kernel that reopens the path would see
`ENOENT` for a file that is still open and still whole.

## What the tree answers

`newfstatat` fills the 128-byte `struct stat` the ABI lays out, with one user - root - as the owner
of everything. `fstat` of an open directory answers for the directory it names rather than for an
inode of its own: a program that opens a directory compares the two, and `shutil.rmtree` reads a
directory whose name and descriptor disagree as a symbolic link and refuses to remove it. `statx` fills its own 256-byte structure with the fields reordered and a mask saying
which were filled; coreutils asks for one before it falls back and prints the `ENOSYS` as an error
on every file it is given.

The xattr family answers the way a file without attributes does: `ENODATA` to a read, an empty list
to a listing, `ENOTSUP` to a write. The tree is a directory on this machine, where the guest's
attribute names mean nothing, and a program that asks is ready for exactly these answers.

Character devices are provided rather than found: `/dev/null`, `/dev/zero`, `/dev/full`,
`/dev/random` and `/dev/urandom` are in the table whether or not the rootfs has a `/dev` at all, and
`random` is one deterministic stream, so a run twice is a run twice.

Changing the tree - `rename`, `link`, `mkdir`, `rmdir`, `unlink`, `symlink` - is the host's own
operation on the rootfs, and a failure comes back as the errno a program branches on rather than as
an exception.

## Two names, one file

The rootfs is a directory on this machine, so the tree is only as expressive as the host's
filesystem. A default APFS volume does not tell `xt_connmark.h` from `xt_CONNMARK.h`, and Debian's
kernel headers hold both: `apt-get install linux-libc-dev` unpacks the first and fails on the
second, because dpkg's `rename` finds the temporary file gone, renamed to the other name. The same
applies to `xt_mark.h`, `xt_dscp.h` and the rest of that family. A case-sensitive volume for the
rootfs - an APFS volume made with `case-sensitive`, or any Linux filesystem mounted here - is what a
Debian tree needs, and nothing inside the guest can make up the difference.
