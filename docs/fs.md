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
a read of either random device answers bytes from the host's CSPRNG, as `getrandom` does.

Changing the tree - `rename`, `link`, `mkdir`, `rmdir`, `unlink`, `symlink` - is the host's own
operation on the rootfs, and a failure comes back as the errno a program branches on rather than as
an exception.

## Two names, one file

The rootfs is a directory on this machine, and a default APFS volume does not tell `xt_connmark.h`
from `xt_CONNMARK.h`. Debian's kernel headers hold both, along with `xt_mark.h`, `xt_dscp.h` and the
rest of that family, so a filesystem that folds case would let one of each pair overwrite the other.

What the walk does instead is keep the two apart by name. A name is looked up as the directory holds
it spelled, which only a listing can say, and a name that another entry would answer to as well is
stored under `.armjit.case.` and the hex of its bytes: `xt_connmark.h` becomes
`.armjit.case.78745f636f6e6e6d61726b2e68`. The escape stays with the name, so once a file is created
that way it is found there by every later lookup, even after the entry that forced the escape is
gone - `dpkg` writes its temporary under the target's own name and renames it after, by which time
the sibling is usually not there any more. `readdir` decodes the escapes back, so the guest sees the
names it created and never the hex.

The host tree shows the escaped spelling for the second of a pair, and a guest name that begins with
`.armjit.case.` followed by hex is read back as the hex means, so an escaped tree is not a tree to
edit from the host side and hand back. `apt-get install linux-libc-dev` unpacks its whole header set
now, which is what `libc6-dev`, `g++` and every `-dev` package depend on.
