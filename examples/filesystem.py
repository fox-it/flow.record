from __future__ import annotations

import stat
from pathlib import Path
from typing import TYPE_CHECKING

from flow.record import RecordDescriptor, RecordWriter

if TYPE_CHECKING:
    from collections.abc import Iterator


descriptor = """
filesystem/unix/entry
    string path;
    varint inode;
    varint dev;
    unix_file_mode mode;
    filesize size;
    uint32 uid;
    uint32 gid;
    datetime ctime;
    datetime mtime;
    datetime atime;
    string link;
"""
FilesystemFile = RecordDescriptor(descriptor)


def hash_file(path: str | Path) -> None:
    with Path(path).open("rb") as f:
        while True:
            d = f.read(4096)
            if not d:
                break


class FilesystemIterator:
    basepath = None

    def __init__(self, basepath: str | None):
        self.basepath = basepath
        self.recordType = FilesystemFile

    def classify(self, source: str, classification: str) -> None:
        self.recordType = FilesystemFile.base(_source=source, _classification=classification)

    def iter(self, path: str | Path) -> Iterator[FilesystemFile]:
        return self._iter(Path(path).resolve())

    def _iter(self, path: Path) -> Iterator[FilesystemFile]:
        if path.is_relative_to("/proc"):
            return

        st = path.lstat()

        abspath = path
        if self.basepath and abspath.startswith(self.basepath):
            abspath = abspath[len(self.basepath) :]

        ifmt = stat.S_IFMT(st.st_mode)

        link = None
        if ifmt == stat.S_IFLNK:
            link = path.readlink()

        yield self.recordType(
            path=abspath,
            inode=int(st.st_ino),
            dev=int(st.st_dev),
            mode=st.st_mode,
            size=st.st_size,
            uid=st.st_uid,
            gid=st.st_gid,
            ctime=st.st_ctime,
            mtime=st.st_mtime,
            atime=st.st_atime,
            link=link,
        )

        if ifmt == stat.S_IFDIR:
            for i in path.iterdir():
                fullpath = path.joinpath(i)
                yield from self.iter(fullpath)


chunk = []


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("target", metavar="TARGET", nargs="*")
    parser.add_argument("-s", dest="source", help="Source")
    parser.add_argument("-c", dest="classification", help="Classification")
    parser.add_argument("-b", dest="base", help="Base directory")

    args = parser.parse_args()

    stream = RecordWriter()

    fsiter = FilesystemIterator(args.base)

    if args.source or args.classification:
        fsiter.classify(args.source, args.classification)

    for path in args.target:
        for r in fsiter.iter(path):
            stream.write(r)
