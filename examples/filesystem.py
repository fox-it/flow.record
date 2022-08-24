import os
import stat

from datetime import datetime

from flow.record import RecordDescriptor, RecordWriter

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


def hash_file(path, t):
    f = open(path, "rb")
    while 1:
        d = f.read(4096)
        if d == "":
            break
    f.close()


class FilesystemIterator:
    basepath = None

    def __init__(self, basepath):
        self.basepath = basepath
        self.recordType = FilesystemFile

    def classify(self, source, classification):
        self.recordType = FilesystemFile.base(_source=source, _classification=classification)

    def iter(self, path):
        path = os.path.abspath(path)
        return self._iter(path)

    def _iter(self, path):
        if path.startswith("/proc"):
            return

        st = os.lstat(path)

        abspath = path
        if self.basepath and abspath.startswith(self.basepath):
            abspath = abspath[len(self.basepath) :]

        ifmt = stat.S_IFMT(st.st_mode)

        link = None
        if ifmt == stat.S_IFLNK:
            link = os.readlink(path)

        yield self.recordType(
            path=abspath,
            inode=int(st.st_ino),
            dev=int(st.st_dev),
            mode=st.st_mode,
            size=st.st_size,
            uid=st.st_uid,
            gid=st.st_gid,
            ctime=datetime.fromtimestamp(st.st_ctime),
            mtime=datetime.fromtimestamp(st.st_mtime),
            atime=datetime.fromtimestamp(st.st_atime),
            link=link,
        )

        if ifmt == stat.S_IFDIR:
            for i in os.listdir(path):
                if i in (".", ".."):
                    continue

                fullpath = os.path.join(path, i)
                for e in self.iter(fullpath):
                    yield e


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
