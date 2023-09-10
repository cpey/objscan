"""
Helper class to support unit testing
"""
import hashlib

class Helper():
    BUF_SIZE = 65536
    OUTPUT_FILE = "/tmp/objscan-test"

    @staticmethod
    def sha1_from_file(fname):
        sha1 = hashlib.sha1()
        with open(fname, 'rb') as f:
            while True:
                data = f.read(Helper.BUF_SIZE)
                if not data:
                    break
                sha1.update(data)
        return sha1.hexdigest()
