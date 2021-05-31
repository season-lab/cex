import rzpipe
import os

from .cfg_extractors.utils import get_md5_file
from collections import namedtuple

FunctionDescription = namedtuple("FunctionDescription", ["name", "offset", "is_exported"])

class BinInfo(object):
    def __init__(self, bin, addr=None):
        self.path = bin
        self.name = os.path.basename(bin)
        self.hash = get_md5_file(bin)

        self.min_addr = addr or 0x400000

        self.imported_functions = list()
        self.exported_functions = list()

        rz = self._open_rz()

        laddr = rz.cmdj("iIj")["laddr"]

        self.max_addr = laddr
        for s in rz.cmdj("iSj"):
            a = s["vaddr"] + s["vsize"]
            if a > self.max_addr:
                self.max_addr = a

        if laddr == 0:
            self.max_addr += self.min_addr
        else:
            self.min_addr  = laddr

        symbols = rz.cmdj("isj")
        for symbol in symbols:
            if symbol["type"] != "FUNC" or symbol["bind"] != "GLOBAL":
                continue
            if symbol["is_imported"]:
                self.imported_functions.append(
                    FunctionDescription(
                        name=symbol["name"].replace("imp.", ""),
                        offset=symbol["vaddr"] + self.min_addr,
                        is_exported=False))
            else:
                self.exported_functions.append(
                    FunctionDescription(
                        name=symbol["name"],
                        offset=symbol["vaddr"] + self.min_addr,
                        is_exported=True))
        rz.quit()

    @property
    def addr(self):
        return self.min_addr

    @property
    def size(self):
        return self.max_addr - self.min_addr

    def contains_addr(self, addr):
        return self.min_addr <= addr < self.max_addr

    def _open_rz(self):
        return rzpipe.open(self.path, flags=["-2"])

    def __hash__(self):
        return hash(self.hash)

    def __eq__(self, other):
        return isinstance(other, BinInfo) and self.hash == other.hash

    def __str__(self):
        return "BinInfo < %s : %#x -> %#x >" % (self.name, self.min_addr, self.max_addr)
