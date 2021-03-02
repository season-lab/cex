from yapsy.IPlugin import IPlugin

import os

class FunctionNotFoundException(Exception):
    def __init__(self, addr):
        super().__init__("Function @ %#x not found" % addr)


class CFGInstruction(object):
    def __init__(self, addr: int, call_ref: int, mnemonic: str):
        self.addr     = addr
        self.mnemonic = mnemonic
        self.call_ref = call_ref

    def __str__(self):
        return "%#x : %s" % (self.addr, self.mnemonic)


class CFGNodeData(object):
    def __init__(self, addr: int, insns: list, calls: list):
        self.addr  = addr
        self.insns = insns
        self.calls = calls

    def get_dot_label(self):
        return "\l".join(map(str, self.insns)) + "\l"

    def __str__(self):
        return "<CFGNode %#x>" % self.addr


class CGNodeData(object):
    def __init__(self, addr: int, name: str):
        self.name = name
        self.addr = addr

    def get_dot_label(self):
        return "%s @ %#x" % (self.name, self.addr)

    def __str__(self):
        return "<CGNode %s @ %#x>" % (self.name, self.addr)


class ICfgExtractor(IPlugin):
    def __init__(self):
        super().__init__()
        if not os.path.exists(self.get_tmp_folder()):
            os.mkdir(self.get_tmp_folder())

    def loadable(self):
        return True

    def get_callgraph(self, binary, entry=None):
        raise NotImplementedError

    def get_cfg(self, binary, addr):
        raise NotImplementedError

    def get_tmp_folder(self):
        return "/tmp/cex_projects"
