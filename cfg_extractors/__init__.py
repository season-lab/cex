from yapsy.IPlugin import IPlugin

import os

class FunctionNotFoundException(Exception):
    def __init__(self, addr):
        super().__init__("Function @ %#x not found" % addr)


class CFGNodeData(object):
    def __init__(self, addr: int, code: list, calls: list):
        self.addr  = addr
        self.code  = code
        self.calls = calls

    def get_dot_label(self):
        return "\l".join(self.code) + "\l"

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
