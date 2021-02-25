from yapsy.IPlugin import IPlugin


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

    def get_callgraph(self, binary, entry=None):
        raise NotImplementedError

    def get_cfg(self, binary, addr):
        raise NotImplementedError
