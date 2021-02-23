from yapsy.IPlugin import IPlugin


class CFGNodeData(object):
    def __init__(self, addr: int, code: list):
        self.addr = addr
        self.code = code

    def get_dot_label(self):
        return "\l".join(code)

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
    def __init__(self, binary=None):
        super().__init__()
        self.binary = binary

    def get_callgraph(self, entry=None):
        raise NotImplementedError

    def get_cfg(self, addr):
        raise NotImplementedError

    @staticmethod
    def to_dot(graph, filename):
        header = "digraph {\n\tnode [shape=box];\n"
        footer = "}\n"

        body = ""
        for node_id in graph.nodes:
            node = graph.nodes[node_id]
            body += "\tnode_%x [label=\"%s\"];\n" % (node["data"].addr, node["data"].get_dot_label())
        body += "\n"
        for src_id, dst_id in graph.edges:
            src = graph.nodes[src_id]
            dst = graph.nodes[dst_id]
            body += "\tnode_%x -> node_%x;\n" % (src["data"].addr, dst["data"].addr)

        with open(filename, "w") as fout:
            fout.write(header)
            fout.write(body)
            fout.write(footer)
