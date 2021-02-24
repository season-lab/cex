from cex_plugin_manager import CexPluginManager

class CEX(object):
    default_plugin = "AngrFast"

    def __init__(self):
        self.pm = CexPluginManager()

    def get_callgraph(self, binary, entry=None, plugins=None):
        plugins = plugins or [self.default_plugin]
        plugins = list(map(lambda p: self.pm.get_plugin_by_name(p), plugins))

        graphs = list(map(lambda p: p.get_callgraph(binary, entry), plugins))
        return CEX.merge_graphs(*graphs)

    def get_cfg(self, binary, addr, plugins=None):
        plugins = plugins or [self.default_plugin]
        plugins = list(map(lambda p: self.pm.get_plugin_by_name(p), plugins))

        graphs = list(map(lambda p: p.get_cfg(binary, addr), plugins))
        return CEX.merge_graphs(*graphs)

    @staticmethod
    def merge_graphs(*graphs):
        # FIXME: todo

        assert len(graphs) == 1
        return graphs[0]

    @staticmethod
    def to_dot(graph):
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

        return header + body + footer

    @staticmethod
    def to_json(graph, filename):
        pass
