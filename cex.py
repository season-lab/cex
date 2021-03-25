import networkx as nx
import sys

from .cex_plugin_manager import CexPluginManager
from .cfg_extractors import ICfgExtractor


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
        return CEX.merge_cfgs(*graphs)

    def find_path(self, binary, src_addr, dst_addr, plugins=None, include_cfgs=True):
        callgraph = self.get_callgraph(binary, src_addr, plugins)
        if nx.number_of_nodes(callgraph) == 0 or dst_addr not in callgraph:
            return []
        cg_path = nx.shortest_path(callgraph, src_addr, dst_addr)
        if not include_cfgs:
            return list(map(lambda n_addr: callgraph.nodes[n_addr]["data"], cg_path))

        def find_path_in_cfg(fun_addr, callee):
            cfg = self.get_cfg(binary, fun_addr, plugins)
            assert cfg is not None # this should not happen, since the functions are taken from the CG

            nodes_callee = list(filter(lambda n_addr: callee in cfg.nodes[n_addr]["data"].calls, cfg.nodes))
            if len(nodes_callee) == 0:
                # This should not happen...
                sys.stderr.write("ERROR: edge in CG between %#x and %#x, but %#x is not in the CFG of %#x\n" % \
                    (fun_addr, callee, callee, fun_addr))
                return list()

            node_callee  = nodes_callee[0]
            if not nx.has_path(cfg, fun_addr, node_callee):
                sys.stderr.write("WARNING: no path between %#x and %#x in the CFG of %#x (non-connected graph?)\n" % \
                    (fun_addr, node_callee, fun_addr))
                return list()

            return list(map(lambda n_addr: cfg.nodes[n_addr]["data"], nx.shortest_path(cfg, fun_addr, node_callee)))

        path = list()
        for i in range(len(cg_path)-1):
            src, dst = cg_path[i:i+2]
            path    += find_path_in_cfg(src, dst)
        return path

    @staticmethod
    def explode_cfg(g):
        res_g = nx.DiGraph()

        exploded_nodes = dict()
        for n_id in g.nodes:
            node_data = g.nodes[n_id]["data"]
            nodes = node_data.explode()

            for n in nodes:
                res_g.add_node(n.addr, data=n)

            for src, dst in zip(nodes, nodes[1:]):
                res_g.add_edge(src.addr, dst.addr)

            if len(nodes) > 1:
                exploded_nodes[n_id] = nodes[-1].addr

        for src_id, dst_id in g.edges:
            if src_id in exploded_nodes:
                src_id = exploded_nodes[src_id]
            res_g.add_edge(src_id, dst_id)
        return res_g

    @staticmethod
    def merge_cfgs(*graphs):
        if len(graphs) == 1:
            return graphs[0]

        exploded_graphs = list(map(CEX.explode_cfg, graphs))
        merged          = CEX.merge_graphs(*exploded_graphs)
        return ICfgExtractor.normalize_graph(merged)

    @staticmethod
    def merge_graphs(*graphs):
        if len(graphs) == 1:
            return graphs[0]

        visited   = set()
        res_graph = nx.DiGraph()
        for g in graphs:
            for n_id in g.nodes:
                if n_id in visited:
                    continue
                visited.add(n_id)
                res_graph.add_node(n_id, data=g.nodes[n_id]["data"])

        for g in graphs:
            for src_id, dst_id in g.edges:
                res_graph.add_edge(src_id, dst_id)

        return res_graph

    @staticmethod
    def to_dot(graph):
        header  = "digraph {\n\tnode [shape=box];\n"
        header += "\tgraph [fontname = \"monospace\"];\n"
        header += "\tnode  [fontname = \"monospace\"];\n"
        header += "\tedge  [fontname = \"monospace\"];\n"
        footer  = "}\n"

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
    def to_json(graph):
        res = "[%s]" % ", ".join(
            map(
                lambda n_id: graph.nodes[n_id]["data"].get_json(list(map(lambda x: x[1], graph.out_edges(n_id)))),
                graph.nodes))
        return res
