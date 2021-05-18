import networkx as nx

from collections import defaultdict
from cfg_extractors import ICfgExtractor

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


def merge_cfgs(*graphs):
    if len(graphs) == 1:
        return graphs[0]

    exploded_graphs = list(map(explode_cfg, graphs))
    merged          = merge_graphs(*exploded_graphs)
    return ICfgExtractor.normalize_graph(merged)


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

def fix_graph_addresses(graph, off):
    mapping = lambda a : a + off
    graph = nx.relabel_nodes(graph, mapping, copy=False)
    for n_id in graph.nodes:
        n = graph.nodes[n_id]
        data = n["data"]
        data.addr += off
        if hasattr(data, "calls"):
            for i in range(len(data.calls)):
                data.calls[i] += off
    return graph

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

def to_json(graph):
    res = "[%s]" % ", ".join(
        map(
            lambda n_id: graph.nodes[n_id]["data"].get_json(list(map(lambda x: x[1], graph.out_edges(n_id)))),
            graph.nodes))
    return res
