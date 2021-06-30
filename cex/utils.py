import networkx as nx

from collections import defaultdict

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

def normalize_graph(entry, graph, merge_calls=False):
    """ 
        Merge nodes n1 and n2 if:
            - n1 is the only (direct) predecessor of n2
            - n2 is the only (direct) successor of n1
            - the last instruction of n1 is not a call (only if merge_calls is False)
    """

    assert entry is not None

    entry_for_merged = set([entry])
    merged_nodes = dict()
    out_graph    = nx.DiGraph()

    if entry not in graph.nodes:
        return out_graph

    for n_id in nx.dfs_preorder_nodes(graph, entry):
        if n_id in merged_nodes:
            continue

        orig_n_id = n_id
        merged_node_data = graph.nodes[n_id]["data"]
        while 1:
            node_data  = graph.nodes[n_id]["data"]
            successors = list(graph.successors(n_id))
            if len(successors) != 1:
                break

            unique_successor_id = successors[0]
            predecessors = list(graph.predecessors(unique_successor_id))
            if len(predecessors) != 1:
                break

            if unique_successor_id in entry_for_merged:
                break

            assert predecessors[0] == n_id
            if not merge_calls and hasattr(node_data, "insns") and \
                    len(node_data.insns[-1].call_refs) > 0:
                break

            unique_successor_data = graph.nodes[unique_successor_id]["data"]
            merged_nodes[unique_successor_id] = orig_n_id
            entry_for_merged.add(orig_n_id)
            merged_node_data = merged_node_data.join(unique_successor_data)
            n_id = unique_successor_id

        out_graph.add_node(orig_n_id, data=merged_node_data)

    for src_id, dst_id in graph.edges:
        if dst_id in merged_nodes:
            # this edge is surely unique, and is the edge (n1, n2) where n1 and n2 has been merged. Delete this edge!
            continue
        if src_id in merged_nodes:
            # this is an edge from the n2 to its successors, I want to preserve those edges. Keep them!
            src_id = merged_nodes[src_id]

        out_graph.add_edge(src_id, dst_id)

    return out_graph

def merge_cfgs(entry, *graphs):
    if len(graphs) == 0:
        return nx.DiGraph()
    if len(graphs) == 1:
        return graphs[0]
    if len(graphs) == 2 and len(graphs[0].nodes) == 0:
        return graphs[1]
    if len(graphs) == 2 and len(graphs[1].nodes) == 0:
        return graphs[0]

    exploded_graphs = list(map(explode_cfg, graphs))
    merged          = merge_digraphs(*exploded_graphs)
    return normalize_graph(entry, merged)


def merge_digraphs(*graphs):
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

def merge_cgs(*graphs):
    if len(graphs) == 1:
        return graphs[0]

    visited   = set()
    res_graph = nx.MultiDiGraph()
    for g in graphs:
        for n_id in g.nodes:
            if n_id in visited:
                continue
            visited.add(n_id)
            res_graph.add_node(n_id, data=g.nodes[n_id]["data"])

    for g in graphs:
        for src_id, dst_id, i in g.edges:
            callsite = g.edges[src_id, dst_id, i]["callsite"]
            res_graph.add_edge(src_id, dst_id, callsite=callsite)

    return res_graph

def fix_graph_addresses(graph, off):
    mapping = lambda a : a + off
    graph = nx.relabel_nodes(graph, mapping, copy=True)
    for n_id in graph.nodes:
        n = graph.nodes[n_id]
        data = n["data"]
        data.addr += off
        if hasattr(data, "calls"):
            for i in range(len(data.calls)):
                data.calls[i] += off
        if hasattr(data, "insns"):
            for i in range(len(data.insns)):
                data.insns[i].addr += off
        if hasattr(data, "return_sites"):
            for i in range(len(data.return_sites)):
                data.return_sites[i] += off

    for e in graph.edges:
        if len(e) == 2:
            break
        graph.edges[e]["callsite"] += off
    return graph

def to_dot(graph, include_callsites=False):
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
    for e in graph.edges:
        src_id = e[0]
        dst_id = e[1]
        i = e[2] if len(e) > 2 else None

        assert not (include_callsites and i is not None)

        if i is not None and not include_callsites and i != 0:
            continue
        src = graph.nodes[src_id]
        dst = graph.nodes[dst_id]
        if not include_callsites:
            body += "\tnode_%x -> node_%x;\n" % (src["data"].addr, dst["data"].addr)
        else:
            callsite = graph.edges[src_id, dst_id, i]["callsite"]
            body += "\tnode_%x -> node_%x [label=\"%#x\"] ;\n" % (src["data"].addr, dst["data"].addr, callsite)

    return header + body + footer

def to_json(graph):
    res = "[%s]" % ", ".join(
        map(
            lambda n_id: graph.nodes[n_id]["data"].get_json(list(map(lambda x: x[1], graph.out_edges(n_id)))),
            graph.nodes))
    return res
