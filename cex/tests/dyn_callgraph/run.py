import networkx as nx
import subprocess
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))
from cfg_extractors.utils import check_pie
from cex import CEX

def usage():
    sys.stderr.write("USAGE: %s <plugin> <cmd> [<arg> ...]\n" % sys.argv[0])
    exit(1)

def check_pincher():
    try:
        subprocess.check_call(["pincher", "-h"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    except:
        return False
    return True

def gen_dyn_callgraph(prog_cmd):
    cmd  = ["pincher", "--callgraph", "/dev/shm/callgraph.dot"]
    cmd += prog_cmd

    subprocess.check_call(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    raw_graph = nx.drawing.nx_pydot.read_dot("/dev/shm/callgraph.dot")

    prog_name   = os.path.basename(prog_cmd[0])
    added_nodes = dict()
    graph       = nx.DiGraph()
    for node_id in raw_graph.nodes:
        label = raw_graph.nodes[node_id]["label"].replace('"', '')
        if prog_name in label:
            if " " in label:
                label = label.split(" ")[1]
            name, offset = label.split("+")
            assert name == prog_name
            graph.add_node(int(offset, 16))
            added_nodes[node_id] = int(offset, 16)

    for src_id, dst_id, i in raw_graph.edges:
        assert i == 0
        if src_id in added_nodes and dst_id in added_nodes:
            graph.add_edge(added_nodes[src_id], added_nodes[dst_id])

    return graph

def find_paths_of_lenght_for_node(G,u,n):
    if n==0:
        return [[u]]
    paths = [[u]+path for neighbor in G.neighbors(u) for path in find_paths_of_lenght_for_node(G,neighbor,n-1) if u not in path]
    return paths

def find_paths_of_lenght(G, k):
    allpaths = []
    for node in G:
        allpaths.extend(find_paths_of_lenght_for_node(G,node,k))
    return allpaths


if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    if not check_pincher():
        sys.stderr.write("pincher not found\n")
        exit(1)

    plugin    = sys.argv[1]
    prog_cmd  = sys.argv[2:]
    prog_path = prog_cmd[0]

    cex = CEX()
    if plugin not in cex.pm.get_plugin_names():
        sys.stderr.write("%s is not a valid plugin name [valid names: %s]\n" % (plugin, " ".join(cex.pm.get_plugin_names())))
        exit(1)

    dyn_callgraph = gen_dyn_callgraph(prog_cmd)
    paths = find_paths_of_lenght(dyn_callgraph, 1)
    if check_pie(prog_path):
        paths = list(map(lambda p: list(map(lambda x: x + 0x400000, p)), paths))

    found = 0
    for path in paths:
        p = cex.find_path(prog_path, path[0], path[-1], plugins=[plugin])
        if len(p) > 0:
            found += 1
        else:
            print("WARNING: path [%#x, %#x] not found" % (path[0], path[1]))

    print("found %d / %d paths" % (found, len(paths)))
