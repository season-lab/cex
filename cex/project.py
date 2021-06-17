import networkx as nx
import sys

from .cfg_extractors import IMultilibCfgExtractor
from .cex_plugin_manager import CexPluginManager
from .utils import merge_cgs, merge_cfgs, fix_graph_addresses, explode_cfg, normalize_graph
from .bininfo import BinInfo

def print_err(*msg):
    sys.stderr.write(" ".join(map(str, msg)) + "\n")


class CEXProject(object):
    default_plugin = "AngrFast"
    pm             = CexPluginManager()

    def __init__(self, main_binary: str, libs: list=None, plugins: list=None):
        self.plugins = list(map(lambda p: CEXProject.pm.get_plugin_by_name(p), plugins or [CEXProject.default_plugin]))
        self.multilib_plugins     = list(filter(lambda p: hasattr(p, "get_multi_callgraph"), self.plugins))
        self.non_multilib_plugins = list(filter(lambda p: not hasattr(p, "get_multi_callgraph"), self.plugins))

        self.bin  = BinInfo(main_binary, 0x400000)
        self.libs = list()

        addr = 0x7f000000
        libs = libs or list()
        for lib in libs:
            binfo = BinInfo(lib, addr)
            self.libs.append(binfo)
            addr += binfo.size + 0x1000
            addr  = addr - (addr % 0x1000)

        self._addresses = dict()
        for b in [self.bin] + self.libs:
            self._addresses[b.path] = b.addr
        self._libs_paths = list(map(lambda l: l.path, self.libs))

        self._lib_dep_graph       = None
        self._lib_dep_graph_edges = dict()

    def get_bins(self):
        return [self.bin] + self.libs

    def get_bin_containing(self, addr):
        for b in [self.bin] + self.libs:
            if b.contains_addr(addr):
                return b
        return None

    def get_bininfo(self, name):
        for b in [self.bin] + self.libs:
            if b.name == name:
                return b
        return None

    def _fix_addresses(self, g, b):
        if b.path != self.bin.path:
            g = fix_graph_addresses(g, b.addr - 0x400000)
        return g

    def get_callgraph(self, addr=None):
        b = self.bin if addr is None else self.get_bin_containing(addr)
        if b is None:
            return None
        other_paths = list(map(lambda l: l.path, filter(lambda bb: bb.hash != b.hash, [self.bin] + self.libs)))

        def gen_callgraph_with_fixpoint(bin_info, addr, plugins):
            while 1:
                # Merge callgraphs until a fixpoint is reached (applies only to plugins that construct the callgraph lazily, e.g. Ghidra)
                graphs        = list(map(lambda p: p.get_callgraph(bin_info.path, addr), plugins))
                all_functions = set()
                for g in graphs:
                    for n in g.nodes:
                        all_functions.add(n)

                define_functions_result = list(map(lambda p: p.define_functions(bin_info.path, all_functions), plugins))
                all_false = True
                for r in define_functions_result:
                    if r:
                        all_false = False
                        break
                if all_false:
                    break

            res = merge_cgs(*graphs)
            res = self._fix_addresses(res, bin_info)
            return res

        if len([self.bin] + self.libs) == 1:
            res = gen_callgraph_with_fixpoint(b, addr, self.plugins)
            if addr is not None:
                return nx.ego_graph(res, addr, radius=sys.maxsize)

            return res

        self.get_depgraph()

        def get_involved_libs(g):
            libs = set()
            functions_to_define = dict()
            for n_id in g.nodes:
                binfo = self.get_bin_containing(n_id)
                if binfo is None:
                    continue
                libs.add(binfo)

                if n_id in self._lib_dep_graph_edges:
                    dst_addr = self._lib_dep_graph_edges[n_id]
                    binfo = self.get_bin_containing(dst_addr)
                    if binfo is None:
                        continue
                    libs.add(binfo)
                    rebased_addr = n_id - binfo.min_addr + 0x400000
                    if binfo.path not in functions_to_define:
                        functions_to_define[binfo.path] = set()
                    functions_to_define[binfo.path].add(rebased_addr)

            # Define potentially new functions
            for bin in functions_to_define:
                for p in self.plugins:
                    p.define_functions(bin, list(functions_to_define[bin]))

            return libs

        def add_depgraph_edges(g):
            for src in self._lib_dep_graph_edges:
                dst = self._lib_dep_graph_edges[src]
                if src in g.nodes and dst in g.nodes:
                    g.add_edge(src, dst, callsite=src)
            return g

        graphs = list(map(lambda p: p.get_multi_callgraph(
            b.path, other_paths, addr, self._addresses), self.multilib_plugins))
        res = merge_cgs(*graphs)

        processed = set()
        stack = [self.bin]
        while stack:
            b = stack.pop()
            if b in processed:
                continue
            processed.add(b)
            g = gen_callgraph_with_fixpoint(b, None, self.non_multilib_plugins)

            res = merge_cgs(res, g)
            res = add_depgraph_edges(res)

            for lib in get_involved_libs(res):
                if lib not in processed:
                    stack.append(lib)

        res = add_depgraph_edges(res)
        if addr is not None:
            res = nx.ego_graph(res, addr, radius=sys.maxsize)
        return res

    def get_cfg(self, addr, no_multilib=False):
        b = self.get_bin_containing(addr)
        if b is None:
            return None

        if addr is not None:
            addr = addr - b.addr + 0x400000

        graphs = list(map(lambda p: p.get_cfg(b.path, addr), self.non_multilib_plugins if no_multilib else self.plugins))
        merged = merge_cfgs(*graphs)
        if merged is None:
            return None
        merged = self._fix_addresses(merged, b)
        return merged

    def get_icfg(self, entry, use_multilib_icfg=True):
        cg = self.get_callgraph(entry)

        res_g = nx.DiGraph()
        def add_cfg(addr):
            cfg = self.get_cfg(addr, no_multilib=use_multilib_icfg)
            cfg = cfg or nx.DiGraph()
            cfg = explode_cfg(cfg)

            for addr in cfg.nodes:
                bb = cfg.nodes[addr]["data"]
                res_g.add_node(addr, data=bb)

            for src, dst in cfg.edges:
                res_g.add_edge(src, dst)

            return cfg

        def is_return(bb):
            # Superdumb... Improve it
            return ": ret" in bb.get_dot_label().lower() or ": bx lr" in bb.get_dot_label().lower()

        ret_nodes_cache = dict()
        def get_ret_nodes(entry, cfg):
            if entry in ret_nodes_cache:
                return ret_nodes_cache[entry]

            ret_nodes = list()
            for addr in cfg.nodes:
                bb = cfg.nodes[addr]["data"]
                if is_return(bb):
                    ret_nodes.append(addr)

            ret_nodes_cache[entry] = ret_nodes
            return ret_nodes

        def get_ret_addr(cfg_src, callsite):
            # Just a DUMB function... It finds the fallthrough instruction
            # without assuming the instrunction length (but it must be < 10)
            i = 1
            while i < 10:
                if callsite + i in cfg_src.nodes:
                    return callsite + i
                i += 1
            return None

        cfgs = dict()
        for addr in cg.nodes:
            cfg = add_cfg(addr)
            cfgs[addr] = cfg

        for addr_src, addr_dst, i in cg.edges:
            if len(cfgs[addr_src]) == 0 or len(cfgs[addr_dst]) == 0:
                continue

            callsite = cg.edges[addr_src, addr_dst, i]["callsite"]
            if callsite not in res_g.nodes:
                # The callsite in not among the instructions of the CFG. Skip the edge
                # Most probably an inaccuracy of the original CFG (I debugged a case in angr)
                continue

            assert addr_dst in res_g.nodes
            res_g.add_edge(callsite, addr_dst)

            # Easy edge
            retaddr = get_ret_addr(cfgs[addr_src], callsite)

            # HARD ret edges. Best effort
            if retaddr is None:
                # FIXME: this happens for example with PLT calls between libraries
                continue
            for ret_node in get_ret_nodes(addr_dst, cfgs[addr_dst]):
                assert ret_node in res_g.nodes
                assert retaddr  in res_g.nodes
                res_g.add_edge(ret_node, retaddr)

        if use_multilib_icfg:
            # Dont reconstruct the CFG of every single function, but use the
            # ICFG at entrypoint. This is more scalable but less precise
            b = self.bin if addr is None else self.get_bin_containing(addr)
            other_paths = list(map(lambda l: l.path, filter(lambda bb: bb.hash != b.hash, [self.bin] + self.libs)))
            if b is not None:
                graphs = list(map(lambda p: p.get_icfg(b.path, other_paths, entry, self._addresses), self.multilib_plugins))
                res_g  = merge_cfgs(res_g, *graphs)

        g = normalize_graph(res_g)
        return nx.ego_graph(g, entry, radius=sys.maxsize)

    def get_depgraph(self):
        if self._lib_dep_graph is not None:
            return self._lib_dep_graph

        bins = [self.bin] + self.libs

        g = nx.MultiDiGraph()
        for bin_src in bins:
            if bin_src.hash not in g.nodes:
                g.add_node(bin_src.hash)

            for fun_src in bin_src.imported_functions:
                for bin_dst in bins:
                    if bin_src.hash == bin_dst.hash:
                        continue

                    for fun_dst in bin_dst.exported_functions:
                        if fun_src.name != fun_dst.name:
                            continue

                        if bin_dst.hash not in g.nodes:
                            g.add_node(bin_dst.hash)
                        g.add_edge(bin_src.hash, bin_dst.hash, fun=fun_src.name,
                            src_off=fun_src.offset, dst_off=fun_dst.offset)
                        self._lib_dep_graph_edges[fun_src.offset] = fun_dst.offset

        self._lib_dep_graph = g
        return self._lib_dep_graph

    @staticmethod
    def clear_plugins_cache():
        for pname in CEXProject.pm.get_plugin_names():
            plugin = CEXProject.pm.get_plugin_by_name(pname)
            plugin.clear_cache()

    @staticmethod
    def rebase_addr(addr):
        return addr + 0x400000
