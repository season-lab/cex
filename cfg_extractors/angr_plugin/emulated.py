import networkx as nx
import angr
import sys
import os

from cfg_extractors.angr_plugin.common import AngrCfgExtractor, AngrBinaryData, check_pie
from cfg_extractors import IMultilibCfgExtractor, CGNodeData


class new(angr.SimProcedure):
    def run(self, sim_size):
        return self.state.heap._malloc(sim_size)


class AngrCfgExtractorEmulated(AngrCfgExtractor, IMultilibCfgExtractor):
    def __init__(self):
        super().__init__()

        self.multi_cache = dict()

    def _get_angr_cfg(self, proj, addr):
        # Hook some symbols
        proj.hook_symbol("_Znwm", new(), replace=True)

        # We are accurate, but with an incomplete graph
        # NOTE: keep_state=True is necessary, otherwise
        #       SimProcedures are not called
        return proj.analyses.CFGEmulated(
            fail_fast=True, keep_state=True, starts=[addr],
            context_sensitivity_level=1, call_depth=5)

    @staticmethod
    def _get_multi_hash(binary: str, libraries: list):
        return tuple([binary] + sorted(libraries))

    def _build_multi_project(self, binary: str, libraries: list, addresses: dict):
        assert len(libraries) > 0

        h = AngrCfgExtractorEmulated._get_multi_hash(binary, libraries)
        if h not in self.multi_cache:
            main_opts = { 'base_addr' : addresses[binary] }
            lib_opts  = {}
            for l in libraries:
                lib_opts[os.path.basename(l)] = { "base_addr" : addresses[l] }

            proj = angr.Project(
                    binary,
                    main_opts = main_opts,
                    use_system_libs     = False,
                    auto_load_libs      = True,
                    except_missing_libs = False,
                    use_sim_procedures  = True,
                    force_load_libs     = libraries,
                    lib_opts            = lib_opts
                )

            self.multi_cache[h] = AngrBinaryData(
                proj=proj,
                processed=set(),
                cg=dict(),
                cfg=dict())

        return self.multi_cache[h].proj

    def get_multi_callgraph(self, binary, libraries=None, entry=None, addresses=None):
        if libraries is None:
            return self.get_callgraph(binary, entry)

        h     = AngrCfgExtractorEmulated._get_multi_hash(binary, libraries)
        proj  = self._build_multi_project(binary, libraries, addresses)
        entry = entry or proj.entry

        if h in self.multi_cache and entry in self.multi_cache[h].cg:
            return self.multi_cache[h].cg[entry]

        self._get_angr_cfg(proj, entry)

        callgraph = proj.kb.callgraph
        subgraph  = nx.ego_graph(callgraph, entry, radius=sys.maxsize)

        g = nx.DiGraph()
        for src, dst, c in subgraph.edges:
            if c != 0:
                continue
            if src not in proj.kb.functions or dst not in proj.kb.functions:
                sys.stderr.write("ERROR: %#x or %#x is in callgraph, but there is no CFG\n" % (src, dst))
                continue
            fun_src = proj.kb.functions[src]
            fun_dst = proj.kb.functions[dst]
            if fun_src.is_simprocedure or fun_dst.is_simprocedure:
                # Exclude SimProcedures
                continue
            if src not in g.nodes:
                g.add_node(src, data=CGNodeData(addr=src, name=proj.kb.functions[src].name))
            if dst not in g.nodes:
                g.add_node(dst, data=CGNodeData(addr=dst, name=proj.kb.functions[dst].name))
            g.add_edge(src, dst)

        self.multi_cache[h].cg[entry] = g
        return g
