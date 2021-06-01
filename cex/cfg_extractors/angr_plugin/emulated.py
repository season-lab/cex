import networkx as nx
import angr
import sys
import os

from cex.cfg_extractors.angr_plugin.common import AngrCfgExtractor, AngrBinaryData, check_pie
from cex.cfg_extractors import IMultilibCfgExtractor, CGNodeData


class new(angr.SimProcedure):
    def run(self, sim_size):
        return self.state.heap._malloc(sim_size)


class AngrCfgExtractorEmulated(AngrCfgExtractor, IMultilibCfgExtractor):
    def __init__(self):
        super().__init__()

        self._state_constructors = dict()
        self.multi_cache = dict()

    def set_state_constructor(self, addr, fun: callable):
        self._state_constructors[addr] = fun

    def del_state_constructor(self, addr):
        if addr in self._state_constructors:
            del self._state_constructors

    def _get_angr_cfg(self, proj, addr):
        # Hook some symbols
        proj.hook_symbol("_Znwm", new(), replace=True)
        proj.hook_symbol("_Znwj", new(), replace=True)

        if addr in self._state_constructors:
            state = self._state_constructors[addr](proj)
        else:
            state = None

        if addr % 2 == 0 and AngrCfgExtractor.is_thumb(proj, addr):
            addr += 1

        # We are accurate, but with an incomplete graph
        # NOTE: keep_state=True is necessary, otherwise
        #       SimProcedures are not called
        return proj.analyses.CFGEmulated(
            fail_fast=True, keep_state=True, starts=[addr],
            context_sensitivity_level=1, call_depth=5,
            initial_state=state)

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
                    auto_load_libs      = False,
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

        orig_entry = entry
        if AngrCfgExtractor.is_thumb(proj, entry):
            entry += 1

        is_arm = False
        if AngrCfgExtractor.is_arm(proj):
            is_arm = True

        self._get_angr_cfg(proj, entry)

        g = nx.MultiDiGraph()
        for src in proj.kb.functions:
            fun_src = proj.kb.functions[src]
            if is_arm:
                src -= src % 2

            if src not in g.nodes:
                g.add_node(src, data=CGNodeData(addr=src, name=fun_src.name))

            for block_with_call_addr in fun_src.get_call_sites():
                callsite = fun_src.get_block(block_with_call_addr).instruction_addrs[-1]
                if is_arm:
                    callsite -= callsite % 2

                dst = fun_src.get_call_target(block_with_call_addr)
                fun_dst = proj.kb.functions[dst]
                if fun_dst.is_simprocedure:
                    continue

                if is_arm:
                    dst -= dst % 2

                if dst not in g.nodes:
                    g.add_node(dst, data=CGNodeData(addr=dst, name=fun_dst.name))

                g.add_edge(src, dst, callsite=callsite)

            for block_with_jmp_addr in fun_src.jumpout_sites:
                callsite = fun_src.get_block(block_with_jmp_addr.addr).instruction_addrs[-1]
                if is_arm:
                    callsite -= callsite % 2

                for b_dst in block_with_jmp_addr.successors():
                    dst = b_dst.addr
                    fun_dst = proj.kb.functions[dst]
                    if fun_dst.is_simprocedure:
                        continue

                    if is_arm:
                        dst -= dst % 2

                    if dst not in g.nodes:
                        g.add_node(dst, data=CGNodeData(addr=dst, name=fun_dst.name))

                    g.add_edge(src, dst, callsite=callsite)

        self.multi_cache[h].cg[entry] = nx.ego_graph(g, orig_entry, radius=sys.maxsize)
        return self.multi_cache[h].cg[entry]
