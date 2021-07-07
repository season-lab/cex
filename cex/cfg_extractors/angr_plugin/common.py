import sys
import angr
import networkx as nx

from cex.cfg_extractors import CFGNodeData, CFGInstruction, CGNodeData, ICfgExtractor, FunctionNotFoundException
from cex.cfg_extractors.angr_plugin.graph_utils import to_supergraph
from cex.cfg_extractors.utils import check_pie

class DummyEmptyModel(angr.SimProcedure):
    def run(self, *args):
        return None

class AngrBinaryData(object):
    def __init__(self, proj, processed, cg, cfg):
        self.proj      = proj
        self.processed = processed
        self.cg        = cg
        self.cfg       = cfg


class AngrCfgExtractor(ICfgExtractor):
    is_thumb_cache = dict()

    def __init__(self):
        super().__init__()

        self.data = dict()
        self.build_cfg = True

    @staticmethod
    def is_arm(proj):
        return proj.arch.name == "ARMEL"

    @staticmethod
    def is_thumb(proj, addr):
        if not AngrCfgExtractor.is_arm(proj):
            return False

        assert addr % 2 == 0

        if proj.filename not in AngrCfgExtractor.is_thumb_cache:
            AngrCfgExtractor.is_thumb_cache[proj.filename] = dict()
        if addr in AngrCfgExtractor.is_thumb_cache[proj.filename]:
            return AngrCfgExtractor.is_thumb_cache[proj.filename][addr]

        # Heuristic 1: check if the lifted block is empty
        try:
            b = proj.factory.block(addr)
        except:
            return True
        if b.size == 0:
            AngrCfgExtractor.is_thumb_cache[proj.filename][addr] = True
            return True

        # Heuristic 2: check number of instructions with capstone
        if len(b.capstone.insns) == 0:
            AngrCfgExtractor.is_thumb_cache[proj.filename][addr] = True
            return True

        # Heuristic 3: check symbols
        for s in proj.loader.symbols:
            if s.rebased_addr == addr + 1:
                AngrCfgExtractor.is_thumb_cache[proj.filename][addr] = True
                return True
            elif s.rebased_addr == addr:
                AngrCfgExtractor.is_thumb_cache[proj.filename][addr] = False
                return False

        AngrCfgExtractor.is_thumb_cache[proj.filename][addr] = False
        return False

    @staticmethod
    def _hook_fp_models(proj):
        # Just an hack to avoid crashes
        def hook_with_dummy(name):
            proj.hook_symbol(name, DummyEmptyModel(), replace=True)

        float_functions = set()
        for s in proj.loader.symbols:
            if proj.is_hooked(s.rebased_addr):
                h = proj.hooked_by(s.rebased_addr)
                if h is None or h.cc is None:
                    continue
                fun_ty = h.cc.func_ty
                if fun_ty is None:
                    continue
                if "double" in fun_ty.returnty.name or "float" in fun_ty.returnty.name:
                    float_functions.add(h.display_name)

        to_hook = float_functions
        for n in to_hook:
            hook_with_dummy(n)

    def _build_project(self, binary: str):
        if binary not in self.data:
            load_options={'main_opts': {}}
            if check_pie(binary):
                load_options['main_opts']['base_addr'] = 0x400000
            self.data[binary] = AngrBinaryData(
                proj=angr.Project(binary, auto_load_libs=False, load_options=load_options),
                processed=set(),
                cg=dict(),
                cfg=dict())
            AngrCfgExtractor._hook_fp_models(self.data[binary].proj)

    def _get_angr_cfg(self, proj, addr):
        # Look in subclasses
        raise NotImplementedError

    def _build_angr_cfg_cg(self, binary, addr):
        self._build_project(binary)

        if not self.build_cfg:
            return

        addr_angr = addr
        if addr % 2 == 0 and AngrCfgExtractor.is_thumb(self.data[binary].proj, addr):
            addr_angr += 1

        if addr not in self.data[binary].processed or \
            addr_angr not in self.data[binary].proj.kb.functions:

            # I trust proj.kb
            self._get_angr_cfg(self.data[binary].proj, addr)
            self.data[binary].processed.add(addr)

    def _build_cg(self, binary, entry):
        self._build_angr_cfg_cg(binary, entry)

        if entry not in self.data[binary].cg:

            orig_entry = entry
            if AngrCfgExtractor.is_thumb(self.data[binary].proj, entry):
                entry += 1

            is_arm = False
            if AngrCfgExtractor.is_arm(self.data[binary].proj):
                is_arm = True

            g = nx.MultiDiGraph()
            for src in self.data[binary].proj.kb.functions:
                fun_src = self.data[binary].proj.kb.functions[src]
                if is_arm:
                    src -= src % 2

                is_returning = fun_src.returning
                ret_sites = list()
                for r in fun_src.ret_sites:
                    if r is not None and r.size is not None and r.size > 0:
                        ret_sites.append(r.addr if not is_arm else (r.addr - r.addr % 2))

                if src not in g.nodes:
                    g.add_node(src, data=CGNodeData(addr=src, name=fun_src.name, is_returning=is_returning, return_sites=ret_sites))

                for block_with_call_addr in fun_src.get_call_sites():
                    try:
                        callsite = fun_src.get_block(block_with_call_addr).instruction_addrs[-1]
                    except:
                        callsite = block_with_call_addr
                    if is_arm:
                        callsite -= callsite % 2

                    dst = fun_src.get_call_target(block_with_call_addr)
                    if dst is None or dst not in self.data[binary].proj.kb.functions:
                        continue
                    fun_dst = self.data[binary].proj.kb.functions[dst]
                    if is_arm:
                        dst -= dst % 2

                    is_returning = fun_dst.returning
                    ret_sites = list()
                    for r in fun_dst.ret_sites:
                        if r is not None and r.size is not None and r.size > 0:
                            ret_sites.append(r.addr if not is_arm else (r.addr - r.addr % 2))

                    if dst not in g.nodes:
                        g.add_node(dst, data=CGNodeData(addr=dst, name=fun_dst.name, is_returning=is_returning, return_sites=ret_sites))

                    g.add_edge(src, dst, callsite=callsite)

                for block_with_jmp_addr in fun_src.jumpout_sites:
                    callsite = fun_src.get_block(block_with_jmp_addr.addr).instruction_addrs[-1]
                    if is_arm:
                        callsite -= callsite % 2

                    for b_dst in block_with_jmp_addr.successors():
                        dst = b_dst.addr
                        if dst not in self.data[binary].proj.kb.functions:
                            continue
                        fun_dst = self.data[binary].proj.kb.functions[dst]
                        if is_arm:
                            dst -= dst % 2

                        is_returning = fun_dst.returning
                        ret_sites = list()
                        for r in fun_dst.ret_sites:
                            if r is not None and r.size is not None and r.size > 0:
                                ret_sites.append(r.addr if not is_arm else (r.addr - r.addr % 2))

                        if dst not in g.nodes:
                            g.add_node(dst, data=CGNodeData(addr=dst, name=fun_dst.name, is_returning=is_returning, return_sites=ret_sites))

                        g.add_edge(src, dst, callsite=callsite)

            self.data[binary].cg[orig_entry] = g.subgraph(nx.dfs_postorder_nodes(g, orig_entry)).copy()

    def _build_cfg(self, binary, addr):
        self._build_angr_cfg_cg(binary, addr)

        is_thumb = False
        addr_angr = addr
        if addr % 2 == 0 and AngrCfgExtractor.is_thumb(self.data[binary].proj, addr):
            addr_angr += 1
            is_thumb = True

        if addr_angr not in self.data[binary].proj.kb.functions:
            return nx.DiGraph()

        if addr not in self.data[binary].cfg:
            is_arm = False
            if AngrCfgExtractor.is_arm(self.data[binary].proj):
                is_arm = True

            fun = self.data[binary].proj.kb.functions[addr_angr]
            g   = nx.DiGraph()

            # fun_cfg   = to_supergraph(fun.transition_graph_ex(exception_edges=True))
            # fun_edges = [
            #     (src, dst) for (src, dst, data) in fun_cfg.edges(data=True) 
            #         if data['type'] not in ('call', 'return_from_call')]

            def add_node(node):
                calls = list()
                n     = fun.get_node(node.addr)
                if n is None:
                    return
                for el in n.successors():
                    if el.__class__.__name__ == "Function":
                        calls.append(el.addr)

                insns = list()
                try:
                    capstone_insns = fun.get_block(node.addr, node.size).capstone.insns
                except KeyError:
                    return
                for insn in capstone_insns:
                    mnemonic = str(insn).split(":")[1].strip().replace("\t", "  ")
                    addr = insn.insn.address
                    if is_arm:
                        addr -= addr % 2
                    insns.append(CFGInstruction(addr=addr, size=insn.size, call_refs=list(), mnemonic=mnemonic))

                if len(insns) == 0:
                    return
                if len(calls) > 0:
                    insns[-1].call_refs = calls

                addr = node.addr
                if is_arm:
                    addr -= addr % 2

                g.add_node(addr, data=CFGNodeData(
                    addr=addr,
                    insns=insns,
                    calls=calls,
                    is_thumb=is_thumb))

            for node in fun.graph.nodes:
                add_node(node)

            for block_src, block_dst in fun.graph.edges:
                src_addr = block_src.addr
                dst_addr = block_dst.addr
                if is_arm:
                    src_addr -= src_addr % 2
                    dst_addr -= dst_addr % 2

                if src_addr not in g.nodes or dst_addr not in g.nodes:
                    continue
                g.add_edge(src_addr, dst_addr)

            self.data[binary].cfg[addr] = g

    def get_callgraph(self, binary, entry=None):
        self._build_project(binary)

        entry = entry or self.data[binary].proj.entry
        if entry not in self.data[binary].cg:
            self._build_cg(binary, entry)

        return self.data[binary].cg[entry]

    def get_cfg(self, binary, addr):
        self._build_project(binary)
        if addr not in self.data[binary].cfg:
            self._build_cfg(binary, addr)

        return self.data[binary].cfg[addr]
