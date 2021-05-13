import sys
import angr
import networkx as nx

from cfg_extractors import CFGNodeData, CFGInstruction, CGNodeData, ICfgExtractor, FunctionNotFoundException
from cfg_extractors.angr_plugin.graph_utils import to_supergraph
from cfg_extractors.utils import check_pie


class AngrBinaryData(object):
    def __init__(self, proj, angr_cfgs, cg, cfg):
        self.proj      = proj
        self.angr_cfgs = angr_cfgs
        self.cg        = cg
        self.cfg       = cfg


class AngrCfgExtractor(ICfgExtractor):
    def __init__(self):
        super().__init__()

        self.data = dict()

    def _build_project(self, binary: str):
        if binary not in self.data:
            load_options={'main_opts': {}}
            if check_pie(binary):
                load_options['main_opts']['base_addr'] = 0x400000
            self.data[binary] = AngrBinaryData(
                proj=angr.Project(binary, auto_load_libs=False, load_options=load_options),
                angr_cfgs=dict(),
                cg=dict(),
                cfg=dict())

    def _get_angr_cfg(self, proj, addr):
        # Look in subclasses
        raise NotImplementedError

    def _build_angr_cfg_cg(self, binary, addr):
        self._build_project(binary)

        if addr not in self.data[binary].angr_cfgs:
            self.data[binary].angr_cfgs[addr] = \
                self._get_angr_cfg(self.data[binary].proj, addr)

    def _build_cg(self, binary, entry):
        self._build_angr_cfg_cg(binary, entry)

        if entry not in self.data[binary].cg:
            g = nx.DiGraph()
            for src, dst, c in self.data[binary].angr_cfgs[entry].functions.callgraph.edges:
                if c != 0:
                    continue
                if src not in self.data[binary].proj.kb.functions or dst not in self.data[binary].proj.kb.functions:
                    sys.stderr.write("ERROR: %#x or %#x is in callgraph, but there is no CFG\n" % (src, dst))
                    continue
                if src not in g.nodes:
                    g.add_node(src, data=CGNodeData(addr=src, name=self.data[binary].proj.kb.functions[src].name))
                if dst not in g.nodes:
                    g.add_node(dst, data=CGNodeData(addr=dst, name=self.data[binary].proj.kb.functions[dst].name))
                g.add_edge(src, dst)

            self.data[binary].cg[entry] = g

    def _build_cfg(self, binary, addr):
        self._build_angr_cfg_cg(binary, addr)

        if addr not in self.data[binary].proj.kb.functions:
            raise FunctionNotFoundException(addr)

        if addr not in self.data[binary].cfg:
            fun = self.data[binary].proj.kb.functions[addr]
            g   = nx.DiGraph()

            # fun_cfg   = to_supergraph(fun.transition_graph_ex(exception_edges=True))
            # fun_edges = [
            #     (src, dst) for (src, dst, data) in fun_cfg.edges(data=True) 
            #         if data['type'] not in ('call', 'return_from_call')]

            def add_node(node):
                calls = list()
                n     = fun.get_node(node.addr)
                for el in n.successors():
                    if el.__class__.__name__ == "Function":
                        calls.append(el.addr)

                insns = list()
                for insn in fun.get_block(node.addr, node.size).capstone.insns:
                    mnemonic = str(insn).split(":")[1].strip().replace("\t", "  ")
                    insns.append(CFGInstruction(addr=insn.insn.address, call_refs=list(), mnemonic=mnemonic))

                if len(calls) > 0:
                    insns[-1].call_refs = calls

                g.add_node(node.addr, data=CFGNodeData(
                    addr=node.addr,
                    insns=insns,
                    calls=calls))

            for block_src, block_dst in fun.graph.edges:
                if block_src.addr not in g.nodes:
                    add_node(block_src)
                if block_dst.addr not in g.nodes:
                    add_node(block_dst)
                g.add_edge(block_src.addr, block_dst.addr)

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
