import angr
import networkx as nx

from cfg_extractors import CFGNodeData, CGNodeData, ICfgExtractor
from cfg_extractors.angr_plugin.graph_utils import to_supergraph


class BinaryData(object):
    def __init__(self, proj, angr_cfg, angr_cg, cg, cfg):
        self.proj     = proj
        self.angr_cfg = angr_cfg
        self.angr_cg  = angr_cg
        self.cg       = cg
        self.cfg      = cfg


class AngrCfgExtractor(ICfgExtractor):
    def __init__(self):
        super().__init__()

        self.data = dict()

    def _build_project(self, binary: str):
        if binary not in self.data:
            self.data[binary] = BinaryData(
                proj=angr.Project(binary, auto_load_libs=False),
                angr_cfg=None,
                angr_cg=None,
                cg=dict(),
                cfg=dict())

    def _get_angr_cfg(self, proj):
        # Look in subclasses
        raise NotImplementedError

    def _build_angr_cfg_cg(self, binary):
        self._build_project(binary)

        if self.data[binary].angr_cfg is None:
            self.data[binary].angr_cfg = self._get_angr_cfg(self.data[binary].proj)
            self.data[binary].angr_cg  = self.data[binary].angr_cfg.functions.callgraph

    def _build_cg(self, binary, entry):
        self._build_angr_cfg_cg(binary)

        if entry not in self.data[binary].cg:
            g = nx.DiGraph()
            for src, dst in nx.dfs_edges(self.data[binary].angr_cg, source=entry):
                if src not in g.nodes:
                    g.add_node(src, data=CGNodeData(addr=src, name=self.data[binary].angr_cfg.functions[src].name))
                if dst not in g.nodes:
                    g.add_node(dst, data=CGNodeData(addr=dst, name=self.data[binary].angr_cfg.functions[dst].name))
                g.add_edge(src, dst)

            self.data[binary].cg[entry] = g

    def _build_cfg(self, binary, addr):
        self._build_angr_cfg_cg(binary)

        if addr not in self.data[binary].angr_cfg.functions:
            raise Exception("No function at address %#x" % addr)

        if addr not in self.data[binary].cfg:
            fun = self.data[binary].angr_cfg.functions[addr]
            g   = nx.DiGraph()

            fun_cfg   = to_supergraph(fun.transition_graph_ex(exception_edges=True))
            fun_edges = [
                (src, dst) for (src, dst, data) in fun_cfg.edges(data=True) 
                    if data['type'] not in ('call', 'return_from_call')]

            for src, dst in fun_edges:
                if src.addr not in g.nodes:
                    g.add_node(src.addr, data=CFGNodeData(
                        addr=src.addr,
                        code=list(map(str, fun.get_block(src.addr, src.size).capstone.insns))))
                if dst.addr not in g.nodes:
                    g.add_node(dst.addr, data=CFGNodeData(
                        addr=dst.addr,
                        code=list(map(str, fun.get_block(dst.addr, dst.size).capstone.insns))))
                g.add_edge(src.addr, dst.addr)

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
