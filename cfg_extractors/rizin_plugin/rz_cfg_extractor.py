import sys
import os
import rzpipe
import hashlib
import subprocess
import networkx as nx

from cfg_extractors import CFGNodeData, CGNodeData, ICfgExtractor
from cfg_extractors.elf_utils import check_pie


class RZCfgExtractor(ICfgExtractor):
    SPLIT_BLOCKS_AT_CALLS = True
    USE_PROJECTS          = False

    def __init__(self):
        super().__init__()
        self.faddr_cache = dict()

    def _function_address(self, rz, name):
        if name not in self.faddr_cache:
            addr_raw = rz.cmd("s @ " + name).strip()
            if addr_raw == "":
                addr = None
            else:
                addr = int(addr_raw, 16)
            self.faddr_cache[name] = addr
        return self.faddr_cache[name]

    def _open_rz(self, binary):
        with open(binary,'rb') as f_binary:
            binary_md5 = hashlib.md5(f_binary.read()).hexdigest()
        proj_name = os.path.join(self.get_tmp_folder(), "rizin_proj_%s.rzdb" % binary_md5)

        if not RZCfgExtractor.USE_PROJECTS or not os.path.exists(proj_name):
            flags=list()
            if check_pie(binary):
                flags.append("-B 0x400000")
            rz = rzpipe.open(binary, flags=flags)
            # rz.cmd("e analysis.jmp.tbl=true")   # | jmp table detection (experimental)
            # rz.cmd("e analysis.jmp.indir=true") # | https://book.rizin.re/analysis/code_analysis.html#jump-tables
            # rz.cmd("e analysis.datarefs=true")  # |
            rz.cmd("aaaa")  # run also emulation stage

            if RZCfgExtractor.USE_PROJECTS:
                with open(binary,'rb') as f_binary:
                    binary_md5 = hashlib.md5(f_binary.read()).hexdigest()
                proj_name = os.path.join(self.get_tmp_folder(), "rizin_proj_%s.rzdb" % binary_md5)
                rz.cmd("Ps %s" % proj_name)
        else:
            rz = rzpipe.open(binary)
            rz.cmd("Po %s" % proj_name)
        return rz

    def loadable(self):
        try:
            subprocess.check_call(["rz", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except:
            return False

    def get_callgraph(self, binary, entry=None):
        self.faddr_cache = dict()

        rz = self._open_rz(binary)
        cg = rz.cmdj("agCj")
        g  = nx.DiGraph()

        fname_dict = dict()
        for fun in cg:
            name = fun["name"]
            off  = self._function_address(rz, name)
            if off is None:
                continue

            if off not in g.nodes:
                g.add_node(off, data=CGNodeData(addr=off, name=name))

            for called_name in fun["imports"]:
                called_off = self._function_address(rz, called_name)
                if called_off is None:
                    continue
                if called_off not in g.nodes:
                    g.add_node(called_off, data=CGNodeData(addr=called_off, name=called_name))

                g.add_edge(off, called_off)

        rz.quit()
        if entry is None or nx.number_of_nodes(g) == 0:
            return g
        if entry not in g.nodes:
            return nx.null_graph()
        return nx.ego_graph(g, entry, radius=sys.maxsize)

    def get_cfg(self, binary, addr):
        self.faddr_cache = dict()

        rz  = self._open_rz(binary)
        cfg = rz.cmdj("agj @ %#x" % addr)[0]
        g   = nx.DiGraph()

        edges = list()
        for block in cfg["blocks"]:
            addr = block["offset"]

            code = list()
            ops_with_call = list()
            for i, op in enumerate(block["ops"]):
                if "refs" in op:
                    for ref_raw in op["refs"]:
                        if ref_raw["type"] == "CALL":
                            ops_with_call.append((i, int(ref_raw["addr"])))
                code.append("%#x : %s" % (op["offset"], op["disasm"]))

            if len(ops_with_call) > 0 and RZCfgExtractor.SPLIT_BLOCKS_AT_CALLS:
                prev_op = 0
                for op_idx, call_target in ops_with_call:
                    op_addr    = addr
                    next_op    = op_idx + 1
                    code_slice = code[prev_op:next_op]
                    calls      = [call_target]

                    g.add_node(op_addr, data=CFGNodeData(addr=op_addr, code=code_slice, calls=calls))
                    if next_op < len(block["ops"]):
                        addr = block["ops"][next_op]["offset"]
                        edges.append((op_addr, addr))
                    prev_op = next_op

                if next_op < len(code):
                    op_addr    = addr
                    code_slice = code[next_op:]
                    g.add_node(op_addr, data=CFGNodeData(addr=op_addr, code=code_slice, calls=[]))

            else:
                calls = list(map(lambda x: x[1], ops_with_call))
                g.add_node(addr, data=CFGNodeData(addr=addr, code=code, calls=calls))

            if "jump" in block:
                dst = block["jump"]
                edges.append((addr, dst))
            if "fail" in block:
                dst = block["fail"]
                edges.append((addr, dst))

        for src, dst in edges:
            if src not in g.nodes:
                sys.stderr.write("WARNING: %#x not in nodes\n" % src)
                continue
            if dst not in g.nodes:
                sys.stderr.write("WARNING: %#x not in nodes\n" % dst)
                continue
            g.add_edge(src, dst)

        rz.quit()
        return g
