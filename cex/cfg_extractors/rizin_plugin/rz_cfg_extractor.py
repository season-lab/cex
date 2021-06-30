import sys
import os
import rzpipe
import subprocess
import networkx as nx

from cex.cfg_extractors import (
    CFGNodeData, CFGInstruction, CGNodeData, ICfgExtractor)
from cex.cfg_extractors.utils import check_pie, get_md5_file


class RizinBinaryData(object):
    def __init__(self):
        self.cfg = dict()  # addr -> cfg
        self.cg  = None


class RZCfgExtractor(ICfgExtractor):
    SPLIT_BLOCKS_AT_CALLS = True
    USE_PROJECTS          = False

    def __init__(self):
        super().__init__()
        self.faddr_cache = dict()
        self.cache = dict()

    def _function_address(self, rz, name):
        if name not in self.faddr_cache:
            addr_raw = rz.cmd("s @ " + name).strip()
            if addr_raw == "":
                addr = None
            else:
                addr = int(addr_raw, 16)
            self.faddr_cache[name] = addr
        return self.faddr_cache[name]

    @staticmethod
    def _get_symbol_name(rz, address):
        symb_name = rz.cmd("f~%x[2]" % address).strip()
        if symb_name == "":
            return None
        return symb_name

    def _open_rz(self, binary):
        binary_md5 = get_md5_file(binary)
        proj_name = os.path.join(self.get_tmp_folder(), "rizin_proj_%s.rzdb" % binary_md5)

        if not RZCfgExtractor.USE_PROJECTS or not os.path.exists(proj_name):
            flags=list()
            if check_pie(binary):
                flags.extend(["-B", "0x400000", "-e", "io.cache=true"])
            rz = rzpipe.open(binary, flags=flags)
            # rz.cmd("e analysis.jmp.tbl=true")   # | jmp table detection (experimental)
            # rz.cmd("e analysis.jmp.indir=true") # | https://book.rizin.re/analysis/code_analysis.html#jump-tables
            # rz.cmd("e analysis.datarefs=true")  # |
            rz.cmd("aaaa")  # run also emulation stage

            if RZCfgExtractor.USE_PROJECTS:
                proj_name = os.path.join(self.get_tmp_folder(), "rizin_proj_%s.rzdb" % binary_md5)
                rz.cmd("Ps %s" % proj_name)
        else:
            rz = rzpipe.open(binary)
            rz.cmd("Po %s" % proj_name)
        return rz

    def loadable(self):
        try:
            subprocess.check_call(["rizin", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except:
            return False

    def get_callgraph(self, binary, entry=None):
        self.faddr_cache = dict()

        if binary not in self.cache:
            self.cache[binary] = RizinBinaryData()

        if self.cache[binary].cg is None:
            rz        = self._open_rz(binary)
            functions = rz.cmdj("aflj")
            cg        = nx.MultiDiGraph()

            for fun in functions:
                addr = fun["offset"]
                name = fun["name"]
                cg.add_node(addr, data=CGNodeData(addr=addr, name=name))

            for src_raw in functions:
                src = src_raw["offset"]
                assert src in cg.nodes

                if "callrefs" not in src_raw:
                    continue
                for dst_raw in src_raw["callrefs"]:
                    if dst_raw["type"] != "CALL":
                        continue
                    dst      = dst_raw["to"]
                    callsite = dst_raw["from"]
                    if dst not in cg.nodes:
                        symb_name = RZCfgExtractor._get_symbol_name(rz, dst)
                        if symb_name is None:
                            sys.stderr.write("WARNING: %#x not in nodes (dst)\n" % dst)
                            continue
                        # External function. Add to CG
                        cg.add_node(dst, data=CGNodeData(addr=dst, name=symb_name))
                    cg.add_edge(src, dst, callsite=callsite)

            self.cache[binary].cg = cg
            rz.quit()

        # Ignore entry, the caller is in charge of pruning the CG
        cg = self.cache[binary].cg
        return cg

    def get_cfg(self, binary, addr):
        self.faddr_cache = dict()

        if binary not in self.cache:
            self.cache[binary] = RizinBinaryData()

        if addr in self.cache[binary].cfg:
            return self.cache[binary].cfg[addr]

        rz  = self._open_rz(binary)
        cfg = rz.cmdj("agj @ %#x" % addr)[0]
        g   = nx.DiGraph()

        edges = list()
        for block in cfg["blocks"]:
            addr = block["offset"]

            insns         = list()
            ops_with_call = list()
            for i, op in enumerate(block["ops"]):
                call_refs = list()
                if "xrefs_from" in op:
                    for ref_raw in op["xrefs_from"]:
                        if ref_raw["type"] == "CALL":
                            call_refs.append(ref_raw["addr"])
                    if len(call_refs) > 0:
                        ops_with_call.append((i, call_refs))
                disasm = "???"
                if "disasm" in op:
                    disasm = op["disasm"]
                insns.append(CFGInstruction(addr=op["offset"], size=op["size"], call_refs=call_refs, mnemonic=disasm))

            if len(ops_with_call) > 0 and RZCfgExtractor.SPLIT_BLOCKS_AT_CALLS:
                prev_op = 0
                for op_idx, call_targets in ops_with_call:
                    op_addr     = addr
                    next_op     = op_idx + 1
                    insns_slice = insns[prev_op:next_op]
                    calls       = call_targets

                    g.add_node(op_addr, data=CFGNodeData(addr=op_addr, insns=insns_slice, calls=calls))
                    if next_op < len(block["ops"]):
                        addr = block["ops"][next_op]["offset"]
                        edges.append((op_addr, addr))
                    prev_op = next_op

                if next_op < len(insns):
                    op_addr     = addr
                    insns_slice = insns[next_op:]
                    g.add_node(op_addr, data=CFGNodeData(addr=op_addr, insns=insns_slice, calls=list()))

            else:
                calls = list(map(lambda x: x[1], ops_with_call))
                g.add_node(addr, data=CFGNodeData(addr=addr, insns=insns, calls=calls))

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

        self.cache[binary].cfg[addr] = self.normalize_graph(addr, g)
        rz.quit()

        return self.cache[binary].cfg[addr]

    def clear_cache(self):
        self.cache = dict()
