import os
import sys
import json
import hashlib
import subprocess
import networkx as nx

from cfg_extractors import CFGNodeData, CFGInstruction, CGNodeData, ICfgExtractor
from cfg_extractors.elf_utils import check_pie


class GhidraBinaryData(object):
    def __init__(self, cfg_raw=None, cg_raw=None, cg=None):
        self.cfg_raw = cfg_raw
        self.cg_raw  = cg_raw
        self.cg      = cg


class GhidraCfgExtractor(ICfgExtractor):

    CMD_CFG = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        "$GHIDRA_OP",  # either -process (if the project exists) or import
        "$BINARY",
        "-postScript",
        "ExportCFG.java",
        "$OUTFILE",
        # "-deleteProject",
        "-scriptPath",
        os.path.realpath(os.path.dirname(__file__))]

    CMD_PIE_ELF = [
        "-loader",
        "ElfLoader",
        "-loader-imagebase",
        "400000" ]

    def __init__(self):
        super().__init__()
        self.data = dict()

    def loadable(self):
        return "GHIDRA_HOME" in os.environ

    @staticmethod
    def _get_cmd_callgraph(binary):
        ghidra_home = os.environ["GHIDRA_HOME"]
        cmd = GhidraCfgExtractor.CMD_CALLGRAPH[:]

        for i in range(len(cmd)):
            cmd[i] = cmd[i]                           \
                .replace("$GHIDRA_HOME", ghidra_home) \
                .replace("$BINARY", binary)           \
                .replace("$OUTFILE", "/dev/shm/cg.json")

        if check_pie(binary):
            cmd += GhidraCfgExtractor.CMD_PIE_ELF
        return cmd

    def _get_cmd_cfg(self, binary):
        ghidra_home = os.environ["GHIDRA_HOME"]
        cmd = GhidraCfgExtractor.CMD_CFG[:]

        with open(binary,'rb') as f_binary:
            binary_md5 = hashlib.md5(f_binary.read()).hexdigest()
        proj_name = "ghidra_proj_" + binary_md5  + ".gpr"
        ghidra_op = "-import"
        if os.path.exists(os.path.join(self.get_tmp_folder(), proj_name)):
            ghidra_op = "-process"
            binary = os.path.basename(binary)

        for i in range(len(cmd)):
            cmd[i] = cmd[i]                                     \
                .replace("$GHIDRA_HOME", ghidra_home)           \
                .replace("$BINARY", binary)                     \
                .replace("$PROJ_FOLDER", self.get_tmp_folder()) \
                .replace("$PROJ_NAME", proj_name)               \
                .replace("$GHIDRA_OP", ghidra_op)               \
                .replace("$OUTFILE", "/dev/shm/cfg.json")

        if check_pie(binary):
            cmd += GhidraCfgExtractor.CMD_PIE_ELF
        return cmd

    def _load_cfg_raw(self, binary):
        if binary not in self.data:
            self.data[binary] = GhidraBinaryData()

        if self.data[binary].cfg_raw is None:
            cmd = self._get_cmd_cfg(binary)
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL)

            with open("/dev/shm/cfg.json", "r") as fin:
                cfg_raw = json.load(fin)

            self.data[binary].cfg_raw = cfg_raw

    def get_callgraph(self, binary, entry=None):
        self._load_cfg_raw(binary)

        if self.data[binary].cg is None:
            cg = nx.DiGraph()
            for fun_raw in self.data[binary].cfg_raw:
                fun_addr = int(fun_raw["addr"], 16)
                fun_name = fun_raw["name"]
                cg.add_node(fun_addr, data=CGNodeData(addr=fun_addr, name=fun_name))

            for fun_raw in self.data[binary].cfg_raw:
                src = int(fun_raw["addr"], 16)
                for block_raw in fun_raw["blocks"]:
                    for call_raw in block_raw["calls"]:
                        dst = int(call_raw, 16)
                        if src not in cg.nodes:
                            sys.stderr.write("WARNING: %#x (src) not in nodes\n" % src)
                            continue
                        if dst not in cg.nodes:
                            sys.stderr.write("WARNING: %#x (dst) not in nodes\n" % src)
                            continue
                        cg.add_edge(src, dst)
            self.data[binary].cg = cg

        if entry is None:
            return self.data[binary].cg
        if entry not in cg.nodes:
            return nx.null_graph()
        return nx.ego_graph(self.data[binary].cg, entry, radius=sys.maxsize)

    def get_cfg(self, binary, addr):
        self._load_cfg_raw(binary)

        target_fun = None
        for fun_raw in self.data[binary].cfg_raw:
            if int(fun_raw["addr"], 16) == addr:
                target_fun = fun_raw
                break

        if target_fun is None:
            return None

        cfg = nx.DiGraph()
        for block_raw in target_fun["blocks"]:
            addr  = int(block_raw["addr"], 16)
            insns = list()
            for insn in block_raw["instructions"]:
                insns.append(CFGInstruction(addr=int(insn["addr"], 16), call_ref=None, mnemonic=insn["mnemonic"]))
            calls = list(map(lambda x: int(x, 16), block_raw["calls"]))

            assert len(calls) < 2  # should always be the case, since blocks are splitted at calls
            if len(calls) == 1:
                insns[-1].call_ref = calls[0]
            cfg.add_node(addr, data=CFGNodeData(addr=addr, insns=insns, calls=calls))

        for block_raw in target_fun["blocks"]:
            src = int(block_raw["addr"], 16)
            for dst_raw in block_raw["successors"]:
                dst = int(dst_raw, 16)
                cfg.add_edge(src, dst)

        return self.normalize_graph(cfg)
