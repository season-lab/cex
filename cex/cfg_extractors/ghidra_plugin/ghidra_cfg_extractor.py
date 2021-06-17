import os
import sys
import json
import subprocess
import networkx as nx

from cex.cfg_extractors import CFGNodeData, CFGInstruction, CGNodeData, ICfgExtractor
from cex.cfg_extractors.utils import check_pie, get_md5_file


class GhidraBinaryData(object):
    def __init__(self, cfg_raw=None, cg_raw=None, cg=None, acc_cg=None):
        self.cfg_raw = cfg_raw
        self.cg_raw  = cg_raw
        self.cg      = cg
        self.acc_cg  = acc_cg
        self.defined_functions = set()


class GhidraCfgExtractor(ICfgExtractor):

    CMD_ANALYSIS_ONLY = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        "-import",
        "$BINARY",
        "-scriptPath",
        os.path.realpath(os.path.dirname(__file__)) ]

    CMD_CFG_USE_EXISTING = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        "-noanalysis",
        "-process",
        "$BINARY",
        "-postScript",
        "ExportCFG.java",
        "$OUTFILE",
        "-scriptPath",
        os.path.realpath(os.path.dirname(__file__))]

    CMD_CG_USE_EXISTING = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        "-noanalysis",
        "-process",
        "$BINARY",
        "-postScript",
        "ExportAccurateCallgraph.java",
        "$OUTFILE",
        "-scriptPath",
        os.path.realpath(os.path.dirname(__file__))]

    CMD_CFG_CREATE_NEW = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        # "-noanalysis",
        "-analysisTimeoutPerFile", "3600",
        "-import",
        "$BINARY",
        "-postScript",
        "ExportCFG.java",
        "$OUTFILE",
        "-scriptPath",
        os.path.realpath(os.path.dirname(__file__))]

    CMD_CG_CREATE_NEW = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        # "-noanalysis",
        "-analysisTimeoutPerFile", "3600",
        "-import",
        "$BINARY",
        "-postScript",
        "ExportAccurateCallgraph.java",
        "$OUTFILE",
        "-scriptPath",
        os.path.realpath(os.path.dirname(__file__))]

    CMD_CUSTOM_FUNCTIONS_USE_EXISTING = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        "-noanalysis",
        "-process",
        "$BINARY",
        "-postScript",
        "CreateFunctions.java",
        "$INFILE",
        "-scriptPath",
        os.path.realpath(os.path.dirname(__file__))]

    CMD_CUSTOM_FUNCTIONS_NEW = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        # "-noanalysis",
        "-analysisTimeoutPerFile", "3600",
        "-import",
        "$BINARY",
        "-postScript",
        "CreateFunctions.java",
        "$INFILE",
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

        self.use_accurate = True

    def loadable(self):
        return "GHIDRA_HOME" in os.environ

    def get_project_path(self, binary):
        # This will trigger the autoanalysis!
        binary_md5 = get_md5_file(binary)
        proj_name  = "ghidra_proj_" + binary_md5  + ".gpr"
        proj_path  = os.path.join(self.get_tmp_folder(), proj_name)
        if not os.path.exists(proj_path):
            ghidra_home = os.environ["GHIDRA_HOME"]
            cmd = GhidraCfgExtractor.CMD_ANALYSIS_ONLY[:]
            for i in range(len(cmd)):
                cmd[i] = cmd[i]                                     \
                    .replace("$GHIDRA_HOME", ghidra_home)           \
                    .replace("$BINARY", binary)                     \
                    .replace("$PROJ_FOLDER", self.get_tmp_folder()) \
                    .replace("$PROJ_NAME", proj_name)
            if check_pie(binary):
                cmd += GhidraCfgExtractor.CMD_PIE_ELF

            subprocess.check_call(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        return proj_path

    def _get_cmd_custom_functions(self, binary, infile):
        binary_fullpath = binary
        ghidra_home     = os.environ["GHIDRA_HOME"]

        binary_md5 = get_md5_file(binary)
        proj_name  = "ghidra_proj_" + binary_md5  + ".gpr"
        if os.path.exists(os.path.join(self.get_tmp_folder(), proj_name)):
            cmd = GhidraCfgExtractor.CMD_CUSTOM_FUNCTIONS_USE_EXISTING[:]
            binary = os.path.basename(binary)
        else:
            cmd = GhidraCfgExtractor.CMD_CUSTOM_FUNCTIONS_NEW[:]

        for i in range(len(cmd)):
            cmd[i] = cmd[i]                                     \
                .replace("$GHIDRA_HOME", ghidra_home)           \
                .replace("$BINARY", binary)                     \
                .replace("$PROJ_FOLDER", self.get_tmp_folder()) \
                .replace("$PROJ_NAME", proj_name)               \
                .replace("$INFILE", infile)

        if check_pie(binary_fullpath):
            cmd += GhidraCfgExtractor.CMD_PIE_ELF
        return cmd

    def _get_cmd_cfg(self, binary, outfile):
        binary_fullpath = binary
        ghidra_home     = os.environ["GHIDRA_HOME"]

        binary_md5 = get_md5_file(binary)
        proj_name  = "ghidra_proj_" + binary_md5  + ".gpr"
        if os.path.exists(os.path.join(self.get_tmp_folder(), proj_name)):
            cmd = GhidraCfgExtractor.CMD_CFG_USE_EXISTING[:]
            binary = os.path.basename(binary)
        else:
            cmd = GhidraCfgExtractor.CMD_CFG_CREATE_NEW[:]

        for i in range(len(cmd)):
            cmd[i] = cmd[i]                                     \
                .replace("$GHIDRA_HOME", ghidra_home)           \
                .replace("$BINARY", binary)                     \
                .replace("$PROJ_FOLDER", self.get_tmp_folder()) \
                .replace("$PROJ_NAME", proj_name)               \
                .replace("$OUTFILE", outfile)

        if check_pie(binary_fullpath):
            cmd += GhidraCfgExtractor.CMD_PIE_ELF
        return cmd

    def _get_cmd_cg(self, binary, outfile):
        binary_fullpath = binary
        ghidra_home     = os.environ["GHIDRA_HOME"]

        binary_md5 = get_md5_file(binary)
        proj_name  = "ghidra_proj_" + binary_md5  + ".gpr"
        if os.path.exists(os.path.join(self.get_tmp_folder(), proj_name)):
            cmd = GhidraCfgExtractor.CMD_CG_USE_EXISTING[:]
            binary = os.path.basename(binary)
        else:
            cmd = GhidraCfgExtractor.CMD_CG_CREATE_NEW[:]

        for i in range(len(cmd)):
            cmd[i] = cmd[i]                                     \
                .replace("$GHIDRA_HOME", ghidra_home)           \
                .replace("$BINARY", binary)                     \
                .replace("$PROJ_FOLDER", self.get_tmp_folder()) \
                .replace("$PROJ_NAME", proj_name)               \
                .replace("$OUTFILE", outfile)

        if check_pie(binary_fullpath):
            cmd += GhidraCfgExtractor.CMD_PIE_ELF
        return cmd

    def _load_cfg_raw(self, binary):
        if binary not in self.data:
            self.data[binary] = GhidraBinaryData()

        if self.data[binary].cfg_raw is None:
            binary_md5    = get_md5_file(binary)
            cfg_json_name = "ghidra_cfg_" + binary_md5  + ".json"
            cfg_json_path = os.path.join(self.get_tmp_folder(), cfg_json_name)
            if not os.path.exists(cfg_json_path):
                cmd = self._get_cmd_cfg(binary, cfg_json_path)
                subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            with open(cfg_json_path, "r") as fin:
                cfg_raw = json.load(fin)

            self.data[binary].cfg_raw = cfg_raw

    def _load_accurate_cg_raw(self, binary):
        if binary not in self.data:
            self.data[binary] = GhidraBinaryData()

        if self.data[binary].cg_raw is None:
            binary_md5    = get_md5_file(binary)
            cg_json_name = "ghidra_cg_" + binary_md5  + ".json"
            cg_json_path = os.path.join(self.get_tmp_folder(), cg_json_name)
            if not os.path.exists(cg_json_path):
                cmd = self._get_cmd_cg(binary, cg_json_path)
                subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            with open(cg_json_path, "r") as fin:
                cg_raw = json.load(fin)

            self.data[binary].cg_raw = cg_raw

    def clear_cg_cfg_cache_for_binary(self, binary):
        if binary not in self.data:
            self.data[binary] = GhidraBinaryData()

        self.data[binary].cfg_raw = None
        self.data[binary].cg_raw  = None
        self.data[binary].cg      = None
        self.data[binary].acc_cg  = None

        binary_md5    = get_md5_file(binary)
        cg_json_name  = "ghidra_cg_" + binary_md5  + ".json"
        cg_json_path  = os.path.join(self.get_tmp_folder(), cg_json_name)
        cfg_json_name = "ghidra_cfg_" + binary_md5  + ".json"
        cfg_json_path = os.path.join(self.get_tmp_folder(), cfg_json_name)

        if os.path.exists(cg_json_path):
            os.remove(cg_json_path)
        if os.path.exists(cfg_json_path):
            os.remove(cfg_json_path)

    def _load_defined_functions(self, binary):
        if binary not in self.data:
            self.data[binary] = GhidraBinaryData()

        binary_md5         = get_md5_file(binary)
        defined_cache_name = "ghidra_defined_functions_" + binary_md5  + ".txt"
        defined_cache_path = os.path.join(self.get_tmp_folder(), defined_cache_name)
        if os.path.exists(defined_cache_path):
            with open(defined_cache_path, "r") as fin:
                for line in fin:
                    line = int(line.strip(), 16)
                    self.data[binary].defined_functions.add(line)

    def _cache_defined_functions(self, binary):
        if binary not in self.data:
            self.data[binary] = GhidraBinaryData()

        binary_md5         = get_md5_file(binary)
        defined_cache_name = "ghidra_defined_functions_" + binary_md5  + ".txt"
        defined_cache_path = os.path.join(self.get_tmp_folder(), defined_cache_name)
        with open(defined_cache_path, "w") as fout:
            for off in self.data[binary].defined_functions:
                fout.write("%#x\n" % off)

    def define_functions(self, binary, offsets):
        if binary not in self.data:
            self.data[binary] = GhidraBinaryData()

        self._load_defined_functions(binary)

        all_defined = True
        for off in offsets:
            if off not in self.data[binary].defined_functions:
                all_defined = False
        if all_defined:
            return False

        for off in offsets:
            self.data[binary].defined_functions.add(off)
        self._cache_defined_functions(binary)

        infile = "/dev/shm/offsets.txt"
        with open(infile, "w") as fout:
            for off in offsets:
                fout.write("%#x\n" % off)

        cmd = self._get_cmd_custom_functions(binary, infile)
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)

        if b"[OUTPUT_MSG] OK" in out:
            self.clear_cg_cfg_cache_for_binary(binary)
            return True
        return False

    def get_cfg_callgraph(self, binary, entry=None):
        if entry is not None:
            self.define_functions(binary, [entry])
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
                            sys.stderr.write("WARNING: %#x (dst) not in nodes\n" % dst)
                            continue
                        cg.add_edge(src, dst)
            self.data[binary].cg = cg

        # Ignore entry, the caller is in charge of pruning the CG
        return self.data[binary].cg

    def get_accurate_callgraph(self, binary, entry=None):
        if entry is not None:
            self.define_functions(binary, [entry])
        self._load_accurate_cg_raw(binary)

        if self.data[binary].acc_cg is None:
            cg = nx.MultiDiGraph()
            for fun_raw in self.data[binary].cg_raw:
                fun_addr = int(fun_raw["addr"], 16)
                fun_name = fun_raw["name"]
                cg.add_node(fun_addr, data=CGNodeData(addr=fun_addr, name=fun_name))

            for fun_raw in self.data[binary].cg_raw:
                src = int(fun_raw["addr"], 16)
                for call in fun_raw["calls"]:
                    dst      = int(call["offset"], 16)
                    callsite = int(call["callsite"], 16)
                    if dst not in cg.nodes:
                        sys.stderr.write("WARNING: %#x (dst) not in nodes\n" % dst)
                        continue
                    cg.add_edge(src, dst, callsite=callsite)

            self.data[binary].acc_cg = cg

        # Ignore entry, the caller is in charge of pruning the CG
        return self.data[binary].acc_cg

    def get_callgraph(self, binary, entry=None):
        if self.use_accurate:
            return self.get_accurate_callgraph(binary, entry)
        return self.get_cfg_callgraph(binary, entry)

    def get_cfg(self, binary, addr):
        self._load_cfg_raw(binary)

        target_fun = None
        for fun_raw in self.data[binary].cfg_raw:
            if int(fun_raw["addr"], 16) == addr:
                target_fun = fun_raw
                break

        if target_fun is None:
            return nx.DiGraph()

        cfg = nx.DiGraph()
        for block_raw in target_fun["blocks"]:
            addr  = int(block_raw["addr"], 16)
            insns = list()
            for insn in block_raw["instructions"]:
                insns.append(CFGInstruction(addr=int(insn["addr"], 16), call_refs=list(), mnemonic=insn["mnemonic"]))
            calls = list(map(lambda x: int(x, 16), block_raw["calls"]))

            if len(calls) > 0:
                insns[-1].call_refs = calls
            cfg.add_node(addr, data=CFGNodeData(addr=addr, insns=insns, calls=calls))

        for block_raw in target_fun["blocks"]:
            src = int(block_raw["addr"], 16)
            for dst_raw in block_raw["successors"]:
                dst = int(dst_raw, 16)
                cfg.add_edge(src, dst)

        return self.normalize_graph(cfg)

    def clear_cache(self):
        self.data = dict()
