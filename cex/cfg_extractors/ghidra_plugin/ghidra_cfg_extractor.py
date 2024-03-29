import os
import sys
import json
import time
import logging
import subprocess
import networkx as nx

from cex.cfg_extractors import CFGNodeData, CFGInstruction, CGNodeData, ICfgExtractor, ExtCallInfo
from cex.cfg_extractors.utils import check_pie, get_md5_file


class GhidraBinaryData(object):
    def __init__(self, cfg_raw=None, cg_raw=None, cg=None, acc_cg=None, ext_calls=None):
        self.cfg_raw   = cfg_raw
        self.cg_raw    = cg_raw
        self.cg        = cg
        self.acc_cg    = acc_cg
        self.ext_calls = ext_calls or dict()


class GhidraCfgExtractor(ICfgExtractor):
    log = logging.getLogger("cex.GhidraCfgExtractor")

    CMD_ANALYSIS_ONLY = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "$PROJ_FOLDER",
        "$PROJ_NAME",
        "-analysisTimeoutPerFile", "$TIMEOUT",
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
        "-analysisTimeoutPerFile", "$TIMEOUT",
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
        "-analysisTimeoutPerFile", "$TIMEOUT",
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
        "-analysisTimeoutPerFile", "$TIMEOUT",
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

        self.use_accurate = False
        self.timeout = 1200

    def loadable(self):
        return "GHIDRA_HOME" in os.environ

    def get_project_path(self, binary):
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
                    .replace("$TIMEOUT", str(self.timeout))         \
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
                .replace("$TIMEOUT", str(self.timeout))         \
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
                .replace("$TIMEOUT", str(self.timeout))         \
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
                .replace("$TIMEOUT", str(self.timeout))         \
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
                start = time.time()
                subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elapsed = time.time() - start
                if elapsed >= float(self.timeout):
                    GhidraCfgExtractor.log.warning("CFG: Timeout elapsed on %s" % binary)

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
                start = time.time()
                subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                elapsed = time.time() - start
                if elapsed >= float(self.timeout):
                    GhidraCfgExtractor.log.warning("CG: Timeout elapsed on %s" % binary)

            with open(cg_json_path, "r") as fin:
                cg_raw = json.load(fin)

            self.data[binary].cg_raw = cg_raw

    def define_functions(self, binary, offsets):
        infile = os.path.join(
            self.get_tmp_folder(), get_md5_file(binary) + "_offsets.txt")
        with open(infile, "w") as fout:
            for off in offsets:
                fout.write("%#x\n" % off)

        cmd = self._get_cmd_custom_functions(binary, infile)
        start = time.time()
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        elapsed = time.time() - start
        if elapsed >= float(self.timeout):
            GhidraCfgExtractor.log.warning("DEF_FUNCS: Timeout elapsed on %s" % binary)

        if b"[OUT] OK" in out:
            # at least one function is new
            self._clear_cg_cfg_cache_for_binary(binary)

    def get_cfg_callgraph(self, binary, entry=None):
        self._load_cfg_raw(binary)

        if self.data[binary].cg is None:
            cg = nx.MultiDiGraph()
            for fun_raw in self.data[binary].cfg_raw:
                fun_addr = int(fun_raw["addr"], 16)
                fun_name = fun_raw["name"]
                is_returning = True if fun_raw["is_returning"] == "true" else False

                last_instr = fun_addr
                for block_raw in fun_raw["blocks"]:
                    for instr_raw in block_raw["instructions"]:
                        if int(instr_raw["addr"], 16) > last_instr:
                            last_instr = int(instr_raw["addr"], 16)
                    for call_raw in block_raw["calls"]:
                        if call_raw["type"] == "external":
                            name     = call_raw["name"]
                            callsite = int(call_raw["callsite"], 16)
                            if fun_addr not in self.data[binary].ext_calls:
                                self.data[binary].ext_calls[fun_addr] = list()
                            self.data[binary].ext_calls[fun_addr].append(ExtCallInfo(fun_addr, name, callsite))

                ret_sites = list(map(lambda r: int(r, 16), fun_raw["return_sites"]))
                if is_returning and len(ret_sites) == 0:
                    ret_sites = [last_instr]
                cg.add_node(fun_addr, data=CGNodeData(addr=fun_addr, name=fun_name, is_returning=is_returning, return_sites=ret_sites))

            for fun_raw in self.data[binary].cfg_raw:
                src = int(fun_raw["addr"], 16)
                # if fun_raw["name"] == "operator.new":
                #     # AngrEmulated has "new" model, so its callgraph does not have
                #     # the successors of this node. Let's skip it for consistency
                #     continue

                for block_raw in fun_raw["blocks"]:
                    for call_raw in block_raw["calls"]:
                        if call_raw["type"] == "external":
                            continue

                        dst      = int(call_raw["offset"], 16)
                        callsite = int(call_raw["callsite"], 16)
                        if src not in cg.nodes:
                            sys.stderr.write("WARNING: %#x (src) not in nodes\n" % src)
                            continue
                        if dst not in cg.nodes:
                            sys.stderr.write("WARNING: %#x (dst) not in nodes\n" % dst)
                            continue
                        cg.add_edge(src, dst, callsite=callsite)
            self.data[binary].cg = cg

        # Ignore entry, the caller is in charge of pruning the CG
        return self.data[binary].cg

    def get_accurate_callgraph(self, binary, entry=None):
        self._load_accurate_cg_raw(binary)

        if self.data[binary].acc_cg is None:
            cg = nx.MultiDiGraph()
            for fun_raw in self.data[binary].cg_raw:
                fun_addr = int(fun_raw["addr"], 16)
                fun_name = fun_raw["name"]
                is_returning = fun_raw["is_returning"]
                ret_sites    = list(map(lambda r: int(r, 16), fun_raw["return_sites"]))
                cg.add_node(fun_addr, data=CGNodeData(
                    addr=fun_addr, name=fun_name, is_returning=is_returning, return_sites=ret_sites))

                for call in fun_raw["calls"]:
                    if call["type"] == "external":
                        name     = call["name"]
                        callsite = int(call["callsite"], 16)
                        if fun_addr not in self.data[binary].ext_calls:
                            self.data[binary].ext_calls[fun_addr] = list()
                        self.data[binary].ext_calls[fun_addr].append(ExtCallInfo(fun_addr, name, callsite))

            for fun_raw in self.data[binary].cg_raw:
                if fun_raw["name"] == "operator.new":
                    # AngrEmulated has "new" model, so its callgraph does not have
                    # the successors of this node. Let's skip it for consistency
                    continue

                src = int(fun_raw["addr"], 16)
                for call in fun_raw["calls"]:
                    if call["type"] == "external":
                        continue

                    dst      = int(call["offset"], 16)
                    callsite = int(call["callsite"], 16)
                    if dst not in cg.nodes:
                        sys.stderr.write("WARNING: %#x (dst) not in nodes\n" % dst)
                        continue
                    cg.add_edge(src, dst, callsite=callsite)

            self.data[binary].acc_cg = cg

        # Ignore entry, the caller is in charge of pruning the CG
        return self.data[binary].acc_cg

    def get_external_calls_of(self, binary, addr):
        if binary not in self.data:
            return list()
        if addr not in self.data[binary].ext_calls:
            return list()
        return self.data[binary].ext_calls[addr]

    def get_callgraph(self, binary, entry=None):
        if self.use_accurate:
            return self.get_accurate_callgraph(binary, entry)
        return self.get_cfg_callgraph(binary, entry)

    def get_cfg(self, binary, addr):
        self._load_cfg_raw(binary)
        orig_addr = addr

        target_fun = None
        for fun_raw in self.data[binary].cfg_raw:
            if int(fun_raw["addr"], 16) == addr:
                target_fun = fun_raw
                break

        if target_fun is None:
            return nx.DiGraph()

        is_thumb = True if target_fun["is_thumb"] == "true" else False

        cfg = nx.DiGraph()
        for block_raw in target_fun["blocks"]:
            addr  = int(block_raw["addr"], 16)
            insns = list()
            for insn in block_raw["instructions"]:
                insns.append(CFGInstruction(addr=int(insn["addr"], 16), size=int(insn["size"]), call_refs=list(), mnemonic=insn["mnemonic"]))
            calls = list()
            for c in block_raw["calls"]:
                if c["type"] == "external":
                    continue
                calls.append(int(c["offset"], 16))

            if len(calls) > 0:
                insns[-1].call_refs = calls
            cfg.add_node(addr, data=CFGNodeData(addr=addr, insns=insns, calls=calls, is_thumb=is_thumb))

        for block_raw in target_fun["blocks"]:
            src = int(block_raw["addr"], 16)
            for dst_raw in block_raw["successors"]:
                dst = int(dst_raw, 16)
                if src not in cfg.nodes or dst not in cfg.nodes:
                    continue
                cfg.add_edge(src, dst)

        return self.normalize_graph(orig_addr, cfg)

    def clear_cache(self):
        self.data = dict()

    def _clear_cg_cfg_cache_for_binary(self, binary):
        if binary not in self.data:
            self.data[binary] = GhidraBinaryData()

        self.data[binary].cfg_raw   = None
        self.data[binary].cg_raw    = None
        self.data[binary].cg        = None
        self.data[binary].acc_cg    = None
        self.data[binary].ext_calls = dict()

        binary_md5    = get_md5_file(binary)
        cg_json_name  = "ghidra_cg_" + binary_md5  + ".json"
        cg_json_path  = os.path.join(self.get_tmp_folder(), cg_json_name)
        cfg_json_name = "ghidra_cfg_" + binary_md5  + ".json"
        cfg_json_path = os.path.join(self.get_tmp_folder(), cfg_json_name)

        if os.path.exists(cg_json_path):
            os.remove(cg_json_path)
        if os.path.exists(cfg_json_path):
            os.remove(cfg_json_path)
