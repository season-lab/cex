import os
import sys
import json
import subprocess
import networkx as nx

from cfg_extractors import CFGNodeData, CGNodeData, ICfgExtractor
from cfg_extractors.elf_utils import check_pie


class GhidraCfgExtractor(ICfgExtractor):
    CMD_CALLGRAPH = [
        "$GHIDRA_HOME/support/analyzeHeadless",
        "/tmp/",
        "Test.gpr",
        "-import",
        "$BINARY",
        "-postScript",
        "ExportCallgraph.java",
        "$OUTFILE",
        "-deleteProject",
        "-scriptPath",
        os.path.realpath(os.path.dirname(__file__))]

    CMD_PIE_ELF = [
        "-loader",
        "ElfLoader",
        "-loader-imagebase",
        "400000" ]

    def __init__(self):
        super().__init__()

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

    def get_callgraph(self, binary, entry=None):
        cmd = GhidraCfgExtractor._get_cmd_callgraph(binary)
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL)

        with open("/dev/shm/cg.json", "r") as fin:
            callgraph_raw = json.load(fin)

        cg = nx.DiGraph()
        for node in callgraph_raw:
            addr = int(node["addr"], 16)
            name = node["name"]
            cg.add_node(addr, data=CGNodeData(addr=addr, name=name))

        for node in callgraph_raw:
            src = int(node["addr"], 16)
            for call in node["calls"]:
                dst = int(call, 16)
                cg.add_edge(src, dst)

        if entry is None:
            return cg
        return nx.ego_graph(cg, entry, radius=sys.maxsize)

    def get_cfg(self, binary, addr):
        raise NotImplementedError
