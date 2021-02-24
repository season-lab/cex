import sys
import rzpipe
import subprocess
import networkx as nx

from cfg_extractors import CFGNodeData, CGNodeData, ICfgExtractor


class RZCfgExtractor(ICfgExtractor):
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

    @staticmethod
    def _check_pie(binary):
        file_output = subprocess.check_output(["file", binary])
        if b"LSB shared object" in file_output or b"LSB pie executable" in file_output:
            return True
        return False

    @staticmethod
    def _open_rz(binary):
        flags=list()
        if RZCfgExtractor._check_pie(binary):
            flags.append("-B 0x400000")
        rz = rzpipe.open(binary, flags=flags)
        return rz

    def get_callgraph(self, binary, entry=None):
        self.faddr_cache = dict()

        rz = RZCfgExtractor._open_rz(binary)
        rz.cmd("aaaa")  # run also emulation stage

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
        if entry is None:
            return g
        return nx.ego_graph(g, entry, radius=sys.maxsize)

    def get_cfg(self, binary, addr):

        rz = RZCfgExtractor._open_rz(binary)
        rz.cmd("aaaa")  # run also emulation stage

        cfg = rz.cmdj("agj @ %#x" % addr)[0]
        g   = nx.DiGraph()

        for block in cfg["blocks"]:
            addr = block["offset"]
            code = list(map(
                lambda op: "%#x : %s" % (op["offset"], op["disasm"]),
                block["ops"]
            ))
            g.add_node(addr, data=CFGNodeData(addr=addr, code=code))

        for block in cfg["blocks"]:
            addr = block["offset"]
            if addr not in g.nodes:
                sys.stderr.write("WARNING: %#x not in nodes\n" % addr)
                continue

            if "jump" in block:
                dst = block["jump"]
                if dst not in g.nodes:
                    sys.stderr.write("WARNING: %#x not in nodes\n" % dst)
                else:
                    g.add_edge(addr, dst)
            if "fail" in block:
                dst = block["fail"]
                if dst not in g.nodes:
                    sys.stderr.write("WARNING: %#x not in nodes\n" % dst)
                else:
                    g.add_edge(addr, dst)

        rz.quit()
        return g
