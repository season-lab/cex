import sys

from cex.utils import normalize_graph
from yapsy.IPlugin import IPlugin
from collections import namedtuple


import os
import networkx as nx

ExtCallInfo = namedtuple("ExtCallInfo", ["fun_addr", "ext_name", "callsite"])

class FunctionNotFoundException(Exception):
    def __init__(self, addr):
        super().__init__("Function @ %#x not found" % addr)


class CFGInstruction(object):
    def __init__(self, addr: int, call_refs: list, mnemonic: str):
        self.addr      = addr
        self.mnemonic  = mnemonic
        self.call_refs = call_refs

    def to_json(self):
        return '{{"addr": {addr}, "mnemonic": "{mnemonic}", "call_refs": {call_refs}}}'.format(
            addr=self.addr,
            mnemonic=self.mnemonic,
            call_refs='[%s]' % ", ".join(map(str, self.call_refs)))

    def __str__(self):
        return "%#x : %s" % (self.addr, self.mnemonic)


class CFGNodeData(object):
    def __init__(self, addr: int, insns: list, calls: list):
        self.addr  = addr
        self.insns = insns
        self.calls = calls

    def get_dot_label(self):
        return "\l".join(map(str, self.insns)) + "\l"

    def get_json(self, successors: list):
        res = '{{"addr": {addr}, "instructions": {insns}, "successors": {successors}}}'
        insns = map(lambda x: x.to_json(), self.insns)
        successors = map(str, successors)
        return res.format(
            addr=self.addr,
            insns="[%s]" % ", ".join(insns),
            successors="[%s]" % ", ".join(successors))

    def join(self, other):
        " Append other instructions to self "
        assert isinstance(other, CFGNodeData)
        return CFGNodeData(self.addr, self.insns + other.insns, self.calls + other.calls)

    def merge(self, other):
        """
        Return the block that has LESS instructions.
         rationale:
           If a graph has a block with less instructions, it is likely
           that the block has been splitted, so the graph is more precise
        """

        assert isinstance(other, CFGNodeData)
        assert self.addr == other.addr

        if len(self.insns) <= len(other.insns):
            return self
        return other

    def explode(self):
        " Split the node in len(insns) nodes "

        res = list()
        for insn in self.insns:
            res.append(CFGNodeData(insn.addr, [insn], insn.call_refs))
        return res

    def __str__(self):
        return "<CFGNode %#x>" % self.addr


class CGNodeData(object):
    def __init__(self, addr: int, name: str, is_returning=True, return_sites=None):
        self.name = name
        self.addr = addr
        self.is_returning = is_returning
        self.return_sites = return_sites or list()

    def get_dot_label(self):
        return "%s @ %#x" % (self.name, self.addr)

    def get_json(self, successors: list):
        return '{{"addr": {addr}, "name": "{name}", "successors": {successors}}}'.format(
            addr=self.addr,
            name=self.name,
            successors="[%s]" % ", ".join(map(str, successors)))

    def __str__(self):
        return "<CGNode %s @ %#x>" % (self.name, self.addr)


class ICfgExtractor(IPlugin):
    def __init__(self):
        super().__init__()
        if not os.path.exists(self.get_tmp_folder()):
            os.mkdir(self.get_tmp_folder())

    def loadable(self):
        return True

    def get_callgraph(self, binary, entry=None):
        raise NotImplementedError

    def get_cfg(self, binary, addr):
        raise NotImplementedError

    def get_tmp_folder(self):
        return "/dev/shm/cex_projects"

    def define_functions(self, binary, addresses):
        # Look also in subclasses
        # This function should notify the plugin that a new functions has been discovered.
        # If this function is new for the plugin, the function should return True.
        return False

    @staticmethod
    def normalize_graph(graph):
        return normalize_graph(graph)

    def clear_cache(self):
        return  # Look in subclasses

    def get_external_calls_of(self, binary, addr):
        # Look in subclasses. If a plugin implements this method, then
        # it must return the list of external functions that the function at addr calls
        # ret_type: ExtCallInfo
        return list()

class IMultilibCfgExtractor(object):
    def get_multi_callgraph(self, binary, libraries=None, entry=None, addresses=None):
        raise NotImplementedError

    def get_icfg(self, binary, libraries=None, entry=None, addresses=None):
        raise NotImplementedError
