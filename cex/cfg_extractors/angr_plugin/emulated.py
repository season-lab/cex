import networkx as nx
import threading
import resource
import logging
import signal
import psutil
import angr
import time
import gc
import os

from cex.cfg_extractors.angr_plugin.common import AngrCfgExtractor
from cex.cfg_extractors import IMultilibCfgExtractor, CGNodeData, CFGInstruction, CFGNodeData
from cex.cfg_extractors.angr_plugin.graph_utils import timeout, TimeoutError

# Define custom handlers. Used to support timeout and maximum memory usage
def sig_handler(signum, frame):
    if signum == signal.SIGUSR1:
        raise Exception("Timeout")
    if signum == signal.SIGUSR2:
        raise Exception("OOM")

signal.signal(signal.SIGUSR1, sig_handler)
signal.signal(signal.SIGUSR2, sig_handler)

class AngrEmuBinaryData(object):
    def __init__(self, proj, cg, icfg_raw, icfg):
        self.proj      = proj
        self.cg        = cg
        self.icfg_raw  = icfg_raw
        self.icfg      = icfg
        self.additional_edges = list()

# Limit the maximum alloc size...
max_malloc_size = 0x10000
class new(angr.SimProcedure):
    def run(self, sim_size):
        if not self.state.solver.symbolic(sim_size) and self.state.solver.eval(sim_size) > max_malloc_size:
            sim_size = max_malloc_size
        return self.state.heap._malloc(sim_size)

class malloc(angr.SimProcedure):
    def run(self, sim_size):
        if not self.state.solver.symbolic(sim_size) and self.state.solver.eval(sim_size) > max_malloc_size:
            sim_size = max_malloc_size
        return self.state.heap._malloc(sim_size)

class calloc(angr.SimProcedure):
    def run(self, sim_nmemb, sim_size):
        if not self.state.solver.symbolic(sim_size) and self.state.solver.eval(sim_size) > max_malloc_size:
            sim_size = max_malloc_size
        if not self.state.solver.symbolic(sim_nmemb) and self.state.solver.eval(sim_nmemb) > max_malloc_size:
            sim_nmemb = max_malloc_size
        return self.state.heap._calloc(sim_nmemb, sim_size)

class memsetWrapper(angr.procedures.libc.memset.memset):
    def run(self, dst_addr, char, num):
        if not self.state.solver.symbolic(num) and self.state.solver.eval(num) > max_malloc_size:
            num = max_malloc_size
        return super().run(dst_addr, char, num)

class memcpyWrapper(angr.procedures.libc.memcpy.memcpy):
    def run(self, dst_addr, src_addr, limit):
        if not self.state.solver.symbolic(limit) and self.state.solver.eval(limit) > max_malloc_size:
            limit = max_malloc_size
        return super().run(dst_addr, src_addr, limit)

class AngrCfgExtractorEmulated(AngrCfgExtractor, IMultilibCfgExtractor):
    log = logging.getLogger("cex.AngrCfgExtractorEmulated")
    # log.setLevel(logging.INFO)

    def __init__(self):
        super().__init__()

        self._state_constructors = dict()
        self.multi_cache = dict()
        self.use_timeout_for_cfg = False

        self.max_memory = None  # bytes
        self.timeout = 1800     # seconds
        self.calldepth = 5
        self.ctx_sensisitivity = 1
        self.bb_iterations = 1

    def set_state_constructor(self, addr, fun: callable):
        self._state_constructors[addr] = fun

    def del_state_constructor(self, addr):
        if addr in self._state_constructors:
            del self._state_constructors[addr]

            # Invalidate caches (we want to rebuild projects)
            self.multi_cache = dict()
            self.data        = dict()

    def _internal_get_cfg(self, proj, addr, state, max_time=None, max_memory=None):
        AngrCfgExtractorEmulated.log.info("Building the CFG @ %#x" % addr)

        should_stop_closure = False
        def monitor_time_memory():
            if max_time is None and max_memory is None:
                return
            process = psutil.Process(os.getpid())

            start = time.time()
            while not should_stop_closure:
                elapsed   = time.time() - start
                mem_usage = process.memory_info().rss

                if max_time is not None and elapsed > max_time:
                    signal.raise_signal(signal.SIGUSR1)
                    break
                if max_memory is not None and mem_usage > max_memory:
                    signal.raise_signal(signal.SIGUSR2)
                    break
                time.sleep(0.1)

        t = threading.Thread(target=monitor_time_memory)
        t.start()

        try:
            # We are accurate, but with an incomplete graph
            # NOTE: keep_state=True is necessary, otherwise
            #       SimProcedures are not called
            cfg = proj.analyses.CFGEmulated(
                fail_fast=True, keep_state=True, starts=[addr],
                context_sensitivity_level=self.ctx_sensisitivity,
                call_depth=self.calldepth,
                max_iterations=self.bb_iterations,
                initial_state=state)
        except Exception as e:
            AngrCfgExtractorEmulated.log.warning("CFGEmulated @ %s+%#x failed [%s]" % (proj.filename, addr, repr(e)))
            if str(e) == "OOM":
                gc.collect()
            cfg = None

        should_stop_closure = True
        t.join()

        AngrCfgExtractorEmulated.log.info("CFG created")
        return cfg

    @staticmethod
    def _hook_if_present(proj, symbol, hook):
        if proj.loader.find_symbol(symbol) is not None:
            proj.hook_symbol(symbol, hook, replace=True)

    def _get_angr_cfg(self, proj, addr):
        # Hook some symbols
        AngrCfgExtractorEmulated._hook_if_present(proj, "_Znwm", new())
        AngrCfgExtractorEmulated._hook_if_present(proj, "_Znwj", new())
        AngrCfgExtractorEmulated._hook_if_present(proj, "malloc", malloc())
        AngrCfgExtractorEmulated._hook_if_present(proj, "calloc", calloc())
        AngrCfgExtractorEmulated._hook_if_present(proj, "memset", memsetWrapper())
        AngrCfgExtractorEmulated._hook_if_present(proj, "memcpy", memcpyWrapper())

        if addr in self._state_constructors:
            state = self._state_constructors[addr](proj)
        else:
            state = None

        if addr % 2 == 0 and AngrCfgExtractor.is_thumb(proj, addr):
            addr += 1

        cfg = self._internal_get_cfg(
            proj,
            addr,
            state,
            max_time=self.timeout if self.use_timeout_for_cfg else None,
            max_memory=self.max_memory)
        return cfg

    @staticmethod
    def _get_multi_hash(binary: str, libraries: list):
        return tuple([binary] + sorted(libraries))

    def _build_multi_project(self, binary: str, libraries: list, addresses: dict):
        h = AngrCfgExtractorEmulated._get_multi_hash(binary, libraries)
        if h not in self.multi_cache:
            main_opts = { 'base_addr' : addresses[binary] }
            lib_opts  = {}
            for l in libraries:
                lib_opts[os.path.basename(l)] = { "base_addr" : addresses[l] }

            proj = angr.Project(
                    binary,
                    main_opts = main_opts,
                    use_system_libs     = False,
                    auto_load_libs      = False,
                    except_missing_libs = False,
                    use_sim_procedures  = True,
                    force_load_libs     = libraries,
                    lib_opts            = lib_opts
                )

            self.multi_cache[h] = AngrEmuBinaryData(
                proj=proj,
                cg=dict(),
                icfg_raw=dict(),
                icfg=dict())

            AngrCfgExtractor._hook_fp_models(self.multi_cache[h].proj)
            # AngrCfgExtractor._hook_misc_models(self.multi_cache[h].proj, self.multi_cache[h].additional_edges)

        return self.multi_cache[h].proj

    def get_multi_callgraph(self, binary, libraries=None, entry=None, addresses=None):
        if libraries is None:
            return self.get_callgraph(binary, entry)

        h     = AngrCfgExtractorEmulated._get_multi_hash(binary, libraries)
        proj  = self._build_multi_project(binary, libraries, addresses)
        entry = entry or proj.entry

        if h in self.multi_cache and entry in self.multi_cache[h].cg:
            return self.multi_cache[h].cg[entry]

        orig_entry = entry
        if AngrCfgExtractor.is_thumb(proj, entry):
            entry += 1

        is_arm = False
        if AngrCfgExtractor.is_arm(proj):
            is_arm = True

        icfg_raw = self._get_angr_cfg(proj, orig_entry)
        if icfg_raw is None:
            self.multi_cache[h].cg[orig_entry] = nx.MultiDiGraph()
            return self.multi_cache[h].cg[orig_entry]

        g = nx.MultiDiGraph()
        for src in proj.kb.functions:
            fun_src = proj.kb.functions[src]
            if is_arm:
                src -= src % 2

            if src not in g.nodes:
                g.add_node(src, data=CGNodeData(addr=src, name=fun_src.name))

            for block_with_call_addr in fun_src.get_call_sites():
                callsite = fun_src.get_block(block_with_call_addr).instruction_addrs[-1]
                if is_arm:
                    callsite -= callsite % 2

                dst = fun_src.get_call_target(block_with_call_addr)
                if dst is None:
                    continue
                fun_dst = proj.kb.functions[dst]
                if fun_dst.is_simprocedure:
                    continue

                if is_arm:
                    dst -= dst % 2

                if dst not in g.nodes:
                    g.add_node(dst, data=CGNodeData(addr=dst, name=fun_dst.name))

                g.add_edge(src, dst, callsite=callsite)

            for block_with_jmp_addr in fun_src.jumpout_sites:
                callsite = fun_src.get_block(block_with_jmp_addr.addr).instruction_addrs[-1]
                if is_arm:
                    callsite -= callsite % 2

                for b_dst in block_with_jmp_addr.successors():
                    dst = b_dst.addr
                    if dst not in proj.kb.functions:
                        continue
                    fun_dst = proj.kb.functions[dst]
                    if fun_dst.is_simprocedure:
                        continue

                    if is_arm:
                        dst -= dst % 2

                    if dst not in g.nodes:
                        g.add_node(dst, data=CGNodeData(addr=dst, name=fun_dst.name))

                    g.add_edge(src, dst, callsite=callsite)

        for src, dst, _, callsite in self.multi_cache[h].additional_edges:
            if is_arm:
                src -= src % 2
                dst -= dst % 2
                callsite -= callsite % 2

            if src in g.nodes and dst in g.nodes:
                g.add_edge(src, dst, callsite=callsite)

        self.multi_cache[h].cg[orig_entry] = g.subgraph(nx.dfs_postorder_nodes(g, orig_entry)).copy()
        self.multi_cache[h].icfg_raw[orig_entry] = icfg_raw
        return self.multi_cache[h].cg[orig_entry]

    def get_icfg(self, binary, libraries=None, entry=None, addresses=None):
        libraries = libraries or list()

        h     = AngrCfgExtractorEmulated._get_multi_hash(binary, libraries)
        proj  = self._build_multi_project(binary, libraries, addresses)
        entry = entry or proj.entry

        if entry in self.multi_cache[h].icfg:
            return self.multi_cache[h].icfg[entry]

        if entry not in self.multi_cache[h].icfg_raw:
            cfg = self._get_angr_cfg(proj, entry)
            if cfg is None:
                self.multi_cache[h].icfg_raw[entry] = None
                return nx.DiGraph()
            self.multi_cache[h].icfg_raw[entry] = cfg

        cfg = self.multi_cache[h].icfg_raw[entry]
        if cfg is None:
            return nx.DiGraph()

        g = nx.DiGraph()
        is_arm = False
        if AngrCfgExtractor.is_arm(proj):
            is_arm = True

        def add_node(node):
            calls = list()
            insns = list()
            if node.block is None:
                return

            try:
                capstone_insns = node.block.capstone.insns
            except KeyError:
                capstone_insns = list()
            for insn in capstone_insns:
                mnemonic = str(insn).split(":")[1].strip().replace("\t", "  ")
                addr = insn.insn.address
                if is_arm:
                    addr -= addr % 2
                insns.append(CFGInstruction(addr=addr, size=insn.size, call_refs=list(), mnemonic=mnemonic))

            if len(insns) == 0:
                return
            if len(calls) > 0:
                insns[-1].call_refs = calls

            is_thumb = False
            addr = node.addr
            if is_arm:
                is_thumb = addr % 2 == 1
                addr    -= addr % 2

            g.add_node(addr, data=CFGNodeData(
                addr=addr,
                insns=insns,
                calls=calls,
                is_thumb=is_thumb))

        for node in cfg.graph.nodes:
            add_node(node)

        for block_src, block_dst in cfg.graph.edges:
            src_addr = block_src.addr
            dst_addr = block_dst.addr
            if is_arm:
                src_addr -= src_addr % 2
                dst_addr -= dst_addr % 2

            if src_addr not in g.nodes or dst_addr not in g.nodes:
                continue
            g.add_edge(src_addr, dst_addr)

        for _, dst, src, _ in self.multi_cache[h].additional_edges:
            if is_arm:
                src -= src % 2
                dst -= dst % 2

            if src in g.nodes and dst in g.nodes:
                g.add_edge(src, dst)

        g = g.subgraph(nx.dfs_postorder_nodes(g, entry)).copy()
        self.multi_cache[h].icfg[entry] = g

        return g
