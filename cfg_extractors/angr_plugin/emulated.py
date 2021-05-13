import angr

from cfg_extractors.angr_plugin.common import AngrCfgExtractor


class new(angr.SimProcedure):
    def run(self, sim_size):
        return self.state.heap._malloc(sim_size)


class AngrCfgExtractorEmulated(AngrCfgExtractor):
    def _get_angr_cfg(self, proj, addr):
        # Hook some symbols
        proj.hook_symbol("_Znwm", new(), replace=True)

        # We are accurate, but with an incomplete graph
        # NOTE: keep_state=True is necessary, otherwise
        #       SimProcedures are not called
        return proj.analyses.CFGEmulated(
            fail_fast=True, keep_state=True, starts=[addr],
            context_sensitivity_level=1, call_depth=5)
