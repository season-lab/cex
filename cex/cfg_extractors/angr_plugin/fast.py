from cex.cfg_extractors.angr_plugin.common import AngrCfgExtractor

class AngrCfgExtractorFast(AngrCfgExtractor):
    def _get_angr_cfg(self, proj, addr):
        if addr % 2 == 0 and AngrCfgExtractor.is_thumb(proj, addr):
            addr += 1

        return proj.analyses.CFGFast(
            normalize=False,
            use_patches=True,
            function_starts=[addr],
            resolve_indirect_jumps=True)
