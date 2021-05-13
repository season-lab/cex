from cfg_extractors.angr_plugin.common import AngrCfgExtractor

class AngrCfgExtractorFast(AngrCfgExtractor):
    def _get_angr_cfg(self, proj, addr):
        return proj.analyses.CFG(
            normalize=False,
            use_patches=True,
            starts=[addr],
            resolve_indirect_jumps=True)
