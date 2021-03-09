from cfg_extractors.angr_plugin.common import AngrCfgExtractor

class AngrCfgExtractorFast(AngrCfgExtractor):
    def _get_angr_cfg(self, proj):
        temp_cfb = proj.analyses.CFB(exclude_region_types={'kernel', 'tls'})
        return proj.analyses.CFG(
            normalize=False,
            use_patches=True,
            cfb=temp_cfb,
            # data_references=True,
            # cross_references=True,
            resolve_indirect_jumps=True)
