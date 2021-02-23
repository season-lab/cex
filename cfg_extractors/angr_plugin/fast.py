from cfg_extractors.angr_plugin.common import AngrCfgExtractor

class AngrCfgExtractorFast(AngrCfgExtractor):
    def _get_angr_cfg(self, proj):
        return proj.analyses.CFGFast()
