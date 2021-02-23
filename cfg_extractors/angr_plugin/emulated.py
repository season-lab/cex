from cfg_extractors.angr_plugin.common import AngrCfgExtractor

class AngrCfgExtractorEmulated(AngrCfgExtractor):
    def _get_angr_cfg(self, proj):
        return proj.analyses.CFGEmulated()
