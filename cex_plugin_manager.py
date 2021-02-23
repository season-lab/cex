import os

from yapsy.PluginManager import PluginManager

class CexPluginManager(PluginManager):
    def __init__(self):
        self.manager = PluginManager(
            directories_list=[
                os.path.join(os.path.dirname(
                    os.path.realpath(__file__)), "cfg_extractors"),
            ],
            plugin_info_ext="plugin"
        )
        self.manager.collectPlugins()

    def get_plugin_names(self):
        pass

    def get_plugin_by_name(self):
        pass
