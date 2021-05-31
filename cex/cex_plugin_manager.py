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
        self.plugin_dict = dict()
        for p in self.manager.getAllPlugins():
            if p.plugin_object.loadable():
                self.plugin_dict[p.name] = p.plugin_object

    def get_plugin_names(self):
        return list(self.plugin_dict.keys())

    def get_plugin_by_name(self, name):
        return self.plugin_dict[name]
