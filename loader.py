import os
import importlib

def load_plugins():
    plugin_dir = "plugins"
    for filename in os.listdir(plugin_dir):
        if filename.endswith(".py") and not filename.startswith("__"):
            module_name = f"{plugin_dir}.{filename[:-3]}"
            importlib.import_module(module_name)
