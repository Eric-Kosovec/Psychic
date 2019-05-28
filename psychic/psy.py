import argparse
import inspect
import os
import sys
sys.path.append('../')

from collections import defaultdict
from psychic.plugins.plugin import Plugin

# TODO MAKE MORE MODULAR FOR EASY ADDITIONS OF DIFFERENT LANGUAGES
# TODO SCAN BUILD TOOL/IDE ARTIFACTS
# TODO REPORTING SYSTEM


class Psychic:

    def __init__(self):
        self._filenames = None
        self._directories = None
        self._extensions = None
        self._load_plugins()

    def _load_plugins(self):
        plugins_base = os.path.dirname(os.path.dirname(__file__))
        plugins_base = os.path.join(plugins_base, 'psychic', 'plugins')

        if not os.path.exists(plugins_base):
            print(f"Path to plugins, '{plugins_base},' does not exist.", file=sys.stderr)
            return

        # Add plugins package to where the system looks for files.
        if plugins_base not in sys.path:
            sys.path.append(plugins_base)

        filenames_to_class = defaultdict(lambda: [])
        directories_to_class = defaultdict(lambda: [])
        extensions_to_class = defaultdict(lambda: [])

        for dirpath, dirnames, filenames in os.walk(plugins_base):
            for filename in filenames:
                if self._is_plugin_module(dirpath, filename):
                    prog = __import__(str(filename.split('.')[0]).lower())

                    for name, obj in inspect.getmembers(prog):
                        if inspect.isclass(obj) and obj != Plugin and issubclass(obj, Plugin):
                            clazz = obj()
                            for file in clazz.filenames():
                                filenames_to_class[file].append(clazz)

                            for directory in clazz.directories():
                                directories_to_class[directory].append(clazz)

                            for extension in clazz.file_extensions():
                                if '.' in extension:
                                    extensions_to_class[extension].append(clazz)
                                else:
                                    extensions_to_class[f'.{extension}'].append(clazz)

        self._filenames = filenames_to_class
        self._directories = directories_to_class
        self._extensions = extensions_to_class

    @staticmethod
    def _is_plugin_module(path, filename):
        if path is None or filename is None:
            return False
        return os.path.basename(path) == 'plugins' and filename != 'plugin.py' and not filename.startswith('__') and \
            filename.endswith('.py')

    def search_source(self, source_base):
        if source_base is None:
            raise ValueError('Source base given was None.')

        for dirpath, dirnames, filenames in os.walk(source_base):
            # TODO MAKE MORE CUSTOMIZABLE, SUCH AS FOLDER PATHS, LIKE ECLIPSE/EXAMPLE, ETC.
            for dirname in dirnames:
                if dirname in self._directories:
                    for plugin in self._directories[dirname]:
                        plugin.parse_directory(os.path.join(dirpath, dirname))
            for filename in filenames:
                if '.' in filename and filename[filename.rfind('.'):] in self._extensions:
                    for plugin in self._extensions[filename[filename.rfind('.'):]]:
                        plugin.parse_extension(os.path.join(dirpath, filename))
                if filename in self._filenames:
                    for plugin in self._filenames[filename]:
                        plugin.parse_filename(os.path.join(dirpath, filename))


def main():
    parser = argparse.ArgumentParser(description='Determine authors and/or author location from source code.')
    parser.add_argument('source_base', type=str)
    args = parser.parse_args()
    psychic = Psychic()
    psychic.search_source(args.source_base)


if __name__ == '__main__':
    main()
