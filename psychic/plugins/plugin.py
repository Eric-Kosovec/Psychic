
class Plugin:

    def __init__(self, patterns=None):
        self._patterns = patterns

    @staticmethod
    def directories():
        return []

    @staticmethod
    def filenames():
        return []

    @staticmethod
    def file_extensions():
        return []

    @staticmethod
    def parse_directory(path):
        pass

    @staticmethod
    def parse_filename(path):
        pass

    @staticmethod
    def parse_extension(path):
        pass

    def patterns(self):
        for pattern in self._patterns:
            yield pattern
