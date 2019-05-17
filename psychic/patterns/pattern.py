import re


class Pattern:

    def __init__(self, pattern_string='', flags=0):
        self._pattern_string = pattern_string
        self._flags = flags
        self._regex = None

    def compile(self):
        self._regex = re.compile(self._pattern_string, self._flags)

    def decompile(self):
        del self._regex
        self._regex = None

    def pattern(self):
        return self._pattern_string

    def get_matches(self, text):
        if text is None:
            return []

        if self._regex is None:
            self.compile()

        for match in self._regex.finditer(text):
            yield match
