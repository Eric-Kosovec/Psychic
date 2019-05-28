import re


class Pattern:

    def __init__(self, pattern_string, flags=0, name=None):
        self._pattern_string = pattern_string
        self._flags = flags
        self._name = name
        self._regex = None

    def compile(self):
        self._regex = re.compile(self._pattern_string, self._flags)

    def decompile(self):
        del self._regex
        self._regex = None

    def pattern(self):
        return self._pattern_string

    def regex(self):
        if self._regex is None:
            self.compile()
        return self._regex

    def name(self):
        return self._name

    def get_matches(self, text):
        if text is None:
            return []

        if self._regex is None:
            self.compile()

        for match in self._regex.finditer(text):
            yield match
