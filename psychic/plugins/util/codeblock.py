
class CodeBlock:

    def __init__(self, file, line, text):
        self._file = file
        self._line = line
        self._text = text

    def file(self):
        return self._file

    def line(self):
        return self._line

    def text(self):
        return self._text

    def __repr__(self):
        return f'CodeBlock({self._file, self._line, self._text})'
