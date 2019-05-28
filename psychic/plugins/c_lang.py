import re

from bisect import bisect_left

from psychic.plugins.plugin import Plugin
from psychic.plugins.util.codeblock import CodeBlock
from psychic.plugins.util.getencoding import determine_encoding
from psychic.patterns.email_pattern import EmailPattern
from psychic.patterns.ip_patterns import IPv4Pattern, IPv6Pattern
from psychic.patterns.mac_pattern import MACPattern
from psychic.patterns.path_pattern import PathPattern
from psychic.patterns.url_pattern import URLPattern

COMMENT_REGEX = re.compile(r"""
                           (?P<line_comment> //(?P<line_content>.+)$) |
                           (?P<block_comment> /\*(?P<block_content>(.|[\r\n])*?)\*/)
""", re.MULTILINE | re.VERBOSE)

STRING_REGEX = re.compile(r"""
                           (?P<single_apost> ['](?P<single_apost_content>.+)[']) |
                           (?P<double_apost> ["](?P<double_apost_content>.+)["])
""", re.MULTILINE | re.VERBOSE)


class CLang(Plugin):

    def __init__(self):
        patterns = [EmailPattern(), IPv4Pattern(), IPv6Pattern(), MACPattern(), PathPattern(), URLPattern()]
        super().__init__(patterns)

    @staticmethod
    def file_extensions():
        return ['.h', '.c']

    def parse_extension(self, path):
        if path is None:
            return
        # TODO PROPER REPORTING
        comments, strings = self._find_comments_and_strings(path)
        self.match_patterns(comments)
        self.match_patterns(strings)

    def match_patterns(self, codeblocks):
        if codeblocks is None:
            raise TypeError('match_patterns given None input.')

        for code in codeblocks:
            for pattern in self.patterns():
                for match in pattern.regex().finditer(code.text()):
                    print(f"'{pattern.name()}' match in '{code.file()}', Line {code.line()}: {match[0]}")

    # Heuristic
    @staticmethod
    def _find_comments_and_strings(path):
        if path is None:
            raise TypeError('find_comments_strings given None input')

        with open(path, encoding=determine_encoding(path)) as f:
            data = f.read()

        lines = [match.start() for match in re.finditer('$', data, re.MULTILINE)]

        comments = []
        strings = []

        for match in COMMENT_REGEX.finditer(data):
            if match.lastgroup == 'line_comment':
                comments.append(CodeBlock(path, bisect_left(lines, match.start()) + 1, match.group('line_content')))
            elif match.lastgroup == 'block_comment':
                comments.append(CodeBlock(path, bisect_left(lines, match.start()) + 1, match.group('block_comment')))

        # TODO HANDLE COMMENTS IN STRINGS AND VICE VERSA
        for match in STRING_REGEX.finditer(data):
            if match.lastgroup == 'single_apost':
                strings.append(CodeBlock(path, bisect_left(lines, match.start()) + 1, match.group('single_apost_content')))
            if match.lastgroup == 'double_apost':
                strings.append(CodeBlock(path, bisect_left(lines, match.start()) + 1, match.group('double_apost_content')))

        return comments, strings
