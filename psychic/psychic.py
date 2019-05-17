import argparse
import mimetypes
import os
import pprint
import re

from bisect import bisect_left

from chardet.universaldetector import UniversalDetector

# Scans source code for file paths, network identifiers (ips and addresses)
# Image EXIF, video
# For use in identifying possible authors
# Comment parsing - language used

IPV4_REGEX = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
IPV6_REGEX = re.compile(r'\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*')
URL_REGEX = re.compile(r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))")
MAC_ADDR_REGEX = re.compile(r'(?i)([0-9A-F]{2}[:-]){5}([0-9A-F]{2})')
EMAIL_ADDR_REGEX = re.compile(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)')

PATH_REGEX = re.compile(r"""
                        (([A-Za-z]:)?(\\\w+\w+)+) |
                        (([A-Za-z]:)?(/\w+\w+)+)
""", re.VERBOSE)

# TODO SUPPORT MORE LANGUAGES
COMMENT_REGEX = re.compile(r"""
                           (?P<line_comment> //(?P<line_content>.+)$) |
                           (?P<block_comment> /\*(?P<block_content>(.|[\r\n])*?)\*/)
""", re.MULTILINE | re.VERBOSE)

STRING_REGEX = re.compile(r"""
                           (?P<single_apost> ['](?P<single_apost_content>.+)[']) |
                           (?P<double_apost> ["](?P<double_apost_content>.+)["])
""", re.MULTILINE | re.VERBOSE)


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


class Comment(CodeBlock):
    def __init__(self, file, line, text):
        super().__init__(file, line, text)

    def __repr__(self):
        return f'Comment({self._file, self._line, self._text})'


class String(CodeBlock):

    def __init__(self, file, line, text):
        super().__init__(file, line, text)

    def __repr__(self):
        return f'String({self._file, self._line, self._text})'


class Psychic:

    # Reporting in format of Pattern - File, Line, Data

    def __init__(self, patterns=None):
        # Patterns list of tuples of pattern name, regex string
        if patterns is None:
            self.patterns = []
        else:
            self.patterns = [(pattern[0], re.compile(pattern[1])) for pattern in patterns]
        self.patterns.append(('IPv4', IPV4_REGEX))
        self.patterns.append(('IPv6', IPV6_REGEX))
        self.patterns.append(('File Path', PATH_REGEX))
        self.patterns.append(('URL', URL_REGEX))
        self.patterns.append(('MAC Address', MAC_ADDR_REGEX))
        self.patterns.append(('E-mail Address', EMAIL_ADDR_REGEX))

    def search_source(self, source_base):
        if source_base is None:
            raise ValueError('Source base given was None.')

        source_files = []
        for dirpath, dirnames, filenames in os.walk(source_base):
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                if self._file_is_type(path, 'text'):
                    source_files.append(path)

        for file in source_files:
            print(file)
            comments, strings = self.find_comments_and_strings(file)
            print(comments)
            print(strings)
            self.match_patterns(comments)
            self.match_patterns(strings)

    def match_patterns(self, codeblocks):
        if codeblocks is None:
            raise TypeError('match_patterns given None input.')

        for code in codeblocks:
            for name, pattern in self.patterns:
                for match in pattern.finditer(code.text()):
                    print(f"'{name}' match in '{code.file()}', Line {code.line()}: {match[0]}")

    def find_comments_and_strings(self, path):
        if path is None:
            raise TypeError('find_comments_strings given None input')

        with open(path, encoding=self._determine_encoding(path)) as f:
            data = f.read()

        lines = [match.start() for match in re.finditer('$', data, re.MULTILINE)]

        comments = []
        strings = []

        for match in COMMENT_REGEX.finditer(data):
            if match.lastgroup == 'line_comment':
                comments.append(Comment(path, bisect_left(lines, match.start()) + 1, match.group('line_content')))
            elif match.lastgroup == 'block_comment':
                comments.append(Comment(path, bisect_left(lines, match.start()) + 1, match.group('block_comment')))

        # TODO HANDLE COMMENTS IN STRINGS AND VICE VERSA
        for match in STRING_REGEX.finditer(data):
            if match.lastgroup == 'single_apost':
                strings.append(String(path, bisect_left(lines, match.start()) + 1, match.group('single_apost_content')))
            if match.lastgroup == 'double_apost':
                strings.append(String(path, bisect_left(lines, match.start()) + 1, match.group('double_apost_content')))

        return comments, strings

    @staticmethod
    def _determine_encoding(path):
        if path is None:
            raise TypeError('_determine_encoding given None input')
        detector = UniversalDetector()
        with open(path, 'rb') as file:
            for line in file.readlines():
                detector.feed(line)
                if detector.done:
                    break
        detector.close()
        return detector.result['encoding']

    def add_pattern(self, pattern):
        if pattern is not None and len(pattern) > 0:
            self.patterns.append((pattern[0], re.compile(pattern[1])))

    @staticmethod
    def _file_is_type(path, ftype):
        if path is None or ftype is None or len(ftype) <= 0:
            return False
        # Detects based on file extension
        file_type, _ = mimetypes.guess_type(path, strict=False)
        return file_type is not None and file_type.startswith(f'{ftype}/')


def main():
    parser = argparse.ArgumentParser(description='Determine authors and/or author location from source code.')
    parser.add_argument('source_base', type=str)
    args = parser.parse_args()
    psychic = Psychic()
    psychic.search_source(args.source_base)


if __name__ == '__main__':
    main()
