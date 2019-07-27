import argparse
import bisect
import io
import os
import re

from chardet.universaldetector import UniversalDetector

import yara


class Psychic:

    _INIT_EXTERNALS = {'file_ext': '', 'file_path': '', 'file_name': ''}
    _LINE_REGEX = re.compile('[\n]|$')

    def __init__(self, source_base, rule_paths=None, disable_rules=None, heuristic_paths=None):
        if rule_paths is None:
            rule_paths = []

        if disable_rules is None:
            disable_rules = []

        if heuristic_paths is None:
            heuristic_paths = []

        self._sources = list(self._list_files(source_base))
        self._rules = self._generate_rules(rule_paths, disable_rules)
        self._heuristics = self._generate_heuristics(heuristic_paths)

    def search(self):
        if len(self._heuristics) > 0:
            self.heuristic_search()
            return

    def heuristic_search(self):
        # TODO: PATH ISSUES, DOESN'T MATCH FILEPATH WITH SPACES
        # TODO: PATH ISSUES, DOESN'T MATCH PATH WITH \ IN FRONT, LIKE USERS\Testing
        # TODO: LINE COMMENT NOT QUIT RIGHT, AS MATCHES // IN URL TOO
        # TODO PATH ISSUE DOESN'T MATCH WITH THE CONTENT IN TESTIO
        for source_file in self._sources:
            print()
            print(source_file)

            externals = self._create_externals(source_file)
            lines = self._find_lines(source_file)

            for heuristic_match in self._heuristics.match(source_file, externals=externals):
                for heuristic_string in heuristic_match.strings:
                    base_line_match = bisect.bisect_left(lines, heuristic_string[0])
                    lines_used = set()

                    #print(f'Heuristic match: {heuristic_string}')

                    for rule_match in self._rules.match(data=str(heuristic_string[2], encoding='utf-8'),
                                                        externals=externals):
                        for rule_string in rule_match.strings:
                            offset = lines[len(lines) - 1] if base_line_match >= len(lines) \
                                else lines[base_line_match] + rule_string[0]
                            line = bisect.bisect_left(lines, offset) + 1

                            if (line, rule_string[1]) not in lines_used:
                                print(f'Rule match: {rule_string}')
                                lines_used.add((line, rule_string[1]))

    def _find_lines(self, path):
        # TODO Encoding is assumed to be utf-8, for now, however this may not be the case for some files.
        with io.open(path, encoding='utf-8', newline='') as f:
            data = f.read()
        return [match.start() for match in self._LINE_REGEX.finditer(data)]

    @staticmethod
    def _determine_encoding(path):
        if path is None:
            raise TypeError('determine_encoding given None input')
        detector = UniversalDetector()
        with open(path, 'rb') as file:
            for line in file.readlines():
                detector.feed(line)
                if detector.done:
                    break
        detector.close()
        return detector.result['encoding']

    def _generate_heuristics(self, heuristic_paths):
        if heuristic_paths is None:
            raise ValueError('Generate heuristics given None value(s).')

        heuristics = {}

        if not os.path.exists('heuristics'):
            os.mkdir('heuristics')

        # Pull all heuristics from rules folder first.
        for heuristic_path in self._list_files('heuristics', lambda f: f.endswith('.yar')):
            heuristics[os.path.basename(heuristic_path)[:-len('.yar')]] = heuristic_path

        # Pull in heuristics given from command line, overwriting heuristics from folder, if need be.
        for heuristic_path in heuristic_paths:
            heuristics[os.path.basename(heuristic_path)[:-len('.yar')]] = heuristic_path

        return yara.compile(filepaths=heuristics, externals=self._INIT_EXTERNALS)

    def _generate_rules(self, rule_paths, disable_rules):
        if rule_paths is None or disable_rules is None:
            raise ValueError('Generate rules given None value(s).')

        if not os.path.exists('rules'):
            os.mkdir('rules')

        rules = {}

        # Pull all rules from rules folder first.
        for rule_path in self._list_files('rules', lambda f: f.endswith('.yar')):
            rules[os.path.basename(rule_path)[:-len('.yar')]] = rule_path

        # Pull in rules given from command line, overwriting rules from folder, if need be.
        for rule_path in rule_paths:
            rule_name = os.path.basename(rule_path)[:-len('.yar')]
            if rule_name in rules:
                print(f"Overwriting rule '{rules[rule_name]}' with '{rule_path}'")
            rules[rule_name] = rule_path

        # Disable any unwanted rules.
        for rule in disable_rules:
            if rule in rules or f'{rule}.yar' in rules:
                del rules[rule]

        print(rules)

        return yara.compile(filepaths=rules, externals=self._INIT_EXTERNALS)

    @staticmethod
    def _list_files(base, matcher=lambda noop: True):
        if base is None or not os.path.isdir(base):
            yield
            return
        for path, _, names in os.walk(base):
            for filename in names:
                if matcher(filename):
                    yield os.path.join(path, filename)

    @staticmethod
    def _create_externals(path):
        basename = os.path.basename(path)
        file_ext = '' if '.' not in basename else basename[basename.rfind('.'):]
        file_name = basename if '.' not in basename else basename[:basename.rfind('.')]
        file_path = path
        return {'file_ext': file_ext, 'file_path': file_path, 'file_name': file_name}


def _parse_args():
    parser = argparse.ArgumentParser(description='Determine author(s) and/or author(s) location from source code.')
    parser.add_argument('source_base')
    parser.add_argument('--rules', nargs='*')
    parser.add_argument('--disable-rules', nargs='*')
    parser.add_argument('--heur', nargs='*')
    return parser.parse_args()


def main():
    args = _parse_args()
    psychic = Psychic(args.source_base, args.rules, args.disable_rules, args.heur)
    psychic.heuristic_search()


if __name__ == '__main__':
    main()
