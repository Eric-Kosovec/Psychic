import argparse
import bisect
import io
import itertools
import json
import os
import re
import sys

from collections import defaultdict

import yara
""" Test"""
"""

Testing this
"""
"""
my comment
"""
URL_RULE = """
    rule default_url {
        strings:
            $url = /https?:\/\/([\w\.-]+)([\/\w \.-]*)|www.([\/\w \.-]+)/ wide ascii
        condition:
            $url
    }
"""

IPV4_RULE = """
    rule default_ipv4 {
        strings:
            $ipv4 = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide ascii
        condition:
            $ipv4
    }
"""

BASE64_URL_RULE = """
    rule default_base64_url {
        strings:
            $a1 = "aHR0c" wide ascii // http/s
            $a2 = "SFRUU" wide ascii // HTTP/S
            $a3 = "d3d3L" wide ascii // www.
            $a4 = "V1dXL" wide ascii // WWW.
        condition:
            any of ($a*)
    }
"""

EMAIL_RULE = """
    rule default_email {
        meta:
            author = "@kovacsbalu"
            info = "Better email pattern"
            reference = "https://github.com/securenetworx/PasteHunter/tree/fix-email-filter"
        strings:
            $email = /[\w-]+(\.[\w-]+)*@[\w-]+(\.[\w-]+)*\.[a-zA-Z-]+[\w-]/ wide ascii
        condition:
            $email
    }
"""

MAC_RULE = """
    rule mac {
        strings:
            $mac = /(\w*)([0-9A-F]{2}[:-]){5}([0-9A-F]{2})/ wide ascii
        condition:
            all of them
    }
"""


class Psychic:
    DEFAULT_RULES = {'default_url': URL_RULE, 'default_ipv4': IPV4_RULE, 'default_base64_url': BASE64_URL_RULE,
                     'default_email': EMAIL_RULE, 'default_mac': MAC_RULE}

    _INIT_EXTERNALS = {'file_ext': '', 'file_path': '', 'file_name': ''}
    _LINE_REGEX = re.compile('[\n]|$')

    def __init__(self, source_path, rule_paths=None, disable_rules=None):
        self._source_path = source_path if source_path is not None else '.'
        rule_texts, rule_paths = self._collect_rules(rule_paths, disable_rules)
        self._source_rules = yara.compile(sources=rule_texts, externals=self._INIT_EXTERNALS)
        self._file_rules = yara.compile(filepaths=rule_paths, externals=self._INIT_EXTERNALS)

    def search(self):
        # If a file path was given instead of a directory path, os walk will not work on it.
        if os.path.isfile(self._source_path):
            rule_matches = self.search_file(self._source_path)
            return {self._source_path: rule_matches} if len(rule_matches) > 0 else {}

        file_rule_matches = {}
        for path, _, files in os.walk(self._source_path):
            for file in files:
                full_path = os.path.join(path, file)
                rule_matches = self.search_file(full_path)
                if len(rule_matches) > 0:
                    file_rule_matches[full_path] = rule_matches

        return file_rule_matches

    def search_file(self, path):
        if path is None:
            print('Error: Given search_file path was None', file=sys.stderr)
            return {}

        if not os.path.isfile(path):
            print(f'Error: {path} is not a regular file as expected', file=sys.stderr)
            return {}

        try:
            with io.open(path, encoding='utf-8', newline='') as fp:
                text = fp.read()
        except IOError as e:
            print(f'Error opening source file {path}: {e}', file=sys.stderr)
            return {}
        except UnicodeDecodeError as e:
            print(f'WARNING: File {path}, not a UTF-8 compatible encoding: {e}', file=sys.stderr)
            return {}

        line_offsets = self._line_offsets(text)

        rule_matches = defaultdict(lambda: [])
        for match in self._combine_matches(text, path):
            lines_found = set()
            for offset, str_id, str_data in match.strings:
                line = bisect.bisect_left(line_offsets, offset) + 1
                if line not in lines_found:
                    rule_matches[match.rule].append({'Line': line, 'Identifier': str_id,
                                                     'Data': str_data.decode('utf-8')})
                    lines_found.add(line)

        return rule_matches

    def _combine_matches(self, text, path):
        if text is None or path is None:
            return []
        externals = self._create_externals(path)
        return itertools.chain(self._source_rules.match(data=text, externals=externals),
                               self._file_rules.match(data=text, externals=externals))

    @staticmethod
    def _line_offsets(data):
        if data is None:
            return []
        return [match.start() for match in Psychic._LINE_REGEX.finditer(data)]

    @staticmethod
    def _collect_rules(custom_rule_paths=None, to_disable=None):
        custom_rule_paths = custom_rule_paths if custom_rule_paths is not None else []
        to_disable = [d.lower() for d in to_disable] if to_disable is not None else []

        enabled_rules = {name: rule for name, rule in Psychic.DEFAULT_RULES.items() if name not in to_disable
                         and name[len('default_'):] not in to_disable}
        rule_paths = {os.path.splitext(os.path.basename(path))[0]: path for path in custom_rule_paths}
        return enabled_rules, rule_paths

    @staticmethod
    def _create_externals(path):
        file_ext = file_name = file_path = ''
        if path is not None:
            ext_split = os.path.splitext(os.path.basename(path))
            file_ext = ext_split[-1]
            file_name = ext_split[0] if '.' not in ext_split[0] else ext_split[0][:ext_split[0].find('.')]
            file_path = path
        return {'file_ext': file_ext, 'file_path': file_path, 'file_name': file_name}


def _parse_args():
    parser = argparse.ArgumentParser(description='Determine author(s) and/or author(s) location from source code.')
    parser.add_argument('source_path', help='Path to file or source code base directory')
    parser.add_argument('--rule-path', nargs='*', help='Paths to custom YARA rules')
    parser.add_argument('--disable-rule', nargs='*', help='Default Psychic YARA rules to disable. Can be specified as '
                                                          'default_X or X, where X is the rule name. Defaults are url, '
                                                          'ipv4, base64_url, email, mac.')
    return parser.parse_args()


def main():
    args = _parse_args()
    psychic = Psychic(args.source_path, args.rule_path, args.disable_rule)
    result = psychic.search()
    if result is not None:
        print(json.dumps(result, indent=4))
    else:
        print('Error: Search result was None', file=sys.stderr)


if __name__ == '__main__':
    main()
