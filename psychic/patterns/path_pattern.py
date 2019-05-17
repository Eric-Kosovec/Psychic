import re

from patterns.pattern import Pattern

PATH_PATTERN = r"""
            (([A-Za-z]:)?(\\\w+\w+)+) |
            (([A-Za-z]:)?(/\w+\w+)+)
"""


class PathPattern(Pattern):

    def __init__(self):
        super().__init__(PATH_PATTERN, re.VERBOSE)
