from patterns.pattern import Pattern

MAC_ADDR_PATTERN = r'(?i)([0-9A-F]{2}[:-]){5}([0-9A-F]{2})'


class MACPattern(Pattern):

    def __init__(self):
        super().__init__(MAC_ADDR_PATTERN)
