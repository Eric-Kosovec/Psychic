from psychic.patterns.pattern import Pattern

EMAIL_PATTERN = r'(?i)([0-9A-F]{2}[:-]){5}([0-9A-F]{2})'


class EmailPattern(Pattern):

    def __init__(self):
        super().__init__(EMAIL_PATTERN, name='Email')
