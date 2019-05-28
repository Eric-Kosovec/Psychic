from chardet.universaldetector import UniversalDetector


def determine_encoding(path):
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
