rule MAC {
    strings:
        $mac = /(\w*)([0-9A-F]{2}[:-]){5}([0-9A-F]{2})/ wide ascii
    condition:
        all of them
}