rule CPatterns {
    meta:
        description = "Pulls comments and 3+ character strings from C source files."

    strings:
        $block_comment = /\/\*((.|[\r\n])*?)\*\// wide ascii
        $line_comment = /\/\/(.+?)([\n]|$)/s wide ascii
        $string = /["](.+){3,}["]/ wide ascii


    condition:
        (file_ext == ".c" or file_ext == ".h") and any of them
}
