# Psychic
Python-based forensic tool to determine an author's identity from a given codebase using YARA rules. Ideal for finding 
quality starting points for manual investigation within a large source project.

## Overview
Parses source files for certain patterns, such as IP addresses, emails, Base64 encoded emails, and URLs, by default, 
but can be given custom YARA rules. 

Doesn't do country detection, as a researcher can determine this manually. 
Occasionally, a programmer will forget to remove self-identifying information, such as a name or company in a file path 
while testing. This may be best found through a custom YARA rule to extract strings and comments within the respective language.

## Requirements
yara Python library: `pip install yara-python`

## Running
```
$ python psychic.py -h
usage: psychic.py [-h] [--rule-path [RULE_PATH [RULE_PATH ...]]]
                  [--disable-rule [DISABLE_RULE [DISABLE_RULE ...]]]
                  source_path

Determine author(s) and/or author(s) location from source code.

positional arguments:
  source_path           Path to file or source code base directory

optional arguments:
  -h, --help            show this help message and exit
  --rule-path [RULE_PATH [RULE_PATH ...]]
                        Paths to custom YARA rules
  --disable-rule [DISABLE_RULE [DISABLE_RULE ...]]
                        Default Psychic YARA rules to disable. Can be
                        specified as default_X or X, where X is the rule name.
                        Defaults are url, ip, base64_url, email, mac.
```

Alternatively, Psychic can be used programmatically by importing the Psychic class ```from psychic import Psychic```

Class definition: 
```
Psychic(source_path, rule_paths=None, disable_rules=None)
```
Where rule_paths is a list of rule file paths and disable rules is a list of default YARA rules included in Psychic to disable.

### Default Rules
Psychic comes with 5 default rules, as follows:
- base64_url - Finds the starting Base64 encoded http, https, or www
- email
- ipv4
- mac
- url - Finds URLs starting with http, https, or www

### Output
Output from the command line tool is a JSON string of the form: 
```
{
    "file_path1": {
        "rule1": [
            {
                "Line": XX
                "Identifier": "$xxx", 
                "Data": "xxxxxxxxxxx"
            }
        ]
    }
}
```

Output from the Psychic class functions are of the same form, but as Python objects.

### Custom YARA Rules
Psychic will define the following variables within all given custom rules:
- file_ext - The extension of the file being scanned, including the '.'
- file_path - Path to the file
- file_name - Name of the file, without extension

#### Example
The following rule extracts single and multi-line C comments:
```
rule c_comments {
    meta:
        description = "Pulls comments and 3+ character strings from C source files."
    strings:
        $block_comment = /\/\*((.|[\r\n])*?)\*\// wide ascii
        $line_comment = /\/\/(.+?)([\n]|$)/s wide ascii
        $string = /["](.+){3,}["]/ wide ascii
    condition:
        (file_ext == ".c" or file_ext == ".h") and any of them
}
```

## Future Features
- Heuristic searching - Collect pieces of files corresponding to custom YARA rules, such as strings and comments, 
then search only those pieces for the default and given YARA rules.