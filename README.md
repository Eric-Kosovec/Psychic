# Psychic
Work in progress Python-based extensible forensic tool to determine an author's identity from a given codebase. Ideal for finding starting points for manual investigation within a large source project.<br/>
<br/>
Parses source files for certain patterns, such as IP addresses, file paths, and URLs.<br/>


Plugins:<br/>
Create any amount of classes within the 'plugins' package extending the Plugin base class.<br/>
Override the directories, filenames, and/or file_extensions methods to return a list of strings describing the appropriate file to pass into the parse_directory, parse_filename, and parse_extension methods. The file path is passed into these methods, so they may be parsed as needed.

For example, returning file_extensions as ['.h', '.c', '.txt'], will pass all file paths with those extensions into the parse_extension method.
<br/>

To run:<br/>
From the command line, python psy.py [codebase directory]