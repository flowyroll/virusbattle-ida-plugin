# virusbattle-ida-plugin
The plugin is an integration of Virus Battle API to the well known IDA Disassembler.

Virusbattle is a web service that analyses malware and other binaries with a variety of advanced static and dynamic analyses. For more information check out the [Lab Website](http://ulsrl.org/project/VirusBattle).

### Dependecies:
*	IDAPython
*	pySide
*	GraphViz (Optional)

### Usage: 
*	Install GraphViz and add it to the default environment path (for generting and opening API flow and call graphs)
*	Prepare an IDA with pySide support
*	`IDA -> File -> Script file... -> [choose VirusBattle_IDA_Plugin.py]`
*	As a shortcut too see matched procedures for current function: `IDA -> View -> [VB] Matched Procs` or simply `Alt+Shift+V`

