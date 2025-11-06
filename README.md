# Azul Plugin Richid

Parses and features Rich Header Information form Microsoft PE files,
The Rich header is an unofficially documented section in PE files added by
Microsoft Compilers/Linkers.

See the article by _Daniel Pistelli_ for further information:
`https://www.ntcore.com/files/richsign.htm`

## Development Installation

To install azul-plugin-richid for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage

Usage on local files:

```
azul-plugin-richid malware.file
```

Example Output:

```
----- RichId results -----
OK

Output features:
       pe_rich_linker: VS2008 SP1 build 30729
         pe_rich_mask: 0x3093f43d
  pe_rich_entry_count: ASM objects [VS2008 build 21022] - 1
                       C objects [VS2008 SP1 build 30729] - 1
                       Exports [VS2008 SP1 build 30729] - 1
                       Linker [VS2008 SP1 build 30729] - 1
                       Resource objects [VS2008 SP1 build 30729] - 1
                       C objects [VS2008 SP1 build 30729] - 8
                       Imports [VS2008 SP1 build 30729] - 21
                       C++ objects [VS2008 SP1 build 30729] - 46
                       Total imports - 179
       pe_rich_compid: 65536
                       8615945
                       8681481
                       8878089
                       9533449
                       9598985
                       9664521
                       9730057
                       9785886
      pe_rich_product: VS2008 SP1 build 30729
                       VS2008 build 21022
     pe_rich_checksum: 0x3093f43d

Feature key:
  pe_rich_checksum:  Recalculated Rich header checksum
  pe_rich_compid:  Rich header entry compid/type field
  pe_rich_entry_count:  Count of objects for labelled compid/product
  pe_rich_linker:  Final linker used as recorded by the Rich header
  pe_rich_mask:  Rich header XOR mask / checksum used
  pe_rich_product:  Compiler/linker referenced in Rich entry
```

Automated usage in system:

```
azul-plugin-richid --server http://azul-dispatcher.localnet/
```

## Python Package management

This python package is managed using a `setup.py` and `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
