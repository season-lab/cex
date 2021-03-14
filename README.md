# CFG EXtractor - CEX

### Installation

Create a virtualenv and install the requirements. Using [virtualenvwrapper](https://virtualenvwrapper.readthedocs.io/en/latest/):

```
$ mkvirtualenv cex
$ workon cex
$ pip install -r ./requirements.txt
```

Some plugins need specific requirements:

#### Rizin plugin

Clone and install [Rizin](https://github.com/rizinorg/rizin):

``` bash
$ git clone https://github.com/rizinorg/rizin
$ cd rizin
$ meson build
$ ninja -C build
$ sudo ninja -C build install
```

#### Ghidra plugin

Download [Ghidra](https://ghidra-sre.org/) and set GHIDRA_HOME env var:

``` bash
$ wget https://ghidra-sre.org/ghidra_9.2.2_PUBLIC_20201229.zip -P /tmp
$ unzip /tmp/ghidra_9.2.2_PUBLIC_20201229.zip -d ~/bin
$ export GHIDRA_HOME=~/bin/ghidra_9.2.2_PUBLIC
```

### Command Line Usage

Command line util in `bin/cex`:

```
usage: cex [-h] [--list-plugins] [--use-plugins [PLUGIN ...]] [--output DIRECTORY] [--dump-dot-cg [ADDR ...]] [--dump-json-cg [ADDR ...]] [--dump-dot-cfg [ADDR ...]]
           [--dump-json-cfg [ADDR ...]] [--find-path [ADDR1,ADDR2]] [--dump-dot-path]
           binary

CFG EXtractor

positional arguments:
  binary                The binary to analyze

optional arguments:
  -h, --help            show this help message and exit
  --list-plugins        Print the installed plugins
  --use-plugins [PLUGIN ...]
                        List of plugins to use. If omitted, use AngrFast.
  --output DIRECTORY    Output directory. If omitted, stdout
  --dump-dot-cg [ADDR ...]
                        Dump the callgraph in dot from ADDR entrypoint. If '-', program entrypoint.
  --dump-json-cg [ADDR ...]
                        Dump the callgraph in json from ADDR entrypoint. If '-', program entrypoint.
  --dump-dot-cfg [ADDR ...]
                        Dump the control flow graph of the function in dot at address ADDR
  --dump-json-cfg [ADDR ...]
                        Dump the control flow graph of the function in json at address ADDR
  --find-path [ADDR1,ADDR2]
                        Find a path between the two functions at ADDR1 and ADDR2
  --dump-dot-path       Dump the path found by --find-path in dot format
```
