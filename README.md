# gdb-gperftools-backtrace
Store all threads backtrace in Google Perftools CPU Profile format

## Motivation
Assume you have a process with 2000+ threads and a deadlock somewhere inside. How would you analyze a huge bunch of backtraces like this when you have gdb command prompt and/or your favorite text editor with all backtraces as plain text and no idea what function/source line to look for?
MS Visual Studio has Parallel Stacks window that can visualize all threads as a graph and provides easy navigation and search. Unfortunately, I didn't find similar tool for Linux. However, I worked with [Google Perftools](https://gperftools.github.io/gperftools/cpuprofile.html) before and knew it can 
* draw a call graph for me and export it in different formats, 
* store it in the [Valgrind's Callgrind](https://valgrind.org/docs/manual/cl-manual.html) compatible format to be visualized/analyzed further with [KCachegrind](https://kcachegrind.github.io/html/Home.html),
* filter the call paths or focus on particular function/sources.
So there was a great tool to visualize huge call graph, I only needed to put threads backtraces into the format compatible with it.

## Usage
1. Clone this repo or just download dump-stacks-in-google-perftools-format.p
2. Attach to a running process or open a core dump file with GDB.
3. (gdb) source /path/to/dump-stacks-in-google-perftools-format.py
4. (gdb) gbt /filepath/to/store/profile/into
5. Visualize the call graph with pprof. For example:
    google-pprof --pdf --nodecount=100000 --nodefraction=0 --edgefraction=0 --addresses --ignore '.*(NotVeryInterestingFunction).*' /path/to/profile > callgraph.pdf
    
**NOTE:** one can see all options of the *gbt* command with *--help* flag.

## Known issues
* It turned out that *addr2line* utility which *google-pprof* uses to obtain function name and source line information for instruction addresses may in some cases report incorrect function names (observed on Ubuntu 18.04). Possible workarounds are 
  - supply the option *--include-symbols* when generating profile and use [this version of pprof tool](https://github.com/bezkrovatki/gperftools/blob/master/src/pprof) to visualize;
  - force google-pprof to use eu-addr2line (from elfutils package) utility instead of addr2line
