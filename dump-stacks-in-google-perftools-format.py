from __future__ import print_function

import gdb
import string
import subprocess
import sys
import os
import re
import argparse

class DumpStacksAsGPerfTools (gdb.Command):
    "Command to store backtraces of all threads of the current inferior in Google CPU Profiler binary data file format."
    # https://gperftools.github.io/gperftools/cpuprofile-fileformat.html

    def __init__(self):
        super (DumpStacksAsGPerfTools, self).__init__("gperftools-backtrace",
                gdb.COMMAND_DATA,
                gdb.COMPLETE_NONE, True)
        gdb.execute("alias -a gbt = gperftools-backtrace", True)

    class ProfileDump:
        class SymbolMap (dict):
            def __missing__(self, key):
                return []

        def __init__(self, filename, include_symbols, arch):
            self.fProf = open(filename, 'wb')
            if not self.fProf:
                raise OSError()
            self.slotsize = 8
            if arch.name().find("64") == -1:
                self.slotsize = 4
            self.symbol_map = self.SymbolMap()
            self.threads = []
            self.maps = ''
            self.include_symbols = include_symbols

        def __write(self, value):
            self.fProf.write(value.to_bytes(self.slotsize, byteorder = sys.byteorder, signed = False))

        def __write_str(self, value):
            self.fProf.write(value.encode())

        def __write_binary_header(self):
            self.__write(0)
            self.__write(3)
            self.__write(0)
            sample_period_us = 100000
            self.__write(sample_period_us)
            self.__write(0)

        def __write_binary_profile_record(self, sample_count, backtrace):
            self.__write(sample_count)
            self.__write(len(backtrace))
            for addr in backtrace:
                self.__write(addr)

        def __write_binary_trailer(self):
            self.__write_binary_profile_record(0, [ 0 ])

        def __write_symbol_page_header(self):
            self.__write_str('--- symbol\n')

        def __write_symbol_page_trailer(self):
            self.__write_str('---\n')

        def __write_symbol(self, addr, symbol_names):
            self.__write_str('0x{:x}\t{}\n'.format(addr, '--'.join(symbol_names)))

        def add_mapped_object(self, begin, end, perm, offset, device, inode, pathname):
            self.maps += '{}-{}\t{}\t{}\t{}\t{}\t{}\n'.format(begin, end, perm, offset, device, inode, pathname)

        def add_list_of_mapped_objects(self, vmmap):
            self.maps += vmmap

        def add_frame(self, addr, symbol_name, is_inline):
            self.threads[-1].append(addr)
            if not symbol_name or not self.include_symbols:
                return
            pc = self.symbol_map.get(addr, [])
            #sys.stdout.write('pc: {}\n'.format(pc))
            if not symbol_name in pc:
                if is_inline:
                    pc.append(symbol_name)
                else:
                    new_pc = [ symbol_name ]
                    new_pc.extend( pc )
                    pc = new_pc
                self.symbol_map[addr] = pc

        def add_thread(self, index, lwpid, name):
            self.threads.append([])

        def finalize(self, binary):
            if self.include_symbols:
                self.__write_symbol_page_header()
                self.__write_str('binary={}\n'.format(binary))
                for (k, v) in self.symbol_map.items():
                    self.__write_symbol(k, v)
                self.__write_symbol_page_trailer()
                self.__write_str('--- profile\n')
            self.__write_binary_header()
            for t in self.threads:
                self.__write_binary_profile_record(1, t)
            self.__write_binary_trailer()
            self.__write_str('build={}\n'.format(binary))
            self.__write_str(self.maps)

    class StdoutDump:
        def __init__(self):
            self.frame_no = 0

        def add_mapped_object(self, b, e, perm, offset, device, inode, pathname):
            sys.stdout.write('{}-{}\t{}\t{}\n'.format(b, e, offset, pathname))

        def add_list_of_mapped_objects(self, vmmap):
            sys.stdout.write(vmmap)

        def add_frame(self, addr, symbol_name, is_inline):
            sys.stdout.write('#{}\t0x{:016x}\t{}\n'.format(self.frame_no, addr, symbol_name))
            self.frame_no += 1

        def add_thread(self, index, lwpid, name):
            sys.stdout.write('Thread {} (LWP {}) "{}":\n'.format(index, lwpid, name))
            if 0 != self.frame_no:
                sys.stdout.write('\n')
            self.frame_no = 0

        def finalize(self, binary):
            sys.stdout.write(binary + '\n')

    class MapsAndExeFromInfoFilesCommand:
        def __init__(self):
            self.binary = None

        def __get_text_section_offset(self, binary):
            objdump = subprocess.run(' '.join(['objdump', '-h', '-j', '.text', binary]), stdout=subprocess.PIPE, shell=True)
            for line in objdump.stdout.splitlines():
                words = line.decode().split()
                if len(words) > 1 and '.text' == words[1]:
                    return words[4]
            return '0'

        def fill(self, dump):
            sections = gdb.execute("info files", False, True)
            for line in sections.splitlines():
                if not self.binary:
                    match = re.match('^Symbols from "([^"]+)"', line)
                    if match:
                        self.binary = match.group(1)
                        continue
                match = re.match('\s+0x([0-9A-Fa-f]+)\s+-\s+0x([0-9A-Fa-f]+)\s+is\s+[.]text(\s+in\s+([/].+))?', line)
                if match:
                    b = match.group(1)
                    e = match.group(2)
                    if match.group(3):
                        objfile = match.group(4)
                    else:
                        objfile = self.binary
                    offset = self.__get_text_section_offset(objfile)
                    dump.add_mapped_object(b, e, 'r-xp', offset, 'fd:00', '0', objfile)

        def exe(self):
            return self.binary

    class ExeFromInfoProc:
        def exe(self):
            return gdb.execute("info proc exe", False, True).split()[0]

    class MapsFromInfoProcMappingCommand:
        def fill(self, dump):
            mappings = gdb.execute("info proc mapping", False, True)
            if mappings and False:
                for line in mappings.splitlines()[4:]:
                    b, e, _, offset, objfile = line.split()
                    dump.add_mapped_object(b[2:], e[2:], 'r-xp', offset[2:], 'fd:00', '0', objfile)

    class MapsFromFile:
        def __init__(self, filename):
            self.maps = open(filename, 'r')

        def fill(self, dump):
            for mapping in self.maps:
                dump.add_list_of_mapped_objects(mapping)

    class MapsFromCommand:
        def __init__(self, cmdline):
            self.cmd = subprocess.run(cmdline, stdout=subprocess.PIPE, shell=True)

        def fill(self, dump):
            for line in self.cmd.stdout.splitlines():
                dump.add_list_of_mapped_objects(line.decode())

    class ThreadsToFocusOn:
        class NoThreadsMatch(LookupError):
            def __init__(self, message):
                self.message = message

        def __init__(self, thread_ids, inferior):
            aliases = set(thread_ids)
            focus = []
            for thread in inferior.threads():
                lwpid = thread.ptid[1]
                if not lwpid:
                    lwpid = thread.ptid[2]
                for a in [str(thread.num), str(lwpid), thread.name]:
                    if a in aliases:
                        focus.append(thread)
                        break
            if not focus:
                raise self.NoThreadsMatch('No threads match "{}"'.format(str(aliases)))

            self.focus = focus

        def __iter__(self):
            return iter(self.focus)

    def __write_list_of_mapped_objects(self, dump, core_maps, core_binary, inferior):
        binary = ''
        pid = inferior.pid
        if pid > 1:
            try:
                maps = self.MapsFromFile('/proc/{:d}/maps'.format(pid))
                maps.fill(dump)
                binary = os.readlink('/proc/{:d}/exe'.format(pid))
            except FileNotFoundError:
                pass
        if not binary:
            core_maps.fill(dump)
            binary = core_binary.exe()
        dump.finalize(binary)

    def invoke(self, arg, from_tty):
        parser = argparse.ArgumentParser(fromfile_prefix_chars='@')
        parser.add_argument("--include-symbols", action="store_true", help="include symbol section like one generated by google-pprof in raw profile mode")
        parser.add_argument("--core-maps-from-info-files", action="store_true", help="build objects map from the command 'info files' output. This is the default beaviour")
        parser.add_argument("--core-maps-from-info-proc-mapping", action="store_true", help="build objects map from the command 'info proc mapping' output")
        parser.add_argument("--core-maps-from-file", action="store", help="read objects map from the specified file")
        parser.add_argument("--core-maps-from-command", action="store", help="read objects map from the specified command")
        parser.add_argument("output", action="store", help="output profile file")
        parser.add_argument("threads", nargs=argparse.REMAINDER, help="threads to focus on. All threads will be included by default")
        opts = parser.parse_args(gdb.string_to_argv(arg))

        inferior = gdb.selected_inferior()
        if not inferior:
            return

        selected_thread = gdb.selected_thread()
        selected_frame = gdb.selected_frame()
        if not selected_frame:
            return

        dump = None
        if opts.output:
            dump = self.ProfileDump(opts.output, opts.include_symbols, selected_frame.architecture())
        else:
            dump = self.StdoutDump()

        core_maps = None
        core_binary = self.ExeFromInfoProc()
        if opts.core_maps_from_info_proc_mapping:
            core_maps = self.MapsFromInfoProcMappingCommand()
        if opts.core_maps_from_file:
            core_maps = self.MapsFromFile(opts.core_maps_from_file)
        if opts.core_maps_from_command:
            core_maps = self.MapsFromCommand(opts.core_maps_from_command)
        if not core_maps or opts.core_maps_from_info_files:
            core_maps = self.MapsAndExeFromInfoFilesCommand()
            core_binary = core_maps

        if opts.threads:
            threads = self.ThreadsToFocusOn(opts.threads, inferior)
        else:
            threads = inferior.threads()
        for thread in threads:
            lwpid = thread.ptid[1]
            if not lwpid:
                lwpid = thread.ptid[2]
            dump.add_thread(thread.num, lwpid, thread.name)
            thread.switch()
            frame = gdb.newest_frame()
            while None != frame:
                addr = frame.pc()
                fun = frame.function()
                symbol_name = ''
                if fun:
                    symbol_name = '{} at {}:{}'.format(fun.print_name, fun.symtab.filename, fun.line)
                dump.add_frame(addr, symbol_name, gdb.INLINE_FRAME == frame.type())
                frame = frame.older()

        selected_thread.switch()
        selected_frame.select()

        self.__write_list_of_mapped_objects(dump, core_maps, core_binary, inferior)

DumpStacksAsGPerfTools()
