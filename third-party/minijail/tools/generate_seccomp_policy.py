#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script will take any number of trace files generated by strace(1)
# and output a system call filtering policy suitable for use with Minijail.

"""Tool to generate a minijail seccomp filter from strace or audit output."""

from __future__ import print_function

import argparse
import collections
import os
import re
import sys

# auparse may not be installed and is currently optional.
try:
    import auparse
except ImportError:
    auparse = None


NOTICE = """# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""

ALLOW = '1'

# This ignores any leading PID tag and trailing <unfinished ...>, and extracts
# the syscall name and the argument list.
LINE_RE = re.compile(r'^\s*(?:\[[^]]*\]|\d+)?\s*([a-zA-Z0-9_]+)\(([^)<]*)')

SOCKETCALLS = {
    'accept', 'bind', 'connect', 'getpeername', 'getsockname', 'getsockopt',
    'listen', 'recv', 'recvfrom', 'recvmsg', 'send', 'sendmsg', 'sendto',
    'setsockopt', 'shutdown', 'socket', 'socketpair',
}

# List of private ARM syscalls. These can be found in any ARM specific unistd.h
# such as Linux's arch/arm/include/uapi/asm/unistd.h.
PRIVATE_ARM_SYSCALLS = {
    983041: 'ARM_breakpoint',
    983042: 'ARM_cacheflush',
    983043: 'ARM_usr26',
    983044: 'ARM_usr32',
    983045: 'ARM_set_tls',
}

ArgInspectionEntry = collections.namedtuple('ArgInspectionEntry',
                                            ('arg_index', 'value_set'))


# pylint: disable=too-few-public-methods
class BucketInputFiles(argparse.Action):
    """Buckets input files using simple content based heuristics.

    Attributes:
      audit_logs: Mutually exclusive list of audit log filenames.
      traces: Mutually exclusive list of strace log filenames.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        audit_logs = []
        traces = []

        strace_line_re = re.compile(r'[a-z]+[0-9]*\(.+\) += ')
        audit_line_re = re.compile(r'type=(SYSCALL|SECCOMP)')

        for filename in values:
            if not os.path.exists(filename):
                parser.error(f'Input file {filename} not found.')
            with open(filename, mode='r', encoding='utf8') as input_file:
                for line in input_file.readlines():
                    if strace_line_re.search(line):
                        traces.append(filename)
                        break
                    if audit_line_re.search(line):
                        audit_logs.append(filename)
                        break
                else:
                    # Treat it as an strace log to retain legacy behavior and
                    # also just in case the strace regex is imperfect.
                    traces.append(filename)

        setattr(namespace, 'audit_logs', audit_logs)
        setattr(namespace, 'traces', traces)
# pylint: enable=too-few-public-methods


def parse_args(argv):
    """Returns the parsed CLI arguments for this tool."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verbose', action='store_true',
                        help='output informational messages to stderr')
    parser.add_argument('--frequency', type=argparse.FileType('w'),
                        help='frequency file')
    parser.add_argument('--policy', type=argparse.FileType('w'),
                        default=sys.stdout, help='policy file')
    parser.add_argument('input-logs', action=BucketInputFiles,
                        help='strace and/or audit logs', nargs='+')
    parser.add_argument('--audit-comm', type=str, metavar='PROCESS_NAME',
                        help='relevant process name from the audit.log files')
    opts = parser.parse_args(argv)

    if opts.audit_logs and not auparse:
        parser.error('Python bindings for the audit subsystem were not found.\n'
                     'Please install the python3-audit (sometimes python-audit)'
                     ' package for your distro to process audit logs: '
                     f'{opts.audit_logs}')

    if opts.audit_logs and not opts.audit_comm:
        parser.error(f'--audit-comm is required when using audit logs as input:'
                     f' {opts.audit_logs}')

    if not opts.audit_logs and opts.audit_comm:
        parser.error('--audit-comm was specified yet none of the input files '
                     'matched our hueristic for an audit log')

    return opts


def get_seccomp_bpf_filter(syscall, entry):
    """Returns a minijail seccomp-bpf filter expression for the syscall."""
    arg_index = entry.arg_index
    arg_values = entry.value_set
    atoms = []
    if syscall in ('mmap', 'mmap2', 'mprotect') and arg_index == 2:
        # See if there is at least one instance of any of these syscalls trying
        # to map memory with both PROT_EXEC and PROT_WRITE. If there isn't, we
        # can craft a concise expression to forbid this.
        write_and_exec = set(('PROT_EXEC', 'PROT_WRITE'))
        for arg_value in arg_values:
            if write_and_exec.issubset(set(p.strip() for p in
                                           arg_value.split('|'))):
                break
        else:
            atoms.extend(['arg2 in ~PROT_EXEC', 'arg2 in ~PROT_WRITE'])
            arg_values = set()
    atoms.extend(f'arg{arg_index} == {arg_value}' for arg_value in arg_values)
    return ' || '.join(atoms)


def parse_trace_file(trace_filename, syscalls, arg_inspection):
    """Parses one file produced by strace."""
    uses_socketcall = ('i386' in trace_filename or
                       ('x86' in trace_filename and
                        '64' not in trace_filename))

    with open(trace_filename, encoding='utf8') as trace_file:
        for line in trace_file:
            matches = LINE_RE.match(line)
            if not matches:
                continue

            syscall, args = matches.groups()
            if uses_socketcall and syscall in SOCKETCALLS:
                syscall = 'socketcall'

            # strace omits the 'ARM_' prefix on all private ARM syscalls. Add
            # it manually here as a workaround. These syscalls are exclusive
            # to ARM so we don't need to predicate this on a trace_filename
            # based heuristic for the arch.
            if f'ARM_{syscall}' in PRIVATE_ARM_SYSCALLS.values():
                syscall = f'ARM_{syscall}'

            syscalls[syscall] += 1

            args = [arg.strip() for arg in args.split(',')]

            if syscall in arg_inspection:
                arg_value = args[arg_inspection[syscall].arg_index]
                arg_inspection[syscall].value_set.add(arg_value)


def parse_audit_log(audit_log, audit_comm, syscalls, arg_inspection):
    """Parses one audit.log file generated by the Linux audit subsystem."""

    unknown_syscall_re = re.compile(r'unknown-syscall\((?P<syscall_num>\d+)\)')

    au = auparse.AuParser(auparse.AUSOURCE_FILE, audit_log)
    # Quick validity check for whether this parses as a valid audit log. The
    # first event should have at least one record.
    if not au.first_record():
        raise ValueError(f'Unable to parse audit log file {audit_log.name}')

    # Iterate through events where _any_ contained record matches
    # ((type == SECCOMP || type == SYSCALL) && comm == audit_comm).
    au.search_add_item('type', '=', 'SECCOMP', auparse.AUSEARCH_RULE_CLEAR)
    au.search_add_item('type', '=', 'SYSCALL', auparse.AUSEARCH_RULE_OR)
    au.search_add_item('comm', '=', f'"{audit_comm}"',
                       auparse.AUSEARCH_RULE_AND)

    # auparse_find_field(3) will ignore preceding fields in the record and
    # at the same time happily cross record boundaries when looking for the
    # field. This helper method always seeks the cursor back to the first
    # field in the record and stops searching before crossing over to the
    # next record; making the search far less error prone.
    # Also implicitly seeks the internal 'cursor' to the matching field
    # for any subsequent calls like auparse_interpret_field.
    def _find_field_in_current_record(name):
        au.first_field()
        while True:
            if au.get_field_name() == name:
                return au.get_field_str()
            if not au.next_field():
                return None

    while au.search_next_event():
        # The event may have multiple records. Loop through all.
        au.first_record()
        for _ in range(au.get_num_records()):
            event_type = _find_field_in_current_record('type')
            comm = _find_field_in_current_record('comm')
            # Some of the records in this event may not be relevant
            # despite the event-specific search filter. Skip those.
            if (event_type not in ('SECCOMP', 'SYSCALL') or
                    comm != f'"{audit_comm}"'):
                au.next_record()
                continue

            if not _find_field_in_current_record('syscall'):
                raise ValueError(f'Could not find field "syscall" in event of '
                                 f'type {event_type}')
            # Intepret the syscall field that's under our 'cursor' following the
            # find. Interpreting fields yields human friendly names instead
            # of integers. E.g '16' -> 'ioctl'.
            syscall = au.interpret_field()

            # TODO(crbug/1172449): Add these syscalls to upstream
            # audit-userspace and remove this workaround.
            # This is redundant but safe for non-ARM architectures due to the
            # disjoint set of private syscall numbers.
            match = unknown_syscall_re.match(syscall)
            if match:
                syscall_num = int(match.group('syscall_num'))
                syscall = PRIVATE_ARM_SYSCALLS.get(syscall_num, syscall)

            if ((syscall in arg_inspection and event_type == 'SECCOMP') or
                (syscall not in arg_inspection and event_type == 'SYSCALL')):
                # Skip SECCOMP records for syscalls that require argument
                # inspection. Similarly, skip SYSCALL records for syscalls
                # that do not require argument inspection. Technically such
                # records wouldn't exist per our setup instructions but audit
                # sometimes lets a few records slip through.
                au.next_record()
                continue
            elif event_type == 'SYSCALL':
                arg_field_name = f'a{arg_inspection[syscall].arg_index}'
                if not _find_field_in_current_record(arg_field_name):
                    raise ValueError(f'Could not find field "{arg_field_name}"'
                                     f'in event of type {event_type}')
                # Intepret the arg field that's under our 'cursor' following the
                # find. This may yield a more human friendly name.
                # E.g '5401' -> 'TCGETS'.
                arg_inspection[syscall].value_set.add(au.interpret_field())

            syscalls[syscall] += 1
            au.next_record()


def main(argv=None):
    """Main entrypoint."""

    if argv is None:
        argv = sys.argv[1:]

    opts = parse_args(argv)

    syscalls = collections.defaultdict(int)

    arg_inspection = {
        'socket': ArgInspectionEntry(0, set([])),   # int domain
        'ioctl': ArgInspectionEntry(1, set([])),    # int request
        'prctl': ArgInspectionEntry(0, set([])),    # int option
        'mmap': ArgInspectionEntry(2, set([])),     # int prot
        'mmap2': ArgInspectionEntry(2, set([])),    # int prot
        'mprotect': ArgInspectionEntry(2, set([])), # int prot
    }

    if opts.verbose:
        # Print an informational message to stderr in case the filetype detection
        # heuristics are wonky.
        print('Generating a seccomp policy using these input files:',
              file=sys.stderr)
        print(f'Strace logs: {opts.traces}', file=sys.stderr)
        print(f'Audit logs: {opts.audit_logs}', file=sys.stderr)

    for trace_filename in opts.traces:
        parse_trace_file(trace_filename, syscalls, arg_inspection)

    for audit_log in opts.audit_logs:
        parse_audit_log(audit_log, opts.audit_comm, syscalls, arg_inspection)

    # Add the basic set if they are not yet present.
    basic_set = [
        'restart_syscall', 'exit', 'exit_group', 'rt_sigreturn',
    ]
    for basic_syscall in basic_set:
        if basic_syscall not in syscalls:
            syscalls[basic_syscall] = 1

    # If a frequency file isn't used then sort the syscalls based on frequency
    # to make the common case fast (by checking frequent calls earlier).
    # Otherwise, sort alphabetically to make it easier for humans to see which
    # calls are in use (and if necessary manually add a new syscall to the
    # list).
    if opts.frequency is None:
        sorted_syscalls = list(
            x[0] for x in sorted(syscalls.items(), key=lambda pair: pair[1],
                                 reverse=True)
        )
    else:
        sorted_syscalls = list(
            x[0] for x in sorted(syscalls.items(), key=lambda pair: pair[0])
        )

    print(NOTICE, file=opts.policy)
    if opts.frequency is not None:
        print(NOTICE, file=opts.frequency)

    for syscall in sorted_syscalls:
        if syscall in arg_inspection:
            arg_filter = get_seccomp_bpf_filter(syscall,
                                                arg_inspection[syscall])
        else:
            arg_filter = ALLOW
        print(f'{syscall}: {arg_filter}', file=opts.policy)
        if opts.frequency is not None:
            print(f'{syscall}: {syscalls[syscall]}', file=opts.frequency)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
