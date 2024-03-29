#!/usr/bin/env python

"""
CB POV / Poll communication verification tool

Copyright (C) 2014 - Brian Caswell <bmc@lungetech.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

This tool allows for deterministic communication to a CGC Challenge Binary
using a communication spec [0] defined in XML.  Results are logged in the TAP
format [1].

0 - file:///usr/share/cgc-docs/replay.dtd
1 - http://testanything.org/
"""

import argparse
import signal
import re
import struct
import time
import defusedxml.ElementTree as ET


class RegexMatch(object):
    def __init__(self, regex, group=None):
        if group == None:
            group = 0

        self.regex = regex
        self.group = group

    def match(self, data):
        return self.regex.match(data)

class _ValueStr(str):
    """ Wrapper class, used to specify the string is meant to be a 'key' in the
    Throw.values key/value store."""
    pass


class TimeoutException(Exception):
    pass

class TestFailure(Exception):
    pass

class Timeout:
    """ Timeout - A class to use within 'with' for timing out a block via
    exceptions and alarm."""

    def __init__(self, seconds):
        self.seconds = seconds

    def handle_timeout(self, signum, frame):
        raise TimeoutException("timed out")

    def __enter__(self):
        if self.seconds:
            signal.signal(signal.SIGALRM, self.handle_timeout)
            signal.alarm(self.seconds)

    def __exit__(self, exit_type, exit_value, traceback):
        if self.seconds:
            signal.alarm(0)


class Throw(object):
    """Throw - Perform the interactions with a CB

    This class implements the basic methods to interact with a CB, verifying
    the interaction works as expected.

    Usage:
        a = Throw(cb, POV, should_debug)
        a.run()

    Attributes:
        cb: running CB process object

        count: Number of actions performed

        debug: Is debugging enabled

        failed: Number of actions that did not work as expected

        passed: Number of actions that did worked as expected

        pov: POV, as defined by POV()

        values: Variable dictionary
    """
    def __init__(self, cb, pov, debug):
        self.cb = cb
        self.count = 0
        self.failed = 0
        self.passed = 0
        self.pov = pov
        self.debug = debug
        self.values = {}

    def is_ok(self, expected, result, message):
        """ Verifies 'expected' is equal to 'result', logging results in TAP
             format

        Args:
            expected: Expected value
            result:   Action value
            message:  String describing the action being evaluated

        Returns:
            legnth: If the 'expected' result is a string, returns the length of
                the string, otherwise 0

        Raises:
            None
        """

        if isinstance(expected, _ValueStr):
            message += ' (expanded from %s)' % repr(expected)
            if expected not in self.values:
                message += ' value not provided'
                self.log_fail(message)
                return 0
            expected = self.values[expected]

        if isinstance(expected, str):
            if result.startswith(expected):
                self.log_ok(message)
                return len(expected)
        else:
            if result == expected:
                self.log_ok(message)
                return 0

        if self.debug:
            self.log('expected: %s' % repr(expected))
            self.log('result: %s' % repr(result))

        self.log_fail(message)
        return 0

    def is_not(self, expected, result, message):
        """ Verifies 'expected' is not equal to 'result', logging results in
            TAP format

        Args:
            expected: Expected value
            result:   Action value
            message:  String describing the action being evaluated

        Returns:
            legnth: If the 'expected' result is a string, returns the length of
                the string, otherwise 0

        Raises:
            None
        """
        if isinstance(expected, _ValueStr):
            message += ' (expanded from %s)' % repr(expected)
            if expected not in self.values:
                message += ' value not provided'
                self.log_fail(message)
                return 0
            expected = self.values[expected]

        if isinstance(expected, str):
            if not result.startswith(expected):
                self.log_ok(message)
                return len(expected)
        else:
            if result != expected:
                self.log_ok(message)
                return 0

        if self.debug:
            self.log('these are expected to be different:')
            self.log('expected: %s' % repr(expected))
            self.log('result: %s' % repr(result))
        self.log_fail(message)
        return 0

    def log_ok(self, message):
        """ Log a test that passed in the TAP format

        Args:
            message:  String describing the action that 'passed'

        Returns:
            None

        Raises:
            None
        """
        self.passed += 1
        self.count += 1
        if self.debug:
            print "ok %d - %s" % (self.count, message)

    def log_fail(self, message):
        """ Log a test that failed in the TAP format

        Args:
            message:  String describing the action that 'passed'

        Returns:
            None

        Raises:
            None
        """
        self.failed += 1
        self.count += 1
        if self.debug:
            print "not ok %d - %s" % (self.count, message)
        raise TestFailure('failed: %s' % message)

    @staticmethod
    def log(message):
        """ Log diagnostic information in the TAP format

        Args:
            message:  String being logged

        Returns:
            None

        Raises:
            None
        """
        print "# %s" % message

    def sleep(self, value):
        """ Sleep a specified amount

        Args:
            value:  Amount of time to sleep, specified in miliseconds

        Returns:
            None

        Raises:
            None
        """
        time.sleep(value)
        self.log_ok("slept %f" % value)

    def declare(self, values):
        """ Declare variables for use within the current CB communication
            iteration

        Args:
            values:  Dictionary of key/value pair values to be set

        Returns:
            None

        Raises:
            None
        """
        self.values.update(values)
        self.log_ok("set values: %s" % ', '.join(map(repr, values.keys())))

    def _perform_match(self, match, data, invert=False):
        """ Validate the data read from the CB is as expected

        Args:
            match:  Pre-parsed expression to validate the data from the CB
            data:  Data read from the CB

        Returns:
            None

        Raises:
            None
        """
        offset = 0
        for item in match:
            if isinstance(item, str):
                if invert:
                    offset += self.is_not(item, data[offset:],
                                          'match: not string')
                else:
                    offset += self.is_ok(item, data[offset:], 'match: string')
            elif hasattr(item, 'match'):
                match = item.match(data[offset:])
                if match:
                    if invert:
                        if self.debug:
                            self.log('pattern: %s' % repr(item.pattern))
                            self.log('data: %s' % repr(data[offset:]))
                        self.log_fail('match: not pcre')
                    else:
                        self.log_ok('match: pcre')
                    offset += match.end()
                else:
                    if invert:
                        self.log_ok('match: not pcre')
                    else:
                        if self.debug:
                            self.log('pattern: %s' % repr(item.pattern))
                            self.log('data: %s' % repr(data[offset:]))
                        self.log_fail('match: pcre')
            else:
                raise Exception('unknown match type: %s' % repr(item))

    def _perform_expr(self, expr, key, data):
        """ Extract a value from the value read from the CB using 'slice' or
        'pcre'

        Args:
            expr:  Pre-parsed expression to extract the value
            key:   Key to store the value in the instance iteration
            data:  Data read from the CB

        Returns:
            None

        Raises:
            None
        """
        value = None

        # self.log('PERFORMING EXPR (%s): %s' % (key, repr(expr)))
        # self.log('DATA: %s' % repr(data))
        if isinstance(expr, slice):
            value = data[expr]
        elif isinstance(expr, RegexMatch):
            match = expr.match(data)
            if match:
                try:
                    value = match.group(expr.group)
                except IndexError:
                    self.log_fail('match group unavailable')
            else:
                self.log_fail('match failed')

        else:
            self.log_fail('unknown expr type: %s' % repr(expr))

        if value is not None:
            self.values[key] = value
            if self.debug:
                self.log('set %s to %s' % (key, value.encode('hex')))
            self.log_ok('set %s' % (key))

    def read(self, read_args):
        """ Read data from the CB, validating the results

        Args:
            read_args:  Dictionary of arguments

        Returns:
            None

        Raises:
            Exception: if 'expr' argument is provided and 'assign' is not
        """

        data = ''
        try:
            if 'length' in read_args:
                data_array = []
                data_len = 0
                while data_len < read_args['length']:
                    left = read_args['length'] - data_len
                    data_read = self.cb.stdout.read(left)
                    if len(data_read) == 0:
                        self.log_fail('recv failed')
                        break
                    data_array.append(data_read)
                    data_len += len(data_read)
                data = ''.join(data_array)
                self.is_ok(read_args['length'], len(data), 'bytes received')
            elif 'delim' in read_args:
                while not data.endswith(read_args['delim']):
                    val = self.cb.stdout.read(1)
                    if len(val) != 1:
                        self.log_fail("recv failed")
                        break
                    data += val
        except IOError:
            self.log_fail('recv failed')

        if 'echo' in read_args and self.debug:
            assert read_args['echo'] in ['yes', 'no', 'ascii']

            if 'yes' == read_args['echo']:
                self.log('received %s' % data.encode('hex'))
            elif 'ascii' == read_args['echo']:
                self.log('received %s' % repr(data))

        if 'match' in read_args:
            self._perform_match(read_args['match']['values'], data,
                                read_args['match']['invert'])

        if 'expr' in read_args:
            assert 'assign' in read_args
            self._perform_expr(read_args['expr'], read_args['assign'], data)

    def write(self, args):
        """ Write data to the CB

        Args:
            args:  Dictionary of arguments

        Returns:
            None

        Raises:
            None
        """
        data = []
        for value in args['value']:
            if isinstance(value, _ValueStr):
                if value not in self.values:
                    self.log_fail('write failed: %s not available' % value)
                    return
                data.append(self.values[value])
            else:
                data.append(value)
        to_send = ''.join(data)

        if self.debug:
            if args['echo'] == 'yes':
                self.log('writing: %s' % to_send.encode('hex'))
            elif args['echo'] == 'ascii':
                self.log('writing: %s' % repr(to_send))

        try:
            self.cb.stdin.write(to_send)
            self.cb.stdin.flush()
            self.log_ok('write: sent %d bytes' % len(to_send))
        except IOError:
            self.log_fail('write failed')

    def run(self):
        """ Iteratively execute each of the actions within the POV

        Args:
            None

        Returns:
            None

        Raises:
            AssertionError: if a POV action is not in the pre-defined methods
        """

        methods = {
            'sleep': self.sleep,
            'declare': self.declare,
            'read': self.read,
            'write': self.write,
        }

        for method, arguments in self.pov:
            assert method in methods, "%s not in methods" % method
            try:
                methods[method](arguments)
            except TestFailure:
                self.log('stopping due to failure')
                return

    def dump(self):
        """ Log information for the current POV iteraction

        Args:
            None

        Returns:
            None

        Raises:
            None
        """
        if len(self.values) and self.debug:
            self.log("variables at end of interaction: ")
            for key in self.values:
                self.log("%s : %s" % (repr(key), repr(self.values[key])))
        self.log('tests passed: %d' % self.passed)
        self.log('tests failed: %d' % self.failed)


class POV(object):
    """POV - Parse a POV xml file

    This class implements a parser for the CGC POV/Poll format defined in
    replay.dtd.

    Usage:
        p = POV()
        p.parse(filename)
        p.dump()

    Attributes:
        name:  Name of the CB

        filename:  Filename of the CB definition

        _steps:  List of iteractions of a CB

        _variables:  List of variables used during CB interaction
    """
    def __init__(self):
        self.filename = None
        self.name = None
        self._steps = []
        self._variables = []

    def __iter__(self):
        """ Iterate over iteractions in a POV

        Args:
            None

        Returns:
            None

        Raises:
            None
        """
        for step in self._steps:
            yield step

    @staticmethod
    def compile_hex_match(data):
        """ Convert a string of hex values to their ascii value, skipping
        whitespace

        Args:
            data:  Hex string

        Returns:
            None

        Raises:
            None
        """
        for i in [' ', '\n', '\r', '\t']:
            data = data.replace(i, '')
        return data.decode('hex')

    @staticmethod
    def compile_pcre(data):
        """ Compile a PCRE regular express for later use

        Args:
            data:  String to be compiled

        Returns:
            None

        Raises:
            None
        """
        pattern = re.compile(data, re.DOTALL)
        return RegexMatch(pattern)

    @staticmethod
    def compile_slice(data):
        """ Parse a slice XML element, into simplified Python slice format
        (<digits>:<digits>).

        Args:
            data:  XML element defining a slice

        Returns:
            None

        Raises:
            AssertionError: If the tag text is not empty
            AssertionError: If the tag name is not 'slice'
        """
        assert data.tag == 'slice'
        assert data.text is None
        begin = int(POV.get_attribute(data, 'begin', '0'))
        end = POV.get_attribute(data, 'end', None)
        if end is not None:
            end = int(end)
        return slice(begin, end)

    @staticmethod
    def compile_string_match(data):
        """ Parse a string into an 'asciic' format, for easy use.  Allows for
        \\r, \\n, \\t, \\\\, and hex values specified via C Style \\x notation.

        Args:
            data:  String to be parsed into a 'asciic' supported value.

        Returns:
            None

        Raises:
            AssertionError: if either of two characters following '\\x' are not
                hexidecimal values
            Exception: if the escaped value is not one of the supported escaped
                strings (See above)
        """
        # \\, \r, \n, \t \x(HEX)(HEX)
        data = str(data)  # no unicode support
        state = 0
        out = []
        chars = {'n': '\n', 'r': '\r', 't': '\t', '\\': '\\'}
        hex_chars = '0123456789abcdef'
        hex_tmp = ''
        for val in data:
            if state == 0:
                if val != '\\':
                    out.append(val)
                    continue
                state = 1
            elif state == 1:
                if val in chars:
                    out.append(chars[val])
                    state = 0
                    continue
                elif val == 'x':
                    state = 2
                else:
                    raise Exception('invalid asciic string (%s)' % repr(data))
            elif state == 2:
                assert val.lower() in hex_chars
                hex_tmp = val
                state = 3
            else:
                assert val.lower() in hex_chars
                hex_tmp += val
                out.append(hex_tmp.decode('hex'))
                hex_tmp = ''
                state = 0
        return ''.join(out)

    @staticmethod
    def compile_string(data_type, data):
        """ Converts a string from a specified format into the converted into
        an optimized form for later use

        Args:
            data_type:  Which 'compiler' to use
            data:  String to be 'compiled'

        Returns:
            None

        Raises:
            None
        """
        funcs = {
            'pcre': POV.compile_pcre,
            'asciic': POV.compile_string_match,
            'hex': POV.compile_hex_match,
        }
        return funcs[data_type](data)

    @staticmethod
    def get_child(data, name):
        """ Retrieve the specified 'BeautifulSoup' child from the current
        element

        Args:
            data:  Current element that should be searched
            name:  Name of child element to be returned

        Returns:
            child: BeautifulSoup element

        Raises:
            AssertionError: if a child with the specified name is not contained
                in the specified element
        """
        child = data.findChild(name)
        assert child is not None
        return child

    @staticmethod
    def get_attribute(data, name, default=None, allowed=None):
        """ Return the named attribute from the current element.

        Args:
            data:  Element to read the named attribute
            name:  Name of attribute
            default:  Optional default value to be returne if the attribute is
                not provided
            allowed:  Optional list of allowed values

        Returns:
            None

        Raises:
            AssertionError: if the value is not in the specified allowed values
        """
        value = default
        if name in data.attrib:
            value = data.attrib[name]
        if allowed is not None:
            assert value in allowed
        return value

    def add_variable(self, name):
        """ Add a variable the POV interaction

        This allows for insurance of runtime access of initialized variables
        during parse time.

        Args:
            name:  Name of variable

        Returns:
            None

        Raises:
            None
        """
        if name not in self._variables:
            self._variables.append(name)

    def has_variable(self, name):
        """ Verify a variable has been defined

        Args:
            name:  Name of variable

        Returns:
            None

        Raises:
            None
        """
        return name in self._variables

    def add_step(self, step_type, data):
        """ Add a step to the POV iteraction sequence

        Args:
            step_type:  Type of interaction
            data:  Data for the interaction

        Returns:
            None

        Raises:
            AssertionError: if the step_type is not one of the pre-defined
                types
        """
        assert step_type in ['declare', 'sleep', 'read', 'write']
        self._steps.append((step_type, data))

    def parse_delay(self, data):
        """ Parse a 'delay' interaction XML element

        Args:
            data:  XML Element defining the 'delay' iteraction

        Returns:
            None

        Raises:
            AssertionError: if there is not only one child in the 'delay'
                element
        """
        self.add_step('sleep', float(data.text) / 1000)

    def parse_decl(self, data):
        """ Parse a 'decl' interaction XML element

        Args:
            data:  XML Element defining the 'decl' iteraction

        Returns:
            None

        Raises:
            AssertionError: If there is not two children in the 'decl' element
            AssertionError: If the 'var' child element is not defined
            AssertionError: If the 'var' child element does not have only one
                child
            AssertionError: If the 'value' child element is not defined
            AssertionError: If the 'value' child element does not have only one
                child
        """
        assert len(data) == 2
        assert data[0].tag == 'var'
        key = data[0].text

        values = []
        assert data[1].tag == 'value'
        assert len(data[1]) > 0
        for item in data[1]:
            values.append(self.parse_data(item))

        value = ''.join(values)

        self.add_variable(key)
        self.add_step('declare', {key: value})

    def parse_assign(self, data):
        """ Parse an 'assign' XML element

        Args:
            data:  XML Element defining the 'assign' iteraction

        Returns:
            None

        Raises:
            AssertionError: If the 'var' element is not defined
            AssertionError: If the 'var' element does not have only one child
            AssertionError: If the 'pcre' or 'slice' element of the 'assign'
                element is not defined
        """

        assert data.tag == 'assign'
        assert data[0].tag == 'var'
        assign = data[0].text
        self.add_variable(assign)

        if data[1].tag == 'pcre':
            expression = POV.compile_string('pcre', data[1].text)
            group = POV.get_attribute(data[1], 'group', '0')
            expression.group = int(group)

        elif data[1].tag == 'slice':
            expression = POV.compile_slice(data[1])
        else:
            raise Exception("unknown expr tag: %s" % data[1].tag)

        return assign, expression

    def parse_read(self, data):
        """ Parse a 'read' interaction XML element

        Args:
            data:  XML Element defining the 'read' iteraction

        Returns:
            None

        Raises:
            AssertionError: If the 'delim' element is defined, it does not have
                only one child
            AssertionError: If the 'length' element is defined, it does not
                have only one child
            AssertionError: If both 'delim' and 'length' are specified
            AssertionError: If neither 'delim' and 'length' are specified
            AssertionError: If the 'match' element is defined, it does not have
                only one child
            AssertionError: If the 'timeout' element is defined, it does not
                have only one child
        """
        # <!ELEMENT read ((length | delim),match?,assign?,timeout?)>
        # <!ATTLIST read echo (yes|no|ascii) "no">

        # defaults
        read_args = {'timeout': 0}

        # yay, pass by reference.  this allows us to just return when we're out
        # of sub-elements.
        self.add_step('read', read_args)

        read_args['echo'] = POV.get_attribute(data, 'echo', 'no', ['yes', 'no',
                                                                   'ascii'])

        assert len(data) > 0

        children = data.getchildren()

        read_until = children.pop(0)

        if read_until.tag == 'length':
            read_args['length'] = int(read_until.text)
        elif read_until.tag == 'delim':
            read_args['delim'] = self.parse_data(read_until, 'asciic',
                                                 ['asciic', 'hex'])
        else:
            raise Exception('invalid first argument')

        if len(children) == 0:
            return
        current = children.pop(0)

        if current.tag == 'match':
            invert = False
            if POV.get_attribute(current, 'invert', 'false',
                                 ['false', 'true']) == 'true':
                invert = True

            assert len(current) > 0

            values = []
            for item in current:
                if item.tag == 'data':
                    values.append(self.parse_data(item, 'asciic',
                                                  ['asciic', 'hex']))
                elif item.tag == 'pcre':
                    values.append(POV.compile_string('pcre', item.text))
                elif item.tag == 'var':
                    values.append(_ValueStr(item.text))
                else:
                    raise Exception('invalid data.match element name: %s' %
                                    item.name)

            read_args['match'] = {'invert': invert, 'values': values}

            if len(children) == 0:
                return
            current = children.pop(0)

        if current.tag == 'assign':
            assign, expr = self.parse_assign(current)
            read_args['assign'] = assign
            read_args['expr'] = expr
            if len(children) == 0:
                return
            current = children.pop(0)

        assert current.tag == 'timeout', "%s tag, not 'timeout'" % current.tag
        read_args['timeout'] = int(current.text)

    @staticmethod
    def parse_data(data, default=None, formats=None):
        """ Parse a 'data' element'

        Args:
            data: XML Element defining the 'data' item
            formats: Allowed formats

        Returns:
            A 'normalized' string

        Raises:
            AssertionError: If element is not named 'data'
            AssertionError: If the element has more than one child
        """

        if formats is None:
            formats = ['asciic', 'hex']

        if default is None:
            default = 'asciic'

        assert data.tag in ['data', 'delim', 'value']
        assert len(data.text) > 0
        data_format = POV.get_attribute(data, 'format', default, formats)
        return POV.compile_string(data_format, data.text)

    def parse_write(self, data):
        """ Parse a 'write' interaction XML element

        Args:
            data:  XML Element defining the 'write' iteraction

        Returns:
            None

        Raises:
            AssertionError: If any of the child elements do not have the name
                'data'
            AssertionError: If any of the 'data' elements have more than one
                child
        """
        # <!ELEMENT write (data+)>
        # <!ELEMENT data (#PCDATA)>
        # <!ATTLIST data format (asciic|hex) "asciic">

        # self._add_variables(name)

        values = []
        assert len(data) > 0
        for val in data:
            if val.tag == 'data':
                values.append(self.parse_data(val))
            else:
                assert val.tag == 'var'
                assert self.has_variable(val.text)
                values.append(_ValueStr(val.text))

        echo = POV.get_attribute(data, 'echo', 'no', ['yes', 'no', 'ascii'])
        self.add_step('write', {'value': values, 'echo': echo})

    def parse(self, raw_data, filename=None):
        """ Parse the specified replay XML

        Args:
            raw_data:  Raw XML to be parsed

        Returns:
            None

        Raises:
            AssertionError: If the XML file has more than top-level children
                (Expected: pov and doctype)
            AssertionError: If the first child is not a Doctype instance
            AssertionError: If the doctype does not specify the replay.dtd
            AssertionError: If the second child is not named 'pov'
            AssertionError: If the 'pov' element has more than two elements
            AssertionError: If the 'pov' element does not contain a 'cbid'
                element
            AssertionError: If the 'cbid' element value is blank
        """

        self.filename = filename

        tree = ET.fromstring(raw_data)
        assert tree.tag == 'pov'
        assert len(tree) == 2

        assert tree[0].tag == 'cbid'
        assert len(tree[0].tag) > 0
        self.name = tree[0].text

        assert tree[1].tag == 'replay'

        parse_fields = {
            'decl': self.parse_decl,
            'read': self.parse_read,
            'write': self.parse_write,
            'delay': self.parse_delay,
        }

        for replay_element in tree[1]:
            assert replay_element.tag in parse_fields
            parse_fields[replay_element.tag](replay_element)

    def dump(self):
        """ Print the steps in the POV, via repr

        Args:
            None

        Returns:
            None

        Raises:
            None
        """
        for step in self._steps:
            print repr(step)


def throw(cb, pov_filename, timeout, debug):
    """ Parse and Throw the POVs """

    passed = 0
    failed = 0
    errors = 0
    full_passed = 0
    povs = []

    pov_xml = None
    with open(pov_filename, 'rb') as pov_fh:
        pov_xml = pov_fh.read()

    # Limit POV/Poll parsing to 30 seconds each
    try:
        with Timeout(30):
            pov = POV()
            pov.parse(pov_xml, filename=pov_filename)
            povs.append(pov)
    except TimeoutException:
        raise Exception("parsing %s timed out" % pov_filename)

    if debug:
        print '# %s - %s' % (pov.name, pov.filename)
    thrower = Throw(cb, pov, debug)

    if timeout > 0:
        try:
            with Timeout(timeout):
                thrower.run()
        except TimeoutException:
            thrower.log_fail("pov timed out")
    else:
        thrower.run()

    cb.stdin.close()
    cb.stdout.close()

    if debug:
        thrower.dump()
    passed += thrower.passed
    failed += thrower.failed
    if thrower.failed > 0:
        errors += 1
    else:
        full_passed += 1

    return (passed, failed, full_passed, errors)

if __name__ == "__main__":
    print "This program is not intended to be run directly.  Use qemu-cb-test or cb-replay."
    exit(1)
