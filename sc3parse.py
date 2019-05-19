""" sc3parse.py
Recover the contents of string tables from SC3 files. Perhaps at some point 
down the road, we'll deal with more aspects of the actual bytecode, if that 
ends up being necessary.

# Example usage
The sc3() container parses up a file. For looking through strings that have
been mapped onto some character set, the usage should probably look something 
like this:

```
    #!/usr/bin/python3
    from sc3parse import *
    from my_charset import my_utf_charset

    my_script = sc3(my_file.sc3, my_uft_charset)

    for string in my_script.strings:
        for token in string:
            # Do something interesting
            # ...
```
"""

from struct import pack, unpack
from enum import Enum

class cmd(Enum):
    """ Command token types """
    LINE_BREAK              = 0x00
    CHARACTER_NAME          = 0x01
    DIALOGUE_START          = 0x02
    PRESENT_03              = 0x03
    SET_COLOR               = 0x04
    UNK_05                  = 0x05
    PRESENT_RESETALIGN      = 0x08
    RUBY_BASE_START         = 0x09
    RUBY_TEXT_START         = 0x0a
    RUBY_TEXT_END           = 0x0b
    SET_FONT_SIZE           = 0x0c
    PRINT_PARALLEL          = 0x0e
    CENTER_TEXT             = 0x0f
    SET_TOP_MARGIN          = 0x11
    SET_LEFT_MARGIN         = 0x12
    GET_HARDCODED_VALUE     = 0x13
    EVAL_EXPRESSION         = 0x15
    PRESENT_18              = 0x18
    AUTO_FORWARD            = 0x19
    AUTO_FORWARD_1A         = 0x1a
    UNK_1E                  = 0x1e
    LINE_BREAK_ALT          = 0x1f


""" 
Table of geometry for commands. 'None' indicates a variable-length command, 
which might require more parsing to determine the actual length.
"""
command_table = { 
    cmd.LINE_BREAK:         { 'type': 0x00, 'len': 1 },
    cmd.CHARACTER_NAME:     { 'type': 0x01, 'len': 1 },
    cmd.DIALOGUE_START:     { 'type': 0x02, 'len': 1 },
    cmd.PRESENT_03:         { 'type': 0x03, 'len': 1 },
    cmd.SET_COLOR:          { 'type': 0x04, 'len': None },
    cmd.UNK_05:             { 'type': 0x05, 'len': 1 },
    cmd.PRESENT_RESETALIGN: { 'type': 0x08, 'len': 1 },
    cmd.RUBY_BASE_START:    { 'type': 0x09, 'len': 1 },
    cmd.RUBY_TEXT_START:    { 'type': 0x0a, 'len': 1 },
    cmd.RUBY_TEXT_END:      { 'type': 0x0b, 'len': 1 },
    cmd.SET_FONT_SIZE:      { 'type': 0x0c, 'len': 3 },
    cmd.PRINT_PARALLEL:     { 'type': 0x0e, 'len': 1 },
    cmd.CENTER_TEXT:        { 'type': 0x0f, 'len': 1 },
    cmd.SET_TOP_MARGIN:     { 'type': 0x11, 'len': 3 },
    cmd.SET_LEFT_MARGIN:    { 'type': 0x12, 'len': 3 },
    cmd.GET_HARDCODED_VALUE:    { 'type': 0x13, 'len': 3 },
    cmd.EVAL_EXPRESSION:    { 'type': 0x15, 'len': None },
    cmd.PRESENT_18:         { 'type': 0x18, 'len': 1 },
    cmd.AUTO_FORWARD:       { 'type': 0x19, 'len': 1 },
    cmd.AUTO_FORWARD_1A:    { 'type': 0x1a, 'len': 1 },
    cmd.UNK_1E:             { 'type': 0x1e, 'len': 1 },
    cmd.LINE_BREAK_ALT:     { 'type': 0x1f, 'len': 1 },
}



class sc3(object):
    """ An object representing a particular SC3 file.
    We are really only interested in parsing the string table atm. Strings are
    composed of "tokens," which may be *characters* or *commands*. Character 
    tokens are offsets into some game-specific character set which may not
    correspond [in any consistent, rigorous way] with encodings like UTF.

    The constructor takes two arguments:
        - 'filename', the name of some target SC3 file
        - 'charset', an array of characters used to map character tokens
          onto actual UTF characters. 
    """

    def __init__(self, filename, charset):

        self.charset = charset

        # Read the contents of the user-provided file
        with open(filename, "rb") as f:
            self.data = f.read()

        # Verify this is actually an SC3 file
        if (self.data[0x00:0x04] != b'SC3\x00'):
            print("[!] {} is not an SC3 file".format(filename))
            exit(-1)

        # Obtain offsets to various tables
        self.s_table = unpack("<L", self.data[0x04:0x08])[0]
        self.r_table = unpack("<L", self.data[0x08:0x0c])[0]
        self.l_table = unpack("<L", self.data[0x0c:0x10])[0]

        # Proceed to parse all the entries in the string table
        self.s_table_entries = (self.r_table - self.s_table) // 4
        self.parse_strings()

    def _parse_expression(self, expr_base):
        """ Parse an expression starting at self.data[expr_base]. We don't
        care about discriminating particular operators or immediate values
        right now, so just return the size of the expression.
        """
        cur = expr_base
        while True:

            # The first 8-bit signed number is the "type" of expression token
            expr_type = unpack("<b", bytes(self.data[cur:cur+1]))[0]

            # Expressions terminate when the type of a token is 0x00
            if (expr_type == 0x00):
                cur += 1
                break

            # Some expression tokens are {1,2,3,4}-byte immediate values
            elif (expr_type < 0):
                imm_type = expr_type & 0x60
                if (imm_type == 0x00):
                    cur += 1
                if (imm_type == 0x20):
                    cur += 2
                if (imm_type == 0x40):
                    cur += 3
                if (imm_type == 0x60):
                    cur += 1
                    cur += 4

            # Some expression tokens are operators (assumed to be one byte?)
            elif (expr_type > 0):
                cur += 1

            # All expression tokens end with a "precedence" byte
            precedence = self.data[cur]
            cur += 1

        return cur - expr_base


    def parse_strings(self):
        """ Populate self.strings with an array of string representations.
        Strings are composed of dictionary objects of the form:

                {
                    'type': <EOL | CHR | CMD>, 
                    'data': <some relevant string> 
                }
        """
        # Start at the base of the string table
        string_cur = self.s_table
        num_entries = self.s_table_entries

        self.strings = []
        for i in range(0, num_entries):

            # Obtain an offset to some string in the file
            string_base = unpack("<L", self.data[string_cur:string_cur+4])[0]
            cur = string_base
            string = []

            while True:
                token_type = self.data[cur]
                token = {}

                # A string always terminates on 0xFF
                if (token_type == 0xff):
                    token['type'] = 'EOL'
                    token['data'] = None
                    string.append(token)
                    cur += 1
                    break

                # Handle character tokens
                if (token_type >= 0x80):
                    char = unpack(">H", self.data[cur:cur+2])[0]
                    char_idx = char - 0x8000

                    token['type'] = 'CHR'
                    if (char_idx < len(self.charset)):
                        token['data'] = self.charset[char_idx]
                    else:
                        token['data'] = '?'
                    string.append(token)
                    cur += 2

                # Handle command tokens
                if (token_type < 0x80):
                    command = cmd(token_type)
                    token['type'] = 'CMD'
                    token['data'] = command

                    # Parse expressions for variable-length commands
                    if (command_table[command]['len'] == None):
                        cur += 1
                        expr_len = self._parse_expression(cur)
                        cur += expr_len

                    # Otherwise, just look up command size in the table
                    else:
                        cur += command_table[command]['len']

                    # Append this token to our representation of the string
                    string.append(token)

            self.strings.append(string)
            string_cur += 4

