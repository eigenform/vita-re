#!/usr/bin/python3
""" wa2txt.py
"""

def decode_string(data):
    """ Given a bytearray, return the sjis-encoded string """
    return data.decode("shift_jis_2004")

def encode_string(string):
    """ Given a sjis-encoded string, convert it back into a bytearray """
    return string.encode("shift_jis_2004")

def parse_file(data):
    """ Given the bytearray from a file, return a list of bytearray() objects 
    representing individual strings in the file. It appears that \x2c is used
    to delinate individual cases where strings are rendered (note that this is 
    independent of any actual newline characters embedded in a string).
    """
    strings = []

    cur = 0
    string_base = 0
    while True:

        # Stop parsing data when we reach EOF
        if ((cur >= len(data)) or (string_base >= len(data))):
            break

        while True:
            # Stop if we reach EOF unexpectedly
            if (cur >= len(data)):
                break

            # Terminate a string when we find a \x2c byte
            if (data[cur:cur+1] == b'\x2c'):
                cur += 1
                break
            cur += 1

        # Strings seem to be SHIFT-JIS encoded
        #string_decoded = data[string_base:cur].decode("shift_jis_2004")

        # Add string to the list, then go to the next string
        strings.append(data[string_base:cur])
        string_base = cur
    return strings

def build_file(strings):
    """ Given an array of bytearrays representing strings, concatenate them
    back into a whole file """
    data = bytearray()
    for string in strings:
        data += string
    return data


