#!/usr/bin/python3

# Source: https://kasimir123.github.io/writeups/2022-02-DiceCTF/flagle.html

from z3 import *

import string

import sys

# read input into an array

arr = []

for hexval in sys.stdin:
    arr.append(int(hexval, 16))

print(arr)

# variable for each index
s0 = Int("s0")
s1 = Int("s1")
s2 = Int("s2")
s3 = Int("s3")
s4 = Int("s4")
s5 = Int("s5")
s6 = Int("s6")
s7 = Int("s7")
s8 = Int("s8")
s9 = Int("s9")
s10 = Int("s10")
s11 = Int("s11")
s12 = Int("s12")
s13 = Int("s13")
s14 = Int("s14")
s15 = Int("s15") # This can be anything

s = Solver()


# constraints
s.add(s0 + s1 == arr[0])
s.add(s1 + s2 == arr[1])
s.add(s2 + s3 == arr[2])
s.add(s3 + s4 == arr[3])
s.add(s4 + s5 == arr[4])
s.add(s5 + s6 == arr[5])
s.add(s6 + s7 == arr[6])
s.add(s7 + s8 == arr[7])

s.add(s8 == arr[8])
s.add(s9 == arr[9])
s.add(s10 == arr[10])
s.add(s11 == arr[11])
s.add(s12 == arr[12])
s.add(s13 == arr[13])
s.add(s14 == arr[14])

# ascii constrains
s.add(s1 >= ord('0'))
s.add(s2 >= ord('0'))
s.add(s3 >= ord('0'))
s.add(s4 >= ord('0'))
s.add(s5 >= ord('0'))
s.add(s6 >= ord('0'))
s.add(s7 >= ord('0'))
s.add(s8 >= ord('0'))
s.add(s9 >= ord('0'))
s.add(s10 >= ord('0'))
s.add(s11 >= ord('0'))
s.add(s12 >= ord('0'))
s.add(s13 >= ord('0'))
s.add(s14 >= ord('0'))
s.add(s15 >= ord('0'))

# check our contraints
print(s.check())

# get the model
m = s.model()

# Get the solution
solution = ""
v3 = ''
for i in [s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15]:
    print(m[i])
    solution += chr(int(str(m[i])))

print(solution)
