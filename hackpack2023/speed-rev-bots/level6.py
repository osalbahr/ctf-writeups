#!/usr/bin/python3

from pwn import *
import base64

# Level 1

## Get base64 text

# conn = remote('cha.hackpack.club',41709) # debugging using Humans version

conn = remote('cha.hackpack.club',41702)

for i in range(3):
    line = conn.recvline()

## Get raw bytes
base64text = line[2:-1]
binary = b64d(base64text)

## Get solution
f = open("level1.elf", "wb")
f.write(binary)
os.system("strings level1.elf | grep '^[a-zA-Z0-9]\{16\}$' > level1.txt")

f = open("level1.txt", "r")

str1 = f.read()

print("level1 = " + str1[:-1])
conn.sendline(str1[:-1].encode())

# Level 2
for i in range(3):
    line = conn.recvline()
    # print(line.decode(), end='')

## Get raw bytes
base64text = line[2:-1]
binary = b64d(base64text)

## Get solution
f = open("level2.elf", "wb")
f.write(binary)
os.system("objdump -zd level2.elf --disassemble-symbols=validate --print-imm-hex | grep cmp | grep -o '0x..' | cut -c 3- > hexvals3.txt")

lev2str = ''
with open("hexvals3.txt", "r") as fp:
    for hexval in fp:
            lev2str += chr(int(hexval, 16))
        
line = conn.recvline()
# print(line.decode(), end='')

print("level2 = " + lev2str)
conn.sendline(lev2str.encode())

# Level 3
for i in range(2):
    line = conn.recvline()
    # print(line.decode(), end='')

## Get raw bytes
base64text = line[2:-1]
binary = b64d(base64text)

## Get solution
f = open("level3.elf", "wb")
f.write(binary)
os.system("objdump -zd level3.elf --disassemble-symbols=validate --print-imm-hex | grep cmp | grep -o '0x..' | cut -c 3- > hexvals3.txt")

lev3str = ''
with open("hexvals3.txt", "r") as fp:
    for hexval in fp:
            lev3str += chr(int(hexval, 16))
        

line = conn.recvline()
# print(line.decode(), end='')

print("level3 = " + lev3str)
conn.sendline(lev3str.encode())

# Level 4
for i in range(2):
    line = conn.recvline()
    # print(line.decode(), end='')
    

## Get raw bytes
base64text = line[2:-1]
binary = b64d(base64text)

## Get solution
f = open("level4.elf", "wb")
f.write(binary)
os.system("objdump -zd level4.elf --disassemble-symbols=validate --print-imm-hex | grep cmp | grep -o '0x..' | cut -c 3- > hexvals4.txt") 

os.system("java Solve 4 < hexvals4.txt | tail -1 > level4.txt")    

f = open("level4.txt", "r")
str4 = f.read()

line = conn.recvline()
# print(line.decode(), end='')

print("level4 = " + str4[:-1])
conn.sendline(str4[:-1].encode())

# Level 5
for i in range(7):
    line = conn.recvline()
    # print(line.decode(), end='')


## Get raw bytes
base64text = line[2:-1]
binary = b64d(base64text)

## Get solution
f = open("level5.elf", "wb")
f.write(binary)

os.system("objdump -zd level5.elf --disassemble-symbols=validate --print-imm-hex | grep cmp | grep -o '0x..' | cut -c 3- > hexvals5.txt") 
os.system("objdump -zd level5.elf --disassemble-symbols=validate --print-imm-hex | grep -Eo 'cmp|add' > grep5.txt")   
os.system("./level5-solver hexvals5.txt grep5.txt 2>debug5.txt | tail -1 > level5.txt")

f = open("level5.txt", "r")
str5 = f.read()

line = conn.recvline()
# print(line.decode(), end='')

print("level5 = " + str5[:-1])

# conn.interactive()

conn.sendline(str5[:-1].encode())

# Level 6
for i in range(6):
    line = conn.recvline()


## Get raw bytes
base64text = line[2:-1]
binary = b64d(base64text)

## Get solution
f = open("level6.elf", "wb")
f.write(binary)

os.system("objdump -zd level6.elf --disassemble-symbols=validate --print-imm-hex | grep cmp | grep -o '0x..' | cut -c 3- > hexvals6.txt") 
os.system("objdump -zd level6.elf --disassemble-symbols=validate --print-imm-hex | grep -Eo 'cmp|add' > grep6.txt")   
os.system("./level5-solver hexvals6.txt grep6.txt 2>debug6.txt | tail -1 > level6.txt")

f = open("level6.txt", "r")
str6 = f.read()

conn.recvline()
print("level6 = " + str6[:-1])
conn.sendline(str6[:-1].encode())


for i in range(2):
    print(conn.recvline().decode(), end='')

# conn.interactive()
