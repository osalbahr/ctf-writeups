# Challenge Name: Speed-Rev: Bots
***

## Authors

Author: [osalbahr](https://ctftime.org/user/158966)

Co-Authors: The solution and writeup was a collaboration with [ccrollin](https://ctftime.org/user/84127) and [mmtawous](https://ctftime.org/user/159303).

***

## Challenge

The description (as can be found in CTFtime through [Speed-Rev: Bots](https://ctftime.org/task/25005)):
> Welcome to the Speed-Rev battle for your bots! Connect to the socket! Recive binaries! AND GET! THE! FLAGS!
>
> (There are 6 levels total, you have 3 minutes to complete them all)

There was also a hint about the flags consisting of lowercase letters and numbers.

No files were provided, only a `nc` command. This is typical of CTF challenges that are based on connecting to a server.

## Level 1 - Exploration

```
$ nc cha.hackpack.club 41702
Welcome to the speedrun challenge! You have 3 minutes to solve 6 levels!
Level 1, here is the binary!
b'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAcBAAAAAAAABAAAAAAAAAACA6AAAAAAAAAAAAAEAAOAALAEAAHgAdAAYAAAAEAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAaAIAAAAAAABoAgAAAAAAAAgAAAAAAAAAAwAAAAQAAACoAgAAAAAAAKgCAAAAAAAAqAIAAAAAAAAcAAAAAAAAABwAAAAAAAAAAQAAAAAAAAABAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAGAAAAAAAAMAYAAAAAAAAAEAAAAAAAAAEAAAAFAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAXQIAAAAAAABdAgAAAAAAAAAQAAAAAAAAAQAAAAQAAAAAIAAAAAAAAAAgAAAAAAAAACAAAAAAAACIAQAAAAAAAIgBAAAAAAAAABAAAAAAAAABAAAABgAAAOgtAAAAAAAA6D0AAAAAAADoPQAAAAAAAFgCAAAAAAAAaAIAAAAAAAAAEAAAAAAAAAIAAAAGAAAA
...output... - see https://github.com/osalbahr/ctf-writeups/tree/main/hackpack2023/speed-rev-bots 
What is the flag?
123456781234567
Wrong length!
```

In the beginning, I thought this was a side channel attack. I tried guessing the length, and successfully found it as follows:

```
$ nc cha.hackpack.club 41702
Welcome to the speedrun challenge! You have 3 minutes to solve 6 levels!
Level 1, here is the binary!
What is the flag?
b'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAcBAAAAAAAABAAAAAAAAAACA6AAAAAAAAAAAAAEAAOAALAEAAHgAdAAYAAAAEAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAaAIAAAAAAABoAgAAAAAAAAgAAAAAAAAAAwAAAAQAAACoAgAAAAAAAKgCAAAAAAAAqAIAAAAAAAAcAAAAAAAAABwAAAAAAAAAAQAAAAAAAAABAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAGAAAAAAAAMAYAAAAAAAAAEAAAAAAAAAEAAAAFAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAXQIAAAAAAABdAgAAAAAAAAAQAAAAAAAAAQAAAAQAAAAAIAAAAAAAAAAgAAAAAAAAACAAAAAAAACIAQAAAAAAAIgBAAAAAAAAABAAAAAAAAABAAAABgAAAOgtAAAAAAAA6D0AAAAAAADoPQAAAAAAAFgCAAAAAAAAaAIAAAAAAAAAEAAAAAAAAAIAAAAGAAAA
...output... - see https://github.com/osalbahr/ctf-writeups/tree/main/hackpack2023/speed-rev-bots
1234567812345678
Wrong!
```

So, now we know that the length is 16 bytes. Then I was stuck.

Caleb noticed the on-screen prompt of `Level 1, here is the binary!`, so he tried to place the large amount of text sent after this message into [Cyberchef](https://gchq.github.io/CyberChef/). Cyberchef is an online interative tool that can analyze and manipulate data. One feature of Cyberchef is called `Magic`, where various heuristics are applied to the data to form an output that is most intended. Cyberchef was able to correctly identify this data as being encoded in base64. Base64 is a clever method to represent binary data in such a way that only printable ASCII characters need to be used. When Cyberchef decoded the characters from base64 the following information was displayed. 

```
ELF          >    p      @        :          @ 8 
 @         @       @       @       h      h                   ¨      ¨      ¨                                                         0      0                                        ]      ]                                           ˆ      ˆ                   è-      è=      è=      X      h                   ø-      ø=      ø=      à      à                   Ä      Ä      Ä      D       D              Påtd                        D       D              Qåtd                                                  Råtd   è-      è=      è=                         /lib64/ld-linux-x86-64.so.2          GNU                        GNU Nm6QyìËÞ‚0×)C³Y              ¡ €      	   ÑeÎmgUa                        
                      g                                              ?                                            ƒ                       ’                       0   "                        @@              libc.so.6 strncmp stdin calloc __isoc99_fscanf __cxa_finalize __libc_start_main GLIBC_2.7 GLIBC_2.2.5 _ITM_deregisterTMCloneTable __gmon_start__ _ITM_registerTMCloneTable                           ii
   Q      ui	   [       è=             P      ð=                   8@             8@      Ø?                    à?                    è?                    ð?                     ø?                    @@         	           @                      @                     (@                                                                                                                                                                                           HƒìH‹Ý/  H…ÀtÿÐHƒÄÃ         ÿ5â/  ÿ%ä/  @ ÿ%â/  h    éàÿÿÿÿ%Ú/  h   éÐÿÿÿÿ%Ò/  h   éÀÿÿÿÿ%’/  f        1íI‰Ñ^H‰âHƒäðPTLÊ  H
c  H=÷   ÿF/  ôD  H=™/  H’/  H9øtH‹/  H…Àt	ÿà€    Ã€    H=i/  H5b/  H)þHÁþH‰ðHÁè?HÆHÑþtH‹õ.  H…ÀtÿàfD  Ã€    €=1/   u/UHƒ=Ö.   H‰åtH‹=
/  è-ÿÿÿèhÿÿÿÆ	/  ]Ã€    Ã€    é{ÿÿÿUH‰åHƒìH‰}øH‹Eøº   H5“  H‰Çè·þÿÿ…Àt ¸   ë¸    ÉÃUH‰åHƒì¾   ¿   è®þÿÿH‰EøH‹EøHÇ     HÇ@    Æ@ H‹|.  H‹UøH5F  H‰Ç¸    èdþÿÿH‹EøH‰ÇèmÿÿÿÉÃfD  AWI‰×AVI‰öAUA‰ýATL%à+  UH-à+  SL)åHƒìèãýÿÿHÁýt1Û L‰úL‰öD‰ïAÿÜHƒÃH9ÝuêHƒÄ[]A\A]A^A_Ã Ã   HƒìHƒÄÃ                                                                                                                                                                          x        ðïÿÿ+                  zR x   $      pïÿÿ@    FJ
w€ ?;*3$"       D   ˆïÿÿ              \   eðÿÿ6    A†C
q       |   {ðÿÿ_    A†C
Z   D   œ   Àðÿÿ]    BEŽE E(ŒH0†H8ƒ G@j8A0A(B BBB    ä   Øðÿÿ                                                                                                                                                                                                                                                                    P                                        
       T             è=                           ð=                    õþÿo                               0      
       ¬       
                                     @             H                             è                           Ø       	              ûÿÿo           þÿÿo    à      ÿÿÿo           ðÿÿo    Ì      ùÿÿo                                                                                                                                   ø=                      6      F      V              8@      GCC: (Debian 8.3.0-6) 8.3.0                                   ¨                    Ä                    ä                                        0                                          Ì                    à                   	                    
 è                   
                                          
 `                    p                    T                                                               `                     è=                    ð=                    ø=                    Ø?                     @                    0@                    @@                                        ñÿ                                         Ð              !                   7     H@             F     ð=              m     P              y     è=              ˜    ñÿ                    ñÿ                ¡     „!                   ñÿ                ¯      ð=              À     ø=              É      è=              Ü                     ï      @              ð   
                    P                                  *                      °     0@              F                     a    @@             t    @@                 T              {                     š                     ®    0@              »                      Ê   8@              ×                   æ    ð      ]       »     P@              ´    p      +       ö    U      6       ÿ    @@              
    ‹      _          @@                                    6  "                    crtstuff.c deregister_tm_clones __do_global_dtors_aux completed.7325 __do_global_dtors_aux_fini_array_entry frame_dummy __frame_dummy_init_array_entry source.c __FRAME_END__ __init_array_end _DYNAMIC __init_array_start __GNU_EH_FRAME_HDR _GLOBAL_OFFSET_TABLE_ __libc_csu_fini strncmp@@GLIBC_2.2.5 _ITM_deregisterTMCloneTable __isoc99_fscanf@@GLIBC_2.7 stdin@@GLIBC_2.2.5 _edata __libc_start_main@@GLIBC_2.2.5 calloc@@GLIBC_2.2.5 __data_start __gmon_start__ __dso_handle _IO_stdin_used __libc_csu_init validate __bss_start main __TMC_END__ _ITM_registerTMCloneTable __cxa_finalize@@GLIBC_2.2.5  .symtab .strtab .shstrtab .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame .init_array .fini_array .dynamic .got.plt .data .bss .comment                                                                                     ¨      ¨                                    #              Ä      Ä                                     1              ä      ä      $                              D   öÿÿo                   (                             N   
          0      0      ð                           V                           ¬                              ^   ÿÿÿo       Ì      Ì                                  k   þÿÿo       à      à      0                            z                         Ø                            „      B       è      è      H                           Ž                                                         ‰                           @                             ”             `      `                                                p      p      á                             £             T      T      	                              ©                                                           ±                           D                              ¿             `       `       (                             É             è=      è-                                   Õ             ð=      ð-                                   á             ø=      ø-      à                           ˜             Ø?      Ø/      (                             ê              @       0      0                             ó             0@      00                                    ù             @@      @0                                    þ      0               @0                                                         `0      `         -                 	                      À6      R                                                   9                                    
 ```

Caleb was able to notice the `ELF` text at the beginning, representing the header to the standard Linux executable file format otherwise known as [executable and linkable format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format). To get more information about the executable, he saved this Cyberchef output to a file named `level01.elf` and ran the `file` command with it. The Linux `file` command can analyze the metadata and other patterns inside the file to give us a better idea of the type of ELF file.

```bash
ccrollin@thinkbox ~> file level01.elf
level01.elf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=4e6d365179eccbde19828d3017d72943b3597f05, not stripped
```

This confirmed that we were trying to reverse a Linux x86-64 ELF file.

Caleb also automated getting the ELF using the `pwntools` library. Specifically, he used the `recvline()` and `sendline()` functions to mimic manual interation with the server. This meant that the ELF binary could be read, fed into a solver program, and then input to reach the next level. This was crucial as the binaries for each level would slightly change each run.

Putting the bytes in ghidra gives us something like the following:

![level1main](https://cdn.discordapp.com/attachments/1096554014612664492/1096555254167908502/Screen_Shot_2023-04-14_at_5.58.50_PM.png)

It's clear from here that the function of interest is `validate`.

![level1validate](https://cdn.discordapp.com/attachments/1096554014612664492/1096555254453108756/Screen_Shot_2023-04-14_at_5.58.56_PM.png)

Well, that's interesting. It looks like the solution is right there, `JS6ClrItTQRJR6e0`.

```
$ nc cha.hackpack.club 41702
Welcome to the speedrun challenge! You have 3 minutes to solve 6 levels!
Level 1, here is the binary!
b'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAcBAAAAAAAABAAAAAAAAAACA6AAAAAAAAAAAAAEAAOAALAEAAHgAdAAYAAAAEAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAaAIAAAAAAABoAgAAAAAAAAgAAAAAAAAAAwAAAAQAAACoAgAAAAAAAKgCAAAAAAAAqAIAAAAAAAAcAAAAAAAAABwAAAAAAAAAAQAAAAAAAAABAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAGAAAAAAAAMAYAAAAAAAAAEAAAAAAAAAEAAAAFAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAXQIAAAAAAABdAgAAAAAAAAAQAAAAAAAAAQAAAAQAAAAAIAAAAAAAAAAgAAAAAAAAACAAAAAAAACIAQAAAAAAAIgBAAAAAAAAABAAAAAAAAABAAAABgAAAOgtAAAAAAAA6D0AAAAAAADoPQAAAAAAAFgCAAAAAAAAaAIAAAAAAAAAEAAAAAAAAAIAAAAGAAAA
...output... - see https://github.com/osalbahr/ctf-writeups/tree/main/hackpack2023/speed-rev-bots
What is the flag?
JS6ClrItTQRJR6e0
Wrong!
```

How can it be wrong? Mohamed pointed out that the binary is actually randomly generated every time we initiate a connection to the server...

Putting it in ghidra was fine for the [Speed-Rev: Humans](https://ctftime.org/task/25004) version. It's probably also fine for this version of the challenge as well, since we have 6 minutes. But I wanted to fully automate it.

## Level 1 - Solution

```
$ strings level1.elf | grep '^[a-zA-Z0-9]\{16\}$'
X1haT5hNT9wZ0Uxx
```

The above command tries to find a sequence of 16 consecutive bytes that follow the solution's requirements. That was surprisingly sufficient.

## Level 2 - Exploration

After passing Level 1, we get the binary for Level 2. This is true for the remaining levels as well.

```
Level 2, here is the binary!
b'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAYBAAAAAAAABAAAAAAAAAAOg5AAAAAAAAAAAAAEAAOAALAEAAHgAdAAYAAAAEAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAaAIAAAAAAABoAgAAAAAAAAgAAAAAAAAAAwAAAAQAAACoAgAAAAAAAKgCAAAAAAAAqAIAAAAAAAAcAAAAAAAAABwAAAAAAAAAAQAAAAAAAAABAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPgFAAAAAAAA
...output... - see https://github.com/osalbahr/ctf-writeups/tree/main/hackpack2023/speed-rev-bots
What is the flag?
```

Putting it in ghidra, we get

![level2validate](https://cdn.discordapp.com/attachments/1096589637847371806/1096591022617800745/Screen_Shot_2023-04-14_at_8.21.04_PM.png)


Looking at the disassembly of the function,
```
$ objdump -zd level2.elf --disassemble=validate

level2.elf:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .plt.got:

Disassembly of section .text:

0000000000001145 <validate>:
    1145:       55                      push   %rbp
    1146:       48 89 e5                mov    %rsp,%rbp
    1149:       48 89 7d f8             mov    %rdi,-0x8(%rbp)
    114d:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1151:       0f b6 00                movzbl (%rax),%eax
    1154:       3c 4f                   cmp    $0x4f,%al
    1156:       74 0a                   je     1162 <validate+0x1d>
    1158:       b8 01 00 00 00          mov    $0x1,%eax
    115d:       e9 6a 01 00 00          jmp    12cc <validate+0x187>
    1162:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1166:       48 83 c0 01             add    $0x1,%rax
    116a:       0f b6 00                movzbl (%rax),%eax
    116d:       3c 50                   cmp    $0x50,%al
    116f:       74 0a                   je     117b <validate+0x36>
    1171:       b8 01 00 00 00          mov    $0x1,%eax
    1176:       e9 51 01 00 00          jmp    12cc <validate+0x187>
    117b:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    117f:       48 83 c0 02             add    $0x2,%rax
    1183:       0f b6 00                movzbl (%rax),%eax
    1186:       3c 65                   cmp    $0x65,%al
    1188:       74 0a                   je     1194 <validate+0x4f>
    118a:       b8 01 00 00 00          mov    $0x1,%eax
    118f:       e9 38 01 00 00          jmp    12cc <validate+0x187>
    1194:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1198:       48 83 c0 03             add    $0x3,%rax
    119c:       0f b6 00                movzbl (%rax),%eax
    119f:       3c 67                   cmp    $0x67,%al
    11a1:       74 0a                   je     11ad <validate+0x68>
    11a3:       b8 01 00 00 00          mov    $0x1,%eax
    11a8:       e9 1f 01 00 00          jmp    12cc <validate+0x187>
    11ad:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    11b1:       48 83 c0 04             add    $0x4,%rax
    11b5:       0f b6 00                movzbl (%rax),%eax
    11b8:       3c 4f                   cmp    $0x4f,%al
    11ba:       74 0a                   je     11c6 <validate+0x81>
    11bc:       b8 01 00 00 00          mov    $0x1,%eax
    11c1:       e9 06 01 00 00          jmp    12cc <validate+0x187>
    11c6:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    11ca:       48 83 c0 05             add    $0x5,%rax
    11ce:       0f b6 00                movzbl (%rax),%eax
    11d1:       3c 6d                   cmp    $0x6d,%al
    11d3:       74 0a                   je     11df <validate+0x9a>
    11d5:       b8 01 00 00 00          mov    $0x1,%eax
    11da:       e9 ed 00 00 00          jmp    12cc <validate+0x187>
    11df:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    11e3:       48 83 c0 06             add    $0x6,%rax
    11e7:       0f b6 00                movzbl (%rax),%eax
    11ea:       3c 33                   cmp    $0x33,%al
    11ec:       74 0a                   je     11f8 <validate+0xb3>
    11ee:       b8 01 00 00 00          mov    $0x1,%eax
    11f3:       e9 d4 00 00 00          jmp    12cc <validate+0x187>
    11f8:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    11fc:       48 83 c0 07             add    $0x7,%rax
    1200:       0f b6 00                movzbl (%rax),%eax
    1203:       3c 6c                   cmp    $0x6c,%al
    1205:       74 0a                   je     1211 <validate+0xcc>
    1207:       b8 01 00 00 00          mov    $0x1,%eax
    120c:       e9 bb 00 00 00          jmp    12cc <validate+0x187>
    1211:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1215:       48 83 c0 08             add    $0x8,%rax
    1219:       0f b6 00                movzbl (%rax),%eax
    121c:       3c 6c                   cmp    $0x6c,%al
    121e:       74 0a                   je     122a <validate+0xe5>
    1220:       b8 01 00 00 00          mov    $0x1,%eax
    1225:       e9 a2 00 00 00          jmp    12cc <validate+0x187>
    122a:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    122e:       48 83 c0 09             add    $0x9,%rax
    1232:       0f b6 00                movzbl (%rax),%eax
    1235:       3c 76                   cmp    $0x76,%al
    1237:       74 0a                   je     1243 <validate+0xfe>
    1239:       b8 01 00 00 00          mov    $0x1,%eax
    123e:       e9 89 00 00 00          jmp    12cc <validate+0x187>
    1243:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1247:       48 83 c0 0a             add    $0xa,%rax
    124b:       0f b6 00                movzbl (%rax),%eax
    124e:       3c 68                   cmp    $0x68,%al
    1250:       74 07                   je     1259 <validate+0x114>
    1252:       b8 01 00 00 00          mov    $0x1,%eax
    1257:       eb 73                   jmp    12cc <validate+0x187>
    1259:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    125d:       48 83 c0 0b             add    $0xb,%rax
    1261:       0f b6 00                movzbl (%rax),%eax
    1264:       3c 5a                   cmp    $0x5a,%al
    1266:       74 07                   je     126f <validate+0x12a>
    1268:       b8 01 00 00 00          mov    $0x1,%eax
    126d:       eb 5d                   jmp    12cc <validate+0x187>
    126f:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1273:       48 83 c0 0c             add    $0xc,%rax
    1277:       0f b6 00                movzbl (%rax),%eax
    127a:       3c 4c                   cmp    $0x4c,%al
    127c:       74 07                   je     1285 <validate+0x140>
    127e:       b8 01 00 00 00          mov    $0x1,%eax
    1283:       eb 47                   jmp    12cc <validate+0x187>
    1285:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1289:       48 83 c0 0d             add    $0xd,%rax
    128d:       0f b6 00                movzbl (%rax),%eax
    1290:       3c 7a                   cmp    $0x7a,%al
    1292:       74 07                   je     129b <validate+0x156>
    1294:       b8 01 00 00 00          mov    $0x1,%eax
    1299:       eb 31                   jmp    12cc <validate+0x187>
    129b:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    129f:       48 83 c0 0e             add    $0xe,%rax
    12a3:       0f b6 00                movzbl (%rax),%eax
    12a6:       3c 42                   cmp    $0x42,%al
    12a8:       74 07                   je     12b1 <validate+0x16c>
    12aa:       b8 01 00 00 00          mov    $0x1,%eax
    12af:       eb 1b                   jmp    12cc <validate+0x187>
    12b1:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    12b5:       48 83 c0 0f             add    $0xf,%rax
    12b9:       0f b6 00                movzbl (%rax),%eax
    12bc:       3c 67                   cmp    $0x67,%al
    12be:       74 07                   je     12c7 <validate+0x182>
    12c0:       b8 01 00 00 00          mov    $0x1,%eax
    12c5:       eb 05                   jmp    12cc <validate+0x187>
    12c7:       b8 00 00 00 00          mov    $0x0,%eax
    12cc:       5d                      pop    %rbp
    12cd:       c3                      ret    

Disassembly of section .fini:
```

it becomes clear that the needed bytes are in every `cmp`. Luckily, there's only 16 `cmp` instructions in the function.

```
$ objdump -zd level2.elf --disassemble=validate | grep cmp
    1154:       3c 4f                   cmp    $0x4f,%al
    116d:       3c 50                   cmp    $0x50,%al
    1186:       3c 65                   cmp    $0x65,%al
    119f:       3c 67                   cmp    $0x67,%al
    11b8:       3c 4f                   cmp    $0x4f,%al
    11d1:       3c 6d                   cmp    $0x6d,%al
    11ea:       3c 33                   cmp    $0x33,%al
    1203:       3c 6c                   cmp    $0x6c,%al
    121c:       3c 6c                   cmp    $0x6c,%al
    1235:       3c 76                   cmp    $0x76,%al
    124e:       3c 68                   cmp    $0x68,%al
    1264:       3c 5a                   cmp    $0x5a,%al
    127a:       3c 4c                   cmp    $0x4c,%al
    1290:       3c 7a                   cmp    $0x7a,%al
    12a6:       3c 42                   cmp    $0x42,%al
    12bc:       3c 67                   cmp    $0x67,%al
$ objdump -zd level2.elf --disassemble=validate | grep cmp | wc -l
16
```

***
## Level 2 - Solution

We decided to use `pwntools` to automate getting the ELF. I couldn't think of a better way than to use `objdump` and `grep` in `python` other than using `os.system()`. I know that this is probably not a good idea, but it works. Then from there we get the solution string.

```python
os.system("objdump -zd level2.elf --disassemble=validate | grep cmp | grep -o '0x..' | cut -c 3- > hexvals3.txt")

lev2str = ''
with open("hexvals3.txt", "r") as fp:
    for hexval in fp:
            lev2str += chr(int(hexval, 16))
```

## Level 3 - Exploration

```
Level 3, here is the binary!
b'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAYBAAAAAAAABAAAAAAAAAAOg5AAAAAAAAAAAAAEAAOAALAEAAHgAdAAYAAAAEAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAaAIAAAAAAABoAgAAAAAAAAgAAAAAAAAAAwAAAAQAAACoAgAAAAAAAKgCAAAAAAAAqAIAAAAAAAAcAAAAAAAAABwAAAAAAAAAAQAAAAAAAAABAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPgFAAAAAAAA
...output... - see https://github.com/osalbahr/ctf-writeups/tree/main/hackpack2023/speed-rev-bots
What is the flag?
```

![level3validate](https://cdn.discordapp.com/attachments/1096595022725513289/1096618962411855882/Screen_Shot_2023-04-14_at_10.12.11_PM.png)

***

## Level 3 - Solution

The same as Level 2.

***

## Level 4 - Exploration

```
Level 4, here is the binary!
b'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAYBAAAAAAAABAAAAAAAAAAOg5AAAAAAAAAAAAAEAAOAALAEAAHgAdAAYAAAAEAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAaAIAAAAAAABoAgAAAAAAAAgAAAAAAAAAAwAAAAQAAACoAgAAAAAAAKgCAAAAAAAAqAIAAAAAAAAcAAAAAAAAABwAAAAAAAAAAQAAAAAAAAABAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPgFAAAAAAAA
...output... - see https://github.com/osalbahr/ctf-writeups/tree/main/hackpack2023/speed-rev-bots
What is the flag?
```

This is what the disassembly looks like:

![level4validate](https://cdn.discordapp.com/attachments/1096623141830262814/1096624319158820896/Screen_Shot_2023-04-14_at_10.33.12_PM.png)

To me, the pattern started to look like systems of linear equations. This is great for `z3`, but we weren't able to get it to only give ascii solutions.

***

## Level 4 - Solution


The objective of this solver is to find a 16-byte password that can go through all the compares and additions without failing. To do this we guess the first char and subtract from the value we are comparing against to get the value at the next index. We verify that the received char from the subtraction is a letter or number and if it is NOT then we increment the starting char, making sure the char is still an alphanumeric. We keep iterating until we have successfully gone through all the subtractions verifying that the results are still alphanumeric characters.

To summarize, the solution is try out assuming `result[0] = '0'` and if that results in a contradiction we backtrack and try subsequent alphanumeric characters up to `'z'`.

Mohamed solved Level 4 using `Java`.

```
import java.util.*;


public class Solve {
    public static void main(String[] args) {
        if (args[0].equals("4")) {
            level4();
        } 

    }

    public static void level4() {
        // There are always 15 cmp instructions so we grep for them in the pwntools 
        // script and read them from stdin here
        int[] nums = new int[15];
        Scanner scnr = new Scanner(System.in);
        int x = 0;
        while (scnr.hasNext()) {
            nums[x++] = scnr.nextInt(16);
        }

        // We allocate an array of 16 ints for the 16 char password
        int[] result = new int[16];

        // We set the first character the be the first possible ASCII char
        // which happens to be 'A'
        result[0] = 48;

        while (true) {

            // Loop through all the numbers recieved from stdin
            for (int i = 0; i < nums.length; i++) {
                // Perform the subtraction to get the next index of our password
                int curr = nums[i] - result[i];

                // Check if the character is alpanumeric
                if (!Character.isAlphabetic((char) curr) && !Character.isDigit((char) curr)) {
                    break;
                } else {
                    // Place the character if its valid in our result
                    result[i + 1] = curr;
                }

                // Check if this is the last index and if so print out the result and exit.
                if (i == nums.length - 1) {
                    for (int j = 0; j < result.length; j++) {
                        System.out.print((char) result[j]);
                    }
                    System.out.println();
                    System.exit(0);
                }
            }

            // If we broke out of the for loop we end up here where we increment the first
            // char in the result (our next guess) and make sure that character is still valid.
            result[0]++;
            if (result[0] == 58) {
                result[0] = 65;
            } else if (result[0] == 91) {
                result[0] = 97;
            } else if (result[0] > 122) {
                // If we reach the last valid character then we couldn't find a solution
                // so we break out of the while loop and exit.
                System.out.println("No solution found!");
                break;
            }


        }
    }
}
```

***

## Level 5 - Exploration

```
Level 5, here is the binary!
5
4
4
1
1
b'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAYBAAAAAAAABAAAAAAAAAAOg5AAAAAAAAAAAAAEAAOAALAEAAHgAdAAYAAAAEAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAaAIAAAAAAABoAgAAAAAAAAgAAAAAAAAAAwAAAAQAAACoAgAAAAAAAKgCAAAAAAAAqAIAAAAAAAAcAAAAAAAAABwAAAAAAAAAAQAAAAAAAAABAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPgFAAAAAAAA
...output... - see https://github.com/osalbahr/ctf-writeups/tree/main/hackpack2023/speed-rev-bots
What is the flag?
```

Putting it in ghidra, we got that it is also a system of equations.

![sanity1](https://cdn.discordapp.com/attachments/1096682108380004455/1096720294745489468/Screen_Shot_2023-04-15_at_4.54.51_AM.png)
![sanity2](https://cdn.discordapp.com/attachments/1096682508931825694/1096689756731089008/image.png)
![sanity3](https://cdn.discordapp.com/attachments/1096689224566181918/1096695537027256380/image.png)
![sanity4](https://cdn.discordapp.com/attachments/1096689667300130847/1096695995020083200/image.png)

The catch is that the equations shift and fluctuate (took us a while to realize and debug).


***

## Level 5 - Solution

The solution depends on extracting the following pattern by looking at the interleaving of the `cmp` and `add` commands in the `objdump`:

```
1) there are many regions of "plain" statements and "addition" if statements in any order. At least one of each type

2) Plain statements start at index 0 if it's in the beginning

3) Addition statements start at index 0 if it is in the beginning as well

4) falling plain -> addition, the first addition starts at a new index. For a plain statement, the value of the byte is directly given

5) falling addition -> plain, the first plain starts where the last addition ended. This is useful to take this value and "trickle up"
```

For the full solution, see `level5-solver.cpp` below.

***

## Level 6

The same as Level 5

## Final Solution

Putting it all together,

```
$ time { time make && time ./level6.py; } 
g++ -Wall -g3 -O3    level5-solver.cpp   -o level5-solver
javac Solve.java

real    0m1.702s
user    0m2.172s
sys     0m0.157s
[+] Opening connection to cha.hackpack.club on port 41702: Done
level1 = QFsChqAEUnoAlu2Q
level2 = FAmp41JkTPaPPjzE
level3 = 0NFVptnpEVsro47M
level4 = 0YeoFfDV5mLIQ8ta
level5 = hMK5UxzSyzMVZ47W
level6 = Ni4HxMZDGCvUIbSD
Congrats! Here is your flag!
flag{speedruns_are_aw3s0m3_4nd_4ll}
[*] Closed connection to cha.hackpack.club port 41702

real    0m1.683s
user    0m0.305s
sys     0m0.088s

real    0m3.385s
user    0m2.477s
sys     0m0.245s
```

## Files

[`level6.py`](https://github.com/osalbahr/ctf-writeups/blob/main/hackpack2023/speed-rev-bots/level6.py) - Automate solving all levels 1-6

[`Solve.java`](https://github.com/osalbahr/ctf-writeups/blob/main/hackpack2023/speed-rev-bots/Solve.java) - Solves Level 4

[`level5-solver.cpp`](https://github.com/osalbahr/ctf-writeups/blob/main/hackpack2023/speed-rev-bots/level5-solver.cpp) - Solves `$(echo "Level "{5,6})`

[`Makefile`](https://github.com/osalbahr/ctf-writeups/blob/main/hackpack2023/speed-rev-bots/Makefile) - Compiles `Solve.java` and `level5-solver.cpp`

## Environment

To setup for the scripts, I needed to run the following:

`$ sudo apt update && sudo apt install -y python3-pip default-jdk && pip install pwn`

Note: `default-jdk` is optional. It is only to be able to pre-compile `Solve.java`. Using `java Solve.java`, which compiles and runs the program each time, is sufficient. This is purely for benchmarking purposes.

## Acknowledgemnt

Special thanks to the NCSU's [Virtual Computing Lab (VCL)](https://vcl.ncsu.edu/). Most of the development was done on their `Ubuntu 22.04 LTS` image.
