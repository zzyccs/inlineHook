.global _trampoline_
.global _jmp_addr_
.global _shellcode_start_
.global _shellcode_part2_
.global _the_func_addr_
.global _end_func_addr_
.global _ori_ins_set1_
.global _retback_addr_
.global _shellcode_end_

#ifdef __LP64__
#else
    .syntax unified
#endif

.data

#---------------------------------- shellcode for inlineHook ----------------------------------
#ifdef __LP64__
    _trampoline_:
        LDR                 X16, x64code0
        BR                  X16
    x64code0:
    _jmp_addr_:
        .dword 0x1111111111111111
    _shellcode_start_:
        SUB	                SP, SP,     #0x60
        STP             	X7, X6,     [SP, #16 * 0]
        STP             	X5, X4,     [SP, #16 * 1]
        STP             	X3, X2,     [SP, #16 * 2]
        STP             	X1, X0,     [SP, #16 * 3]
        MOV                 X2, LR
        MOV                 X0, SP
        BL                  x64code1
    x64code1:
        MOV                 X1, LR
        STP             	X1, X0,     [SP, #16 * 4]
        STP             	X31, X2,    [SP, #16 * 5]
        MOV                 LR, X2
        LDP             	X1, X0,     [SP, #16 * 3]
        LDP             	X3, X2,     [SP, #16 * 2]

        SUB	                SP, SP,     #0x200

        STP                 Q0, Q1,     [SP, #32 * 0]
        STP                 Q2, Q3,     [SP, #32 * 1]
        STP                 Q4, Q5,     [SP, #32 * 2]
        STP                 Q6, Q7,     [SP, #32 * 3]

        STP             	X0, X1,     [SP, #16 * 0]
        STP             	X2, X3,     [SP, #16 * 1]
        STP             	X4, X5,     [SP, #16 * 2]
        STP             	X6, X7,     [SP, #16 * 3]
        STP             	X8, X9,     [SP, #16 * 4]
        STP             	X10, X11,   [SP, #16 * 5]
        STP             	X12, X13,   [SP, #16 * 6]
        STP             	X14, X15,   [SP, #16 * 7]
        STP             	X16, X17,   [SP, #16 * 8]
        STP             	X18, X19,   [SP, #16 * 9]
        STP             	X20, X21,   [SP, #16 * 10]
        STP             	X22, X23,   [SP, #16 * 11]
        STP             	X24, X25,   [SP, #16 * 12]
        STP             	X26, X27,   [SP, #16 * 13]
        STP             	X28, X29,   [SP, #16 * 14]
        STP             	X30, X31,   [SP, #16 * 15]

        ADD                 X0,         SP, 0x200
        ADR             	X16,        LLCC1
        LDR             	X16,        [X16]
        BLR                 X16

        LDP             	X0, X1,     [SP, #16 * 0]
        LDP             	X2, X3,     [SP, #16 * 1]
        LDP             	X4, X5,     [SP, #16 * 2]
        LDP             	X6, X7,     [SP, #16 * 3]
        LDP             	X8, X9,     [SP, #16 * 4]
        LDP             	X10, X11,   [SP, #16 * 5]
        LDP             	X12, X13,   [SP, #16 * 6]
        LDP             	X14, X15,   [SP, #16 * 7]
        LDP             	X16, X17,   [SP, #16 * 8]
        LDP             	X18, X19,   [SP, #16 * 9]
        LDP             	X20, X21,   [SP, #16 * 10]
        LDP             	X22, X23,   [SP, #16 * 11]
        LDP             	X24, X25,   [SP, #16 * 12]
        LDP             	X26, X27,   [SP, #16 * 13]
        LDP             	X28, X29,   [SP, #16 * 14]
        LDP             	X30, X31,   [SP, #16 * 15]

        LDP                 Q0, Q1,     [SP, #32 * 0]
        LDP                 Q2, Q3,     [SP, #32 * 1]
        LDP                 Q4, Q5,     [SP, #32 * 2]
        LDP                 Q6, Q7,     [SP, #32 * 3]

        ADD	                SP, SP,     #0x200

        LDP             	X7, X6,     [SP, #16 * 0]
        LDP             	X5, X4,     [SP, #16 * 1]
        LDP             	X3, X2,     [SP, #16 * 2]
        LDP             	X1, X0,     [SP, #16 * 3]
        LDP             	X31, X30,   [SP, #16 * 5]
        ADD	                SP, SP,     #0x60

    _ori_ins_set1_:
        .dword 0x1111111111111111
        .dword 0x1111111111111111
        ADR             	X16,        LLCC2
        LDR             	X16,        [X16]
        BR                  X16
LLCC1:
    _the_func_addr_:
        .dword 0x1111111111111111
LLCC2:
    _retback_addr_:
        .dword 0x1111111111111111
# 已弃用，改用线程局部存储，否则多线程交叉执行时可能会存在抢占的问题。。。
# LLCC3:
#   _ori_lr_addr_:
#       .dword 0x1111111111111111
LLCC4:
    _end_func_addr_:
        .dword 0x1111111111111111
    _shellcode_part2_:
        SUB	                SP, SP,     #0x10
        STP             	X31, X0,    [SP, #16 * 0]

        SUB	                SP, SP,     #0x200

        STP                 Q0, Q1,     [SP, #32 * 0]
        STP                 Q2, Q3,     [SP, #32 * 1]
        STP                 Q4, Q5,     [SP, #32 * 2]
        STP                 Q6, Q7,     [SP, #32 * 3]

        STP             	X0, X1,     [SP, #16 * 0]
        STP             	X2, X3,     [SP, #16 * 1]
        STP             	X4, X5,     [SP, #16 * 2]
        STP             	X6, X7,     [SP, #16 * 3]
        STP             	X8, X9,     [SP, #16 * 4]
        STP             	X10, X11,   [SP, #16 * 5]
        STP             	X12, X13,   [SP, #16 * 6]
        STP             	X14, X15,   [SP, #16 * 7]
        STP             	X16, X17,   [SP, #16 * 8]
        STP             	X18, X19,   [SP, #16 * 9]
        STP             	X20, X21,   [SP, #16 * 10]
        STP             	X22, X23,   [SP, #16 * 11]
        STP             	X24, X25,   [SP, #16 * 12]
        STP             	X26, X27,   [SP, #16 * 13]
        STP             	X28, X29,   [SP, #16 * 14]
        STP             	X30, X31,   [SP, #16 * 15]

        ADD                 X0,         SP, 0x200
        ADR             	X16,        LLCC4
        LDR             	X16,        [X16]
        BLR                 X16

        LDP             	X0, X1,     [SP, #16 * 0]
        LDP             	X2, X3,     [SP, #16 * 1]
        LDP             	X4, X5,     [SP, #16 * 2]
        LDP             	X6, X7,     [SP, #16 * 3]
        LDP             	X8, X9,     [SP, #16 * 4]
        LDP             	X10, X11,   [SP, #16 * 5]
        LDP             	X12, X13,   [SP, #16 * 6]
        LDP             	X14, X15,   [SP, #16 * 7]
        LDP             	X16, X17,   [SP, #16 * 8]
        LDP             	X18, X19,   [SP, #16 * 9]
        LDP             	X20, X21,   [SP, #16 * 10]
        LDP             	X22, X23,   [SP, #16 * 11]
        LDP             	X24, X25,   [SP, #16 * 12]
        LDP             	X26, X27,   [SP, #16 * 13]
        LDP             	X28, X29,   [SP, #16 * 14]
        LDP             	X30, X31,   [SP, #16 * 15]

        LDP                 Q0, Q1,     [SP, #32 * 0]
        LDP                 Q2, Q3,     [SP, #32 * 1]
        LDP                 Q4, Q5,     [SP, #32 * 2]
        LDP                 Q6, Q7,     [SP, #32 * 3]

        ADD	                SP, SP,     #0x200

        LDP             	X30, X0,    [SP, #16 * 0]
        ADD	                SP, SP,     #0x10
        RET
    _shellcode_end_:
#else
    _shellcode_start_:
    .arm
    	PUSH			{LR}
    	PUSH			{PC}
    	PUSH			{SP}
    	PUSH			{R3}
    	PUSH			{R2}
    	PUSH			{R1}
    	PUSH			{R0}
    	PUSH			{R0-R12,LR}
    	VPUSH           {D0-D15}
    	VPUSH           {D16-D31}
    	SUB             SP, SP, #0x10
    	PUSH			{R0}
    	MRS				R0, CPSR
    	SWP				R0, R0, [SP]
    	SUB             SP, SP, #0x10

    	ADD             R0, SP, #0x15C
    	ldr 			R4, _the_func_addr_
    	BLX             R4

    	ADD             SP, SP, #0x10
    	POP 			{R0}
    	MSR				CPSR, R0
    	ADD             SP, SP, #0x10
    	VPOP           	{D16-D31}
    	VPOP           	{D0-D15}
    	POP 			{R0-R12,LR}
    	ADD             SP, SP, #0x18
    	POP				{PC}
    _the_func_addr_:
        .long 0x11111111
    _shellcode_end_:
#endif
