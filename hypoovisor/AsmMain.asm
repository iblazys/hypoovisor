PUBLIC AsmEnableVmxOperation
PUBLIC AsmVmxoffAndRestoreState
PUBLIC AsmSaveStateForVmxoff

PUBLIC GetCs
PUBLIC GetDs
PUBLIC GetEs
PUBLIC GetSs
PUBLIC GetFs
PUBLIC GetGs
PUBLIC GetTr
PUBLIC GetLdtr
PUBLIC GetGdtBase
PUBLIC GetIdtBase
PUBLIC GetGdtLimit
PUBLIC GetIdtLimit
PUBLIC GetRflags
PUBLIC __load_ar

EXTERN g_StackPointerForReturning:QWORD
EXTERN g_BasePointerForReturning:QWORD

.CODE _text

; Set the
AsmEnableVmxOperation PROC PUBLIC

	PUSH RAX			    ; Save the state
	
	XOR RAX, RAX			; Clear the RAX
	MOV RAX, CR4

	OR RAX,02000h	    	; Set the 14th bit
	MOV CR4, RAX
	
	POP RAX			     	; Restore the state
	RET

AsmEnableVmxOperation ENDP

AsmVmxoffAndRestoreState PROC PUBLIC

	; turn off vmx before returning, but this is already done in TerminateVMX
	; so if we call vmxoff when it is already turned off we will get a BSOD.
	;
	; TODO: Create dedicated SaveState and RestoreState functions, we dont need to turn VMX off here.
	; And if we ever do need to turn VMX off during an error, we will do it somewhere else.
	
	;VMXOFF  
	
	MOV RSP, g_StackPointerForReturning
	MOV RBP, g_BasePointerForReturning
	
	; add 8 bytes to make RSP a correct return point
	ADD RSP, 8
	
	; return True

	XOR RAX, RAX
	MOV RAX, 1
	
	; return section

	; We need to emulate the return section of the function that calls vmlaunch
	; because vmlaunch acts as a return itself.
	
	ADD     RSP, 50h ;check what IDA / WinDBG says this is
	POP     RDI
	
	RET
	
AsmVmxoffAndRestoreState ENDP 


AsmSaveStateForVmxoff PROC PUBLIC

	MOV g_StackPointerForReturning, RSP
	MOV g_BasePointerForReturning, RBP

	RET

AsmSaveStateForVmxoff ENDP 


GetGdtBase PROC

	LOCAL	GDTR[10]:BYTE
	SGDT	GDTR
	MOV		RAX, QWORD PTR GDTR[2]

	RET

GetGdtBase ENDP


GetCs PROC

	MOV		RAX, CS
	RET

GetCs ENDP
	

GetDs PROC

	MOV		RAX, DS
	RET

GetDs ENDP


GetEs PROC

	MOV		RAX, ES
	RET

GetEs ENDP


GetSs PROC

	MOV		RAX, SS
	RET

GetSs ENDP

	
GetFs PROC

	MOV		RAX, FS
	RET

GetFs ENDP


GetGs PROC

	MOV		RAX, GS
	RET

GetGs ENDP


GetLdtr PROC

	SLDT	RAX
	RET

GetLdtr ENDP


GetTr PROC

	STR		RAX
	RET

GetTr ENDP


GetIdtBase PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		RAX, QWORD PTR IDTR[2]
	RET

GetIdtBase ENDP

	
GetGdtLimit PROC

	LOCAL	GDTR[10]:BYTE

	SGDT	GDTR
	MOV		AX, WORD PTR GDTR[0]

	RET

GetGdtLimit ENDP


GetIdtLimit PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		AX, WORD PTR IDTR[0]

	RET

GetIdtLimit ENDP


GetRflags PROC

	PUSHFQ
	POP		RAX
	RET

GetRflags ENDP

__load_ar proc
        lar     rax, rcx
        jz      no_error
        xor     rax, rax
no_error:
        ret
__load_ar endp

END
