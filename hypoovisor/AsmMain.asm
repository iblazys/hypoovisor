PUBLIC AsmEnableVmxOperation

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

PUBLIC MSRRead
PUBLIC MSRWrite

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

;------------------------------------------------------------------------

MSRRead PROC

	RDMSR				; MSR[ECX] --> EDX:EAX
	SHL		RDX, 32
	OR		RAX, RDX

	RET

MSRRead ENDP

;------------------------------------------------------------------------

MSRWrite PROC

	MOV		RAX, RDX
	SHR		RDX, 32
	WRMSR
	RET

MSRWrite ENDP

;------------------------------------------------------------------------

END
