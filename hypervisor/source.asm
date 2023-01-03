PUBLIC AsmEnableVmxOperation
.code _text

;Move this to C++ if we can
AsmEnableVmxOperation PROC PUBLIC
	PUSH RAX			    ; Save the state
	
	XOR RAX, RAX			; Clear the RAX
	MOV RAX, CR4

	OR RAX,02000h	    	; Set the 14th bit
	MOV CR4, RAX
	
	POP RAX			     	; Restore the state
	RET
AsmEnableVmxOperation ENDP

MainAsm2 PROC PUBLIC
int 3
ret
MainAsm2 ENDP 

END