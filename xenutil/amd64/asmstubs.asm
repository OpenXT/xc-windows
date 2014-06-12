	page	,132
	title	asmstubs - Various bits of stuff which would be inline assembly if we had a real compiler

	.code
	
	;; VOID cpuid(uint32_t lead, uint32_t *peax, uint32_t *pebx,
	;; uint32_t *pecx, uint32_t *pedx)
	public _cpuid
_cpuid  proc
	push rbx
	mov rax, rcx
	mov r10, rdx
        mov ebx, 072746943h ;; poison 
        mov ecx, 0582f7869h
        mov edx, 056506e65h
	cpuid
	mov [r10], eax
	mov [r8], ebx
	mov [r9], ecx
	pop rbx
	mov r10, [rsp+28h]
	mov [r10], edx
	ret
_cpuid	endp

        ;; uint64_t _readcr3(VOID)
        public _readcr3
_readcr3  proc
        mov rax, cr3
        ret
_readcr3  endp		
	
	;; VOID _wrmsr(uint32_t msr, uint32_t lowbits, uint32_t highbits)
	public _wrmsr
_wrmsr  proc
	;; rcx -> msr, rdx -> lowbits, r8 -> highbits.
	mov rax, rdx
	mov rdx, r8
	wrmsr
	ret
_wrmsr	endp

	extrn hypercall_page:near

	;; uint64_t __hypercall2(uint32_t ord, uint64_t arg1, uint64_t arg2)
	public __hypercall2
__hypercall2 proc
	push rdi
	push rsi
	mov rdi, rdx
	mov rax, qword ptr [hypercall_page]
	shl rcx, 5
	add rax, rcx
	mov rsi, r8
	call rax
	pop rsi
	pop rdi
	ret
__hypercall2 endp

	;; uint64_t __hypercall3(uint32_t ord, uint64_t arg1, uint64_t arg2, uint64_t arg3)
	public __hypercall3
__hypercall3 proc
	push rdi
	push rsi
	mov rdi, rdx
	mov rax, qword ptr [hypercall_page]
	shl rcx, 5
	add rax, rcx
	mov rsi, r8
	mov rdx, r9
	call rax
	pop rsi
	pop rdi
	ret
__hypercall3 endp
        
	;; uint64_t __hypercall6(uint32_t ord, uint64_t arg1, uint64_t arg2, uint64_t arg3,
	;;                       uint64_t arg4, uint64_t arg5, uint64_t arg6)
	public __hypercall6
__hypercall6 proc
	; Stack args - up past 2 pushes (rdi/rsi), return addr, 0x20b shadow home
	arg_4 = 038h
	arg_5 = 040h
	arg_6 = 048h

	push rdi
	push rsi
	mov rdi, rdx
	mov rax, qword ptr [hypercall_page]
	shl rcx, 5
	add rax, rcx
	mov rsi, r8
	mov rdx, r9
	mov r10, [rsp+arg_4]
	mov r8, [rsp+arg_5]
	mov r9, [rsp+arg_6]
	call rax
	pop rsi
	pop rdi
	ret
__hypercall6 endp

	end

