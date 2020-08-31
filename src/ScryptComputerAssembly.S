/**
 * Copyright (c) 2009 Colin Percival
 * Copyright (c) 2011 ArtForz
 * Copyright (c) 2011 pooler
 * Copyright (c) 2013 Balthazar
 * Copyright (c) 2019 TokenPay
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS `AS IS` AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

// arm
//
#if defined(OPTIMIZED_SALSA) &&  defined(__arm__) && defined(__APCS_32__)

#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

#if defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5TE__) || \
	defined(__ARM_ARCH_5TEJ__) || defined(__ARM_ARCH_6__) || \
	defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || \
	defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_6T2__) || \
	defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
#define __ARM_ARCH_5E_OR_6__
#endif

#if defined(__ARM_ARCH_5E_OR_6__) || defined(__ARM_ARCH_7__) || \
	defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || \
	defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
#define __ARM_ARCH_5E_OR_6_OR_7__
#endif

#ifdef __ARM_ARCH_5E_OR_6__

#define scrypt_shuffle() \
	add	lr, r0, #9*4; \
	ldmia	r0, {r2-r7}; \
	ldmia	lr, {r2, r8-r12, lr}; \
	str	r3, [r0, #5*4]; \
	str	r5, [r0, #15*4]; \
	str	r6, [r0, #12*4]; \
	str	r7, [r0, #1*4]; \
	ldr r5, [r0, #7*4]; \
	str	r2, [r0, #13*4]; \
	str	r8, [r0, #2*4]; \
	strd	r4, [r0, #10*4]; \
	str	r9, [r0, #7*4]; \
	str	r10, [r0, #4*4]; \
	str	r11, [r0, #9*4]; \
	str	lr, [r0, #3*4]; \
	add	r2, r0, #64+0*4; \
	add	lr, r0, #64+9*4; \
	ldmia	r2, {r2-r7}; \
	ldmia	lr, {r2, r8-r12, lr}; \
	str	r3, [r0, #64+5*4]; \
	str	r5, [r0, #64+15*4]; \
	str	r6, [r0, #64+12*4]; \
	str	r7, [r0, #64+1*4]; \
	ldr r5, [r0, #64+7*4]; \
	str	r2, [r0, #64+13*4]; \
	str	r8, [r0, #64+2*4]; \
	strd	r4, [r0, #64+10*4]; \
	str	r9, [r0, #64+7*4]; \
	str	r10, [r0, #64+4*4]; \
	str	r11, [r0, #64+9*4]; \
	str	lr, [r0, #64+3*4]; \


#define salsa8_core_doubleround_body() \
	add	r6, r2, r6; \
	add	r7, r3, r7; \
	eor	r10, r10, r6, ror #25; \
	add	r6, r0, r4; \
	eor	r11, r11, r7, ror #25; \
	add	r7, r1, r5; \
	strd	r10, [sp, #14*4]; \
	eor	r12, r12, r6, ror #25; \
	eor	lr, lr, r7, ror #25; \
	ldrd	r6, [sp, #10*4]; \
	add	r2, r10, r2; \
	add	r3, r11, r3; \
	eor	r6, r6, r2, ror #23; \
	add	r2, r12, r0; \
	eor	r7, r7, r3, ror #23; \
	add	r3, lr, r1; \
	strd	r6, [sp, #10*4]; \
	eor	r8, r8, r2, ror #23; \
	eor	r9, r9, r3, ror #23; \
	ldrd	r2, [sp, #6*4]; \
	add	r10, r6, r10; \
	add	r11, r7, r11; \
	eor	r2, r2, r10, ror #19; \
	add	r10, r8, r12; \
	eor	r3, r3, r11, ror #19; \
	add	r11, r9, lr; \
	eor	r4, r4, r10, ror #19; \
	eor	r5, r5, r11, ror #19; \
	ldrd	r10, [sp, #2*4]; \
	add	r6, r2, r6; \
	add	r7, r3, r7; \
	eor	r10, r10, r6, ror #14; \
	add	r6, r4, r8; \
	eor	r11, r11, r7, ror #14; \
	add	r7, r5, r9; \
	eor	r0, r0, r6, ror #14; \
	eor	r1, r1, r7, ror #14; \
	ldrd	r6, [sp, #14*4]; \
	strd	r2, [sp, #6*4]; \
	strd	r10, [sp, #2*4]; \
	add	r6, r11, r6; \
	add	r7, r0, r7; \
	eor	r4, r4, r6, ror #25; \
	add	r6, r1, r12; \
	eor	r5, r5, r7, ror #25; \
	add	r7, r10, lr; \
	eor	r2, r2, r6, ror #25; \
	eor	r3, r3, r7, ror #25; \
	strd	r2, [sp, #6*4]; \
	add	r10, r3, r10; \
	ldrd	r6, [sp, #10*4]; \
	add	r11, r4, r11; \
	eor	r8, r8, r10, ror #23; \
	add	r10, r5, r0; \
	eor	r9, r9, r11, ror #23; \
	add	r11, r2, r1; \
	eor	r6, r6, r10, ror #23; \
	eor	r7, r7, r11, ror #23; \
	strd	r6, [sp, #10*4]; \
	add	r2, r7, r2; \
	ldrd	r10, [sp, #14*4]; \
	add	r3, r8, r3; \
	eor	r12, r12, r2, ror #19; \
	add	r2, r9, r4; \
	eor	lr, lr, r3, ror #19; \
	add	r3, r6, r5; \
	eor	r10, r10, r2, ror #19; \
	eor	r11, r11, r3, ror #19; \
	ldrd	r2, [sp, #2*4]; \
	add	r6, r11, r6; \
	add	r7, r12, r7; \
	eor	r0, r0, r6, ror #14; \
	add	r6, lr, r8; \
	eor	r1, r1, r7, ror #14; \
	add	r7, r10, r9; \
	eor	r2, r2, r6, ror #14; \
	eor	r3, r3, r7, ror #14; \


#define salsa8_core() \
	ldmia	sp, {r0-r12, lr}; \
	ldrd	r10, [sp, #14*4]; \
	salsa8_core_doubleround_body(); \
	ldrd	r6, [sp, #6*4]; \
	strd	r2, [sp, #2*4]; \
	strd	r10, [sp, #14*4]; \
	salsa8_core_doubleround_body(); \
	ldrd	r6, [sp, #6*4]; \
	strd	r2, [sp, #2*4]; \
	strd	r10, [sp, #14*4]; \
	salsa8_core_doubleround_body(); \
	ldrd	r6, [sp, #6*4]; \
	strd	r2, [sp, #2*4]; \
	strd	r10, [sp, #14*4]; \
	salsa8_core_doubleround_body(); \
	stmia	sp, {r0-r5}; \
	strd	r8, [sp, #8*4]; \
	str	r12, [sp, #12*4]; \
	str	lr, [sp, #13*4]; \
	strd	r10, [sp, #14*4]; \


#else

#define scrypt_shuffle() \


#define salsa8_core_doubleround_body() \
	ldr	r8, [sp, #8*4]; \
	add	r11, r11, r10; \
	ldr	lr, [sp, #13*4]; \
	add	r12, r12, r3; \
	eor	r2, r2, r11, ror #23; \
	add	r11, r4, r0; \
	eor	r7, r7, r12, ror #23; \
	add	r12, r9, r5; \
	str	r9, [sp, #9*4]; \
	eor	r8, r8, r11, ror #23; \
	str	r10, [sp, #14*4]; \
	eor	lr, lr, r12, ror #23; \
	ldr	r11, [sp, #11*4]; \
	add	r9, lr, r9; \
	ldr	r12, [sp, #12*4]; \
	add	r10, r2, r10; \
	eor	r1, r1, r9, ror #19; \
	add	r9, r7, r3; \
	eor	r6, r6, r10, ror #19; \
	add	r10, r8, r4; \
	str	r8, [sp, #8*4]; \
	eor	r11, r11, r9, ror #19; \
	str	lr, [sp, #13*4]; \
	eor	r12, r12, r10, ror #19; \
	ldr	r9, [sp, #10*4]; \
	add	r8, r12, r8; \
	ldr	r10, [sp, #15*4]; \
	add	lr, r1, lr; \
	eor	r0, r0, r8, ror #14; \
	add	r8, r6, r2; \
	eor	r5, r5, lr, ror #14; \
	add	lr, r11, r7; \
	eor	r9, r9, r8, ror #14; \
	ldr	r8, [sp, #9*4]; \
	eor	r10, r10, lr, ror #14; \
	ldr	lr, [sp, #14*4]; \
	add	r8, r9, r8; \
	str	r9, [sp, #10*4]; \
	add	lr, r10, lr; \
	str	r10, [sp, #15*4]; \
	eor	r11, r11, r8, ror #25; \
	add	r8, r0, r3; \
	eor	r12, r12, lr, ror #25; \
	add	lr, r5, r4; \
	eor	r1, r1, r8, ror #25; \
	ldr	r8, [sp, #8*4]; \
	eor	r6, r6, lr, ror #25; \
	add	r9, r11, r9; \
	ldr	lr, [sp, #13*4]; \
	add	r10, r12, r10; \
	eor	r8, r8, r9, ror #23; \
	add	r9, r1, r0; \
	eor	lr, lr, r10, ror #23; \
	add	r10, r6, r5; \
	str	r11, [sp, #11*4]; \
	eor	r2, r2, r9, ror #23; \
	str	r12, [sp, #12*4]; \
	eor	r7, r7, r10, ror #23; \
	ldr	r9, [sp, #9*4]; \
	add	r11, r8, r11; \
	ldr	r10, [sp, #14*4]; \
	add	r12, lr, r12; \
	eor	r9, r9, r11, ror #19; \
	add	r11, r2, r1; \
	eor	r10, r10, r12, ror #19; \
	add	r12, r7, r6; \
	str	r8, [sp, #8*4]; \
	eor	r3, r3, r11, ror #19; \
	str	lr, [sp, #13*4]; \
	eor	r4, r4, r12, ror #19; \


#define salsa8_core() \
	ldmia	sp, {r0-r7}; \
	ldr	r12, [sp, #15*4]; \
	ldr	r8, [sp, #11*4]; \
	ldr	lr, [sp, #12*4]; \
	ldr	r9, [sp, #9*4]; \
	add	r8, r8, r12; \
	ldr	r11, [sp, #10*4]; \
	add	lr, lr, r0; \
	eor	r3, r3, r8, ror #25; \
	add	r8, r5, r1; \
	ldr	r10, [sp, #14*4]; \
	eor	r4, r4, lr, ror #25; \
	add	lr, r11, r6; \
	eor	r9, r9, r8, ror #25; \
	eor	r10, r10, lr, ror #25; \
	salsa8_core_doubleround_body(); \
	ldr	r11, [sp, #10*4]; \
	add	r8, r9, r8; \
	ldr	r12, [sp, #15*4]; \
	add	lr, r10, lr; \
	eor	r11, r11, r8, ror #14; \
	add	r8, r3, r2; \
	eor	r12, r12, lr, ror #14; \
	add	lr, r4, r7; \
	eor	r0, r0, r8, ror #14; \
	ldr	r8, [sp, #11*4]; \
	eor	r5, r5, lr, ror #14; \
	ldr	lr, [sp, #12*4]; \
	add	r8, r8, r12; \
	str	r11, [sp, #10*4]; \
	add	lr, lr, r0; \
	str	r12, [sp, #15*4]; \
	eor	r3, r3, r8, ror #25; \
	add	r8, r5, r1; \
	eor	r4, r4, lr, ror #25; \
	add	lr, r11, r6; \
	str	r9, [sp, #9*4]; \
	eor	r9, r9, r8, ror #25; \
	str	r10, [sp, #14*4]; \
	eor	r10, r10, lr, ror #25; \
	salsa8_core_doubleround_body(); \
	ldr	r11, [sp, #10*4]; \
	add	r8, r9, r8; \
	ldr	r12, [sp, #15*4]; \
	add	lr, r10, lr; \
	eor	r11, r11, r8, ror #14; \
	add	r8, r3, r2; \
	eor	r12, r12, lr, ror #14; \
	add	lr, r4, r7; \
	eor	r0, r0, r8, ror #14; \
	ldr	r8, [sp, #11*4]; \
	eor	r5, r5, lr, ror #14; \
	ldr	lr, [sp, #12*4]; \
	add	r8, r8, r12; \
	str	r11, [sp, #10*4]; \
	add	lr, lr, r0; \
	str	r12, [sp, #15*4]; \
	eor	r3, r3, r8, ror #25; \
	add	r8, r5, r1; \
	eor	r4, r4, lr, ror #25; \
	add	lr, r11, r6; \
	str	r9, [sp, #9*4]; \
	eor	r9, r9, r8, ror #25; \
	str	r10, [sp, #14*4]; \
	eor	r10, r10, lr, ror #25; \
	salsa8_core_doubleround_body(); \
	ldr	r11, [sp, #10*4]; \
	add	r8, r9, r8; \
	ldr	r12, [sp, #15*4]; \
	add	lr, r10, lr; \
	eor	r11, r11, r8, ror #14; \
	add	r8, r3, r2; \
	eor	r12, r12, lr, ror #14; \
	add	lr, r4, r7; \
	eor	r0, r0, r8, ror #14; \
	ldr	r8, [sp, #11*4]; \
	eor	r5, r5, lr, ror #14; \
	ldr	lr, [sp, #12*4]; \
	add	r8, r8, r12; \
	str	r11, [sp, #10*4]; \
	add	lr, lr, r0; \
	str	r12, [sp, #15*4]; \
	eor	r3, r3, r8, ror #25; \
	add	r8, r5, r1; \
	eor	r4, r4, lr, ror #25; \
	add	lr, r11, r6; \
	str	r9, [sp, #9*4]; \
	eor	r9, r9, r8, ror #25; \
	str	r10, [sp, #14*4]; \
	eor	r10, r10, lr, ror #25; \
	salsa8_core_doubleround_body(); \
	ldr	r11, [sp, #10*4]; \
	add	r8, r9, r8; \
	ldr	r12, [sp, #15*4]; \
	add	lr, r10, lr; \
	str	r9, [sp, #9*4]; \
	eor	r11, r11, r8, ror #14; \
	eor	r12, r12, lr, ror #14; \
	add	r8, r3, r2; \
	str	r10, [sp, #14*4]; \
	add	lr, r4, r7; \
	str	r11, [sp, #10*4]; \
	eor	r0, r0, r8, ror #14; \
	str	r12, [sp, #15*4]; \
	eor	r5, r5, lr, ror #14; \
	stmia	sp, {r0-r7}; \


#endif


#define scrypt_core_macro1a_x4() \
	ldmia	r0, {r4-r7}; \
	ldmia	lr!, {r8-r11}; \
	stmia	r1!, {r4-r7}; \
	stmia	r3!, {r8-r11}; \
	eor	r4, r4, r8; \
	eor	r5, r5, r9; \
	eor	r6, r6, r10; \
	eor	r7, r7, r11; \
	stmia	r0!, {r4-r7}; \
	stmia	r12!, {r4-r7}; \


#define scrypt_core_macro1b_x4() \
	ldmia	r3!, {r8-r11}; \
	ldmia	r2, {r4-r7}; \
	eor	r8, r8, r4; \
	eor	r9, r9, r5; \
	eor	r10, r10, r6; \
	eor	r11, r11, r7; \
	ldmia	r0, {r4-r7}; \
	stmia	r2!, {r8-r11}; \
	eor	r4, r4, r8; \
	eor	r5, r5, r9; \
	eor	r6, r6, r10; \
	eor	r7, r7, r11; \
	ldmia	r1!, {r8-r11}; \
	eor	r4, r4, r8; \
	eor	r5, r5, r9; \
	eor	r6, r6, r10; \
	eor	r7, r7, r11; \
	stmia	r0!, {r4-r7}; \
	stmia	r12!, {r4-r7}; \


#define scrypt_core_macro2_x4() \
	ldmia	r12, {r4-r7}; \
	ldmia	r0, {r8-r11}; \
	add	r4, r4, r8; \
	add	r5, r5, r9; \
	add	r6, r6, r10; \
	add	r7, r7, r11; \
	stmia	r0!, {r4-r7}; \
	ldmia	r2, {r8-r11}; \
	eor	r4, r4, r8; \
	eor	r5, r5, r9; \
	eor	r6, r6, r10; \
	eor	r7, r7, r11; \
	stmia	r2!, {r4-r7}; \
	stmia	r12!, {r4-r7}; \


#define scrypt_core_macro3_x4() \
	ldmia	r1!, {r4-r7}; \
	ldmia	r0, {r8-r11}; \
	add	r4, r4, r8; \
	add	r5, r5, r9; \
	add	r6, r6, r10; \
	add	r7, r7, r11; \
	stmia	r0!, {r4-r7}; \


#define scrypt_core_macro3_x6() \
	ldmia	r1!, {r2-r7}; \
	ldmia	r0, {r8-r12, lr}; \
	add	r2, r2, r8; \
	add	r3, r3, r9; \
	add	r4, r4, r10; \
	add	r5, r5, r11; \
	add	r6, r6, r12; \
	add	r7, r7, lr; \
	stmia	r0!, {r2-r7}; \



	.text
	.code 32
	.align 2
	.globl scrypt_core
	.globl _scrypt_core
#ifdef __ELF__
	.type scrypt_core, %function
#endif
scrypt_core:
_scrypt_core:
	stmfd	sp!, {r4-r11, lr}
	mov	r12, sp
	sub	sp, sp, #21*4
	bic	sp, sp, #63
	str	r12, [sp, #20*4]

	scrypt_shuffle()

	str	r0, [sp, #16*4]
	add	r12, r1, #1024*32*4
	str	r12, [sp, #18*4]
scrypt_core_loop1:
	add	lr, r0, #16*4
	add	r3, r1, #16*4
	mov	r12, sp
	scrypt_core_macro1a_x4()
	scrypt_core_macro1a_x4()
	scrypt_core_macro1a_x4()
	scrypt_core_macro1a_x4()
	str	r1, [sp, #17*4]

	salsa8_core()

	ldr	r0, [sp, #16*4]
	mov	r12, sp
	add	r2, r0, #16*4
	scrypt_core_macro2_x4()
	scrypt_core_macro2_x4()
	scrypt_core_macro2_x4()
	scrypt_core_macro2_x4()

	salsa8_core()

	ldr	r0, [sp, #16*4]
	mov	r1, sp
	add	r0, r0, #16*4
	scrypt_core_macro3_x6()
	scrypt_core_macro3_x6()
	ldr	r3, [sp, #17*4]
	ldr	r12, [sp, #18*4]
	scrypt_core_macro3_x4()

	add	r1, r3, #16*4
	sub	r0, r0, #32*4
	cmp	r1, r12
	bne	scrypt_core_loop1

	ldr	r4, [r0, #16*4]
	sub	r1, r1, #1024*32*4
	str	r1, [sp, #17*4]
	mov	r4, r4, lsl #32-10
	mov	r12, #1024
	add	r1, r1, r4, lsr #32-10-7
scrypt_core_loop2:
	add	r2, r0, #16*4
	add	r3, r1, #16*4
	str	r12, [sp, #18*4]
	mov	r12, sp
#ifdef __ARM_ARCH_5E_OR_6_OR_7__
	pld [r1, #24*4]
	pld [r1, #8*4]
#endif
	scrypt_core_macro1b_x4()
	scrypt_core_macro1b_x4()
	scrypt_core_macro1b_x4()
	scrypt_core_macro1b_x4()

	salsa8_core()

	ldr	r0, [sp, #16*4]
	mov	r12, sp
	add	r2, r0, #16*4
	scrypt_core_macro2_x4()
	scrypt_core_macro2_x4()
	scrypt_core_macro2_x4()
	scrypt_core_macro2_x4()

	salsa8_core()

	ldr	r0, [sp, #16*4]
	mov	r1, sp
	ldr	r3, [sp, #17*4]
	add	r0, r0, #16*4
	scrypt_core_macro3_x4()
	mov	r4, r4, lsl #32-10
	add	r3, r3, r4, lsr #32-10-7
	str	r3, [sp, #19*4]
#ifdef __ARM_ARCH_5E_OR_6_OR_7__
	pld	[r3, #16*4]
	pld	[r3]
#endif
	scrypt_core_macro3_x6()
	scrypt_core_macro3_x6()

	ldr	r12, [sp, #18*4]
	sub	r0, r0, #32*4
	ldr	r1, [sp, #19*4]
	subs	r12, r12, #1
	bne	scrypt_core_loop2

	scrypt_shuffle()

	ldr	sp, [sp, #20*4]
#ifdef __thumb__
	ldmfd	sp!, {r4-r11, lr}
	bx	lr
#else
	ldmfd	sp!, {r4-r11, pc}
#endif

#endif

// x86
//
#if defined(OPTIMIZED_SALSA) &&  defined(__i386__)

#if defined(__linux__) && defined(__ELF__)
.section .note.GNU-stack,"",%progbits
#endif

#define gen_salsa8_core_quadround() \
	movl	52(%esp), %ecx; \
	movl	4(%esp), %edx; \
	movl	20(%esp), %ebx; \
	movl	8(%esp), %esi; \
	leal	(%ecx, %edx), %edi; \
	roll	$7, %edi; \
	xorl	%edi, %ebx; \
	movl	%ebx, 4(%esp); \
	movl	36(%esp), %edi; \
	leal	(%edx, %ebx), %ebp; \
	roll	$9, %ebp; \
	xorl	%ebp, %edi; \
	movl	24(%esp), %ebp; \
	movl	%edi, 8(%esp); \
	addl	%edi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %ecx; \
	movl	40(%esp), %ebx; \
	movl	%ecx, 20(%esp); \
	addl	%edi, %ecx; \
	roll	$18, %ecx; \
	leal	(%esi, %ebp), %edi; \
	roll	$7, %edi; \
	xorl	%edi, %ebx; \
	movl	%ebx, 24(%esp); \
	movl	56(%esp), %edi; \
	xorl	%ecx, %edx; \
	leal	(%ebp, %ebx), %ecx; \
	roll	$9, %ecx; \
	xorl	%ecx, %edi; \
	movl	%edi, 36(%esp); \
	movl	28(%esp), %ecx; \
	movl	%edx, 28(%esp); \
	movl	44(%esp), %edx; \
	addl	%edi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %esi; \
	movl	60(%esp), %ebx; \
	movl	%esi, 40(%esp); \
	addl	%edi, %esi; \
	roll	$18, %esi; \
	leal	(%ecx, %edx), %edi; \
	roll	$7, %edi; \
	xorl	%edi, %ebx; \
	movl	%ebx, 44(%esp); \
	movl	12(%esp), %edi; \
	xorl	%esi, %ebp; \
	leal	(%edx, %ebx), %esi; \
	roll	$9, %esi; \
	xorl	%esi, %edi; \
	movl	%edi, 12(%esp); \
	movl	48(%esp), %esi; \
	movl	%ebp, 48(%esp); \
	movl	64(%esp), %ebp; \
	addl	%edi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %ecx; \
	movl	16(%esp), %ebx; \
	movl	%ecx, 16(%esp); \
	addl	%edi, %ecx; \
	roll	$18, %ecx; \
	leal	(%esi, %ebp), %edi; \
	roll	$7, %edi; \
	xorl	%edi, %ebx; \
	movl	32(%esp), %edi; \
	xorl	%ecx, %edx; \
	leal	(%ebp, %ebx), %ecx; \
	roll	$9, %ecx; \
	xorl	%ecx, %edi; \
	movl	%edi, 32(%esp); \
	movl	%ebx, %ecx; \
	movl	%edx, 52(%esp); \
	movl	28(%esp), %edx; \
	addl	%edi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %esi; \
	movl	40(%esp), %ebx; \
	movl	%esi, 28(%esp); \
	addl	%edi, %esi; \
	roll	$18, %esi; \
	leal	(%ecx, %edx), %edi; \
	roll	$7, %edi; \
	xorl	%edi, %ebx; \
	movl	%ebx, 40(%esp); \
	movl	12(%esp), %edi; \
	xorl	%esi, %ebp; \
	leal	(%edx, %ebx), %esi; \
	roll	$9, %esi; \
	xorl	%esi, %edi; \
	movl	%edi, 12(%esp); \
	movl	4(%esp), %esi; \
	movl	%ebp, 4(%esp); \
	movl	48(%esp), %ebp; \
	addl	%edi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %ecx; \
	movl	16(%esp), %ebx; \
	movl	%ecx, 16(%esp); \
	addl	%edi, %ecx; \
	roll	$18, %ecx; \
	leal	(%esi, %ebp), %edi; \
	roll	$7, %edi; \
	xorl	%edi, %ebx; \
	movl	%ebx, 48(%esp); \
	movl	32(%esp), %edi; \
	xorl	%ecx, %edx; \
	leal	(%ebp, %ebx), %ecx; \
	roll	$9, %ecx; \
	xorl	%ecx, %edi; \
	movl	%edi, 32(%esp); \
	movl	24(%esp), %ecx; \
	movl	%edx, 24(%esp); \
	movl	52(%esp), %edx; \
	addl	%edi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %esi; \
	movl	28(%esp), %ebx; \
	movl	%esi, 28(%esp); \
	addl	%edi, %esi; \
	roll	$18, %esi; \
	leal	(%ecx, %edx), %edi; \
	roll	$7, %edi; \
	xorl	%edi, %ebx; \
	movl	%ebx, 52(%esp); \
	movl	8(%esp), %edi; \
	xorl	%esi, %ebp; \
	leal	(%edx, %ebx), %esi; \
	roll	$9, %esi; \
	xorl	%esi, %edi; \
	movl	%edi, 8(%esp); \
	movl	44(%esp), %esi; \
	movl	%ebp, 44(%esp); \
	movl	4(%esp), %ebp; \
	addl	%edi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %ecx; \
	movl	20(%esp), %ebx; \
	movl	%ecx, 4(%esp); \
	addl	%edi, %ecx; \
	roll	$18, %ecx; \
	leal	(%esi, %ebp), %edi; \
	roll	$7, %edi; \
	xorl	%edi, %ebx; \
	movl	36(%esp), %edi; \
	xorl	%ecx, %edx; \
	leal	(%ebp, %ebx), %ecx; \
	roll	$9, %ecx; \
	xorl	%ecx, %edi; \
	movl	%edi, 20(%esp); \
	movl	%ebx, %ecx; \
	movl	%edx, 36(%esp); \
	movl	24(%esp), %edx; \
	addl	%edi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %esi; \
	movl	28(%esp), %ebx; \
	movl	%esi, 24(%esp); \
	addl	%edi, %esi; \
	roll	$18, %esi; \
	leal	(%ecx, %edx), %edi; \
	roll	$7, %edi; \
	xorl	%edi, %ebx; \
	movl	%ebx, 28(%esp); \
	xorl	%esi, %ebp; \
	movl	8(%esp), %esi; \
	leal	(%edx, %ebx), %edi; \
	roll	$9, %edi; \
	xorl	%edi, %esi; \
	movl	40(%esp), %edi; \
	movl	%ebp, 8(%esp); \
	movl	44(%esp), %ebp; \
	movl	%esi, 40(%esp); \
	addl	%esi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %ecx; \
	movl	4(%esp), %ebx; \
	movl	%ecx, 44(%esp); \
	addl	%esi, %ecx; \
	roll	$18, %ecx; \
	leal	(%edi, %ebp), %esi; \
	roll	$7, %esi; \
	xorl	%esi, %ebx; \
	movl	%ebx, 4(%esp); \
	movl	20(%esp), %esi; \
	xorl	%ecx, %edx; \
	leal	(%ebp, %ebx), %ecx; \
	roll	$9, %ecx; \
	xorl	%ecx, %esi; \
	movl	%esi, 56(%esp); \
	movl	48(%esp), %ecx; \
	movl	%edx, 20(%esp); \
	movl	36(%esp), %edx; \
	addl	%esi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %edi; \
	movl	24(%esp), %ebx; \
	movl	%edi, 24(%esp); \
	addl	%esi, %edi; \
	roll	$18, %edi; \
	leal	(%ecx, %edx), %esi; \
	roll	$7, %esi; \
	xorl	%esi, %ebx; \
	movl	%ebx, 60(%esp); \
	movl	12(%esp), %esi; \
	xorl	%edi, %ebp; \
	leal	(%edx, %ebx), %edi; \
	roll	$9, %edi; \
	xorl	%edi, %esi; \
	movl	%esi, 12(%esp); \
	movl	52(%esp), %edi; \
	movl	%ebp, 36(%esp); \
	movl	8(%esp), %ebp; \
	addl	%esi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %ecx; \
	movl	16(%esp), %ebx; \
	movl	%ecx, 16(%esp); \
	addl	%esi, %ecx; \
	roll	$18, %ecx; \
	leal	(%edi, %ebp), %esi; \
	roll	$7, %esi; \
	xorl	%esi, %ebx; \
	movl	32(%esp), %esi; \
	xorl	%ecx, %edx; \
	leal	(%ebp, %ebx), %ecx; \
	roll	$9, %ecx; \
	xorl	%ecx, %esi; \
	movl	%esi, 32(%esp); \
	movl	%ebx, %ecx; \
	movl	%edx, 48(%esp); \
	movl	20(%esp), %edx; \
	addl	%esi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %edi; \
	movl	24(%esp), %ebx; \
	movl	%edi, 20(%esp); \
	addl	%esi, %edi; \
	roll	$18, %edi; \
	leal	(%ecx, %edx), %esi; \
	roll	$7, %esi; \
	xorl	%esi, %ebx; \
	movl	%ebx, 8(%esp); \
	movl	12(%esp), %esi; \
	xorl	%edi, %ebp; \
	leal	(%edx, %ebx), %edi; \
	roll	$9, %edi; \
	xorl	%edi, %esi; \
	movl	%esi, 12(%esp); \
	movl	28(%esp), %edi; \
	movl	%ebp, 52(%esp); \
	movl	36(%esp), %ebp; \
	addl	%esi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %ecx; \
	movl	16(%esp), %ebx; \
	movl	%ecx, 16(%esp); \
	addl	%esi, %ecx; \
	roll	$18, %ecx; \
	leal	(%edi, %ebp), %esi; \
	roll	$7, %esi; \
	xorl	%esi, %ebx; \
	movl	%ebx, 28(%esp); \
	movl	32(%esp), %esi; \
	xorl	%ecx, %edx; \
	leal	(%ebp, %ebx), %ecx; \
	roll	$9, %ecx; \
	xorl	%ecx, %esi; \
	movl	%esi, 32(%esp); \
	movl	4(%esp), %ecx; \
	movl	%edx, 4(%esp); \
	movl	48(%esp), %edx; \
	addl	%esi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %edi; \
	movl	20(%esp), %ebx; \
	movl	%edi, 20(%esp); \
	addl	%esi, %edi; \
	roll	$18, %edi; \
	leal	(%ecx, %edx), %esi; \
	roll	$7, %esi; \
	xorl	%esi, %ebx; \
	movl	%ebx, 48(%esp); \
	movl	40(%esp), %esi; \
	xorl	%edi, %ebp; \
	leal	(%edx, %ebx), %edi; \
	roll	$9, %edi; \
	xorl	%edi, %esi; \
	movl	%esi, 36(%esp); \
	movl	60(%esp), %edi; \
	movl	%ebp, 24(%esp); \
	movl	52(%esp), %ebp; \
	addl	%esi, %ebx; \
	roll	$13, %ebx; \
	xorl	%ebx, %ecx; \
	movl	44(%esp), %ebx; \
	movl	%ecx, 40(%esp); \
	addl	%esi, %ecx; \
	roll	$18, %ecx; \
	leal	(%edi, %ebp), %esi; \
	roll	$7, %esi; \
	xorl	%esi, %ebx; \
	movl	%ebx, 52(%esp); \
	movl	56(%esp), %esi; \
	xorl	%ecx, %edx; \
	leal	(%ebp, %ebx), %ecx; \
	roll	$9, %ecx; \
	xorl	%ecx, %esi; \
	movl	%esi, 56(%esp); \
	addl	%esi, %ebx; \
	movl	%edx, 44(%esp); \
	roll	$13, %ebx; \
	xorl	%ebx, %edi; \
	movl	%edi, 60(%esp); \
	addl	%esi, %edi; \
	roll	$18, %edi; \
	xorl	%edi, %ebp; \
	movl	%ebp, 64(%esp); \


	.text
	.align 32
gen_salsa8_core:
	gen_salsa8_core_quadround()
	gen_salsa8_core_quadround()
	ret


	.text
	.align 32
	.globl scrypt_core
	.globl _scrypt_core
scrypt_core:
_scrypt_core:
	pushl	%ebx
	pushl	%ebp
	pushl	%edi
	pushl	%esi

	# Check for SSE2 availability
	movl	$1, %eax
	cpuid
	andl	$0x04000000, %edx
	jnz xmm_scrypt_core

gen_scrypt_core:
	movl	20(%esp), %edi
	movl	24(%esp), %esi
	subl	$72, %esp

#define scrypt_core_macro1a(p, q) \
	movl	p(%edi), %eax; \
	movl	q(%edi), %edx; \
	movl	%eax, p(%esi); \
	movl	%edx, q(%esi); \
	xorl	%edx, %eax; \
	movl	%eax, p(%edi); \
	movl	%eax, p(%esp); \


#define scrypt_core_macro1b(p, q) \
	movl	p(%edi), %eax; \
	xorl	p(%esi, %edx), %eax; \
	movl	q(%edi), %ebx; \
	xorl	q(%esi, %edx), %ebx; \
	movl	%ebx, q(%edi); \
	xorl	%ebx, %eax; \
	movl	%eax, p(%edi); \
	movl	%eax, p(%esp); \


#define scrypt_core_macro2(p, q) \
	movl	p(%esp), %eax; \
	addl	p(%edi), %eax; \
	movl	%eax, p(%edi); \
	xorl	q(%edi), %eax; \
	movl	%eax, q(%edi); \
	movl	%eax, p(%esp); \


#define scrypt_core_macro3(p, q) \
	movl	p(%esp), %eax; \
	addl	q(%edi), %eax; \
	movl	%eax, q(%edi); \


	leal	131072(%esi), %ecx
gen_scrypt_core_loop1:
	movl	%esi, 64(%esp)
	movl	%ecx, 68(%esp)

	scrypt_core_macro1a(0, 64)
	scrypt_core_macro1a(4, 68)
	scrypt_core_macro1a(8, 72)
	scrypt_core_macro1a(12, 76)
	scrypt_core_macro1a(16, 80)
	scrypt_core_macro1a(20, 84)
	scrypt_core_macro1a(24, 88)
	scrypt_core_macro1a(28, 92)
	scrypt_core_macro1a(32, 96)
	scrypt_core_macro1a(36, 100)
	scrypt_core_macro1a(40, 104)
	scrypt_core_macro1a(44, 108)
	scrypt_core_macro1a(48, 112)
	scrypt_core_macro1a(52, 116)
	scrypt_core_macro1a(56, 120)
	scrypt_core_macro1a(60, 124)

	call gen_salsa8_core

	movl	92(%esp), %edi
	scrypt_core_macro2(0, 64)
	scrypt_core_macro2(4, 68)
	scrypt_core_macro2(8, 72)
	scrypt_core_macro2(12, 76)
	scrypt_core_macro2(16, 80)
	scrypt_core_macro2(20, 84)
	scrypt_core_macro2(24, 88)
	scrypt_core_macro2(28, 92)
	scrypt_core_macro2(32, 96)
	scrypt_core_macro2(36, 100)
	scrypt_core_macro2(40, 104)
	scrypt_core_macro2(44, 108)
	scrypt_core_macro2(48, 112)
	scrypt_core_macro2(52, 116)
	scrypt_core_macro2(56, 120)
	scrypt_core_macro2(60, 124)

	call gen_salsa8_core

	movl	92(%esp), %edi
	scrypt_core_macro3(0, 64)
	scrypt_core_macro3(4, 68)
	scrypt_core_macro3(8, 72)
	scrypt_core_macro3(12, 76)
	scrypt_core_macro3(16, 80)
	scrypt_core_macro3(20, 84)
	scrypt_core_macro3(24, 88)
	scrypt_core_macro3(28, 92)
	scrypt_core_macro3(32, 96)
	scrypt_core_macro3(36, 100)
	scrypt_core_macro3(40, 104)
	scrypt_core_macro3(44, 108)
	scrypt_core_macro3(48, 112)
	scrypt_core_macro3(52, 116)
	scrypt_core_macro3(56, 120)
	scrypt_core_macro3(60, 124)

	movl	64(%esp), %esi
	movl	68(%esp), %ecx
	addl	$128, %esi
	cmpl	%ecx, %esi
	jne gen_scrypt_core_loop1

	movl	96(%esp), %esi
	movl	$1024, %ecx
gen_scrypt_core_loop2:
	movl	%ecx, 68(%esp)

	movl	64(%edi), %edx
	andl	$1023, %edx
	shll	$7, %edx

	scrypt_core_macro1b(0, 64)
	scrypt_core_macro1b(4, 68)
	scrypt_core_macro1b(8, 72)
	scrypt_core_macro1b(12, 76)
	scrypt_core_macro1b(16, 80)
	scrypt_core_macro1b(20, 84)
	scrypt_core_macro1b(24, 88)
	scrypt_core_macro1b(28, 92)
	scrypt_core_macro1b(32, 96)
	scrypt_core_macro1b(36, 100)
	scrypt_core_macro1b(40, 104)
	scrypt_core_macro1b(44, 108)
	scrypt_core_macro1b(48, 112)
	scrypt_core_macro1b(52, 116)
	scrypt_core_macro1b(56, 120)
	scrypt_core_macro1b(60, 124)

	call gen_salsa8_core

	movl	92(%esp), %edi
	scrypt_core_macro2(0, 64)
	scrypt_core_macro2(4, 68)
	scrypt_core_macro2(8, 72)
	scrypt_core_macro2(12, 76)
	scrypt_core_macro2(16, 80)
	scrypt_core_macro2(20, 84)
	scrypt_core_macro2(24, 88)
	scrypt_core_macro2(28, 92)
	scrypt_core_macro2(32, 96)
	scrypt_core_macro2(36, 100)
	scrypt_core_macro2(40, 104)
	scrypt_core_macro2(44, 108)
	scrypt_core_macro2(48, 112)
	scrypt_core_macro2(52, 116)
	scrypt_core_macro2(56, 120)
	scrypt_core_macro2(60, 124)

	call gen_salsa8_core

	movl	92(%esp), %edi
	movl	96(%esp), %esi
	scrypt_core_macro3(0, 64)
	scrypt_core_macro3(4, 68)
	scrypt_core_macro3(8, 72)
	scrypt_core_macro3(12, 76)
	scrypt_core_macro3(16, 80)
	scrypt_core_macro3(20, 84)
	scrypt_core_macro3(24, 88)
	scrypt_core_macro3(28, 92)
	scrypt_core_macro3(32, 96)
	scrypt_core_macro3(36, 100)
	scrypt_core_macro3(40, 104)
	scrypt_core_macro3(44, 108)
	scrypt_core_macro3(48, 112)
	scrypt_core_macro3(52, 116)
	scrypt_core_macro3(56, 120)
	scrypt_core_macro3(60, 124)

	movl	68(%esp), %ecx
	subl	$1, %ecx
	ja gen_scrypt_core_loop2

	addl	$72, %esp
	popl	%esi
	popl	%edi
	popl	%ebp
	popl	%ebx
	ret


#define xmm_salsa8_core_doubleround() \
	movdqa	%xmm1, %xmm4; \
	paddd	%xmm0, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$7, %xmm4; \
	psrld	$25, %xmm5; \
	pxor	%xmm4, %xmm3; \
	pxor	%xmm5, %xmm3; \
	movdqa	%xmm0, %xmm4; \
	paddd	%xmm3, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$9, %xmm4; \
	psrld	$23, %xmm5; \
	pxor	%xmm4, %xmm2; \
	movdqa	%xmm3, %xmm4; \
	pshufd	$0x93, %xmm3, %xmm3; \
	pxor	%xmm5, %xmm2; \
	paddd	%xmm2, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$13, %xmm4; \
	psrld	$19, %xmm5; \
	pxor	%xmm4, %xmm1; \
	movdqa	%xmm2, %xmm4; \
	pshufd	$0x4e, %xmm2, %xmm2; \
	pxor	%xmm5, %xmm1; \
	paddd	%xmm1, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$18, %xmm4; \
	psrld	$14, %xmm5; \
	pxor	%xmm4, %xmm0; \
	pshufd	$0x39, %xmm1, %xmm1; \
	pxor	%xmm5, %xmm0; \
	movdqa	%xmm3, %xmm4; \
	paddd	%xmm0, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$7, %xmm4; \
	psrld	$25, %xmm5; \
	pxor	%xmm4, %xmm1; \
	pxor	%xmm5, %xmm1; \
	movdqa	%xmm0, %xmm4; \
	paddd	%xmm1, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$9, %xmm4; \
	psrld	$23, %xmm5; \
	pxor	%xmm4, %xmm2; \
	movdqa	%xmm1, %xmm4; \
	pshufd	$0x93, %xmm1, %xmm1; \
	pxor	%xmm5, %xmm2; \
	paddd	%xmm2, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$13, %xmm4; \
	psrld	$19, %xmm5; \
	pxor	%xmm4, %xmm3; \
	movdqa	%xmm2, %xmm4; \
	pshufd	$0x4e, %xmm2, %xmm2; \
	pxor	%xmm5, %xmm3; \
	paddd	%xmm3, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$18, %xmm4; \
	psrld	$14, %xmm5; \
	pxor	%xmm4, %xmm0; \
	pshufd	$0x39, %xmm3, %xmm3; \
	pxor	%xmm5, %xmm0; \


#define xmm_salsa8_core() \
	xmm_salsa8_core_doubleround(); \
	xmm_salsa8_core_doubleround(); \
	xmm_salsa8_core_doubleround(); \
	xmm_salsa8_core_doubleround(); \


	.align 32
xmm_scrypt_core:
	movl	20(%esp), %edi
	movl	24(%esp), %esi
	movl	%esp, %ebp
	subl	$128, %esp
	andl	$-16, %esp

	# shuffle 1st block to (%esp)
	movl	60(%edi), %edx
	movl	44(%edi), %ecx
	movl	28(%edi), %ebx
	movl	12(%edi), %eax
	movl	%edx, 12(%esp)
	movl	%ecx, 28(%esp)
	movl	%ebx, 44(%esp)
	movl	%eax, 60(%esp)
	movl	40(%edi), %ecx
	movl	24(%edi), %ebx
	movl	8(%edi), %eax
	movl	56(%edi), %edx
	movl	%ecx, 8(%esp)
	movl	%ebx, 24(%esp)
	movl	%eax, 40(%esp)
	movl	%edx, 56(%esp)
	movl	20(%edi), %ebx
	movl	4(%edi), %eax
	movl	52(%edi), %edx
	movl	36(%edi), %ecx
	movl	%ebx, 4(%esp)
	movl	%eax, 20(%esp)
	movl	%edx, 36(%esp)
	movl	%ecx, 52(%esp)
	movl	0(%edi), %eax
	movl	48(%edi), %edx
	movl	32(%edi), %ecx
	movl	16(%edi), %ebx
	movl	%eax, 0(%esp)
	movl	%edx, 16(%esp)
	movl	%ecx, 32(%esp)
	movl	%ebx, 48(%esp)

	# shuffle 2nd block to 64(%esp)
	movl	124(%edi), %edx
	movl	108(%edi), %ecx
	movl	92(%edi), %ebx
	movl	76(%edi), %eax
	movl	%edx, 76(%esp)
	movl	%ecx, 92(%esp)
	movl	%ebx, 108(%esp)
	movl	%eax, 124(%esp)
	movl	104(%edi), %ecx
	movl	88(%edi), %ebx
	movl	72(%edi), %eax
	movl	120(%edi), %edx
	movl	%ecx, 72(%esp)
	movl	%ebx, 88(%esp)
	movl	%eax, 104(%esp)
	movl	%edx, 120(%esp)
	movl	84(%edi), %ebx
	movl	68(%edi), %eax
	movl	116(%edi), %edx
	movl	100(%edi), %ecx
	movl	%ebx, 68(%esp)
	movl	%eax, 84(%esp)
	movl	%edx, 100(%esp)
	movl	%ecx, 116(%esp)
	movl	64(%edi), %eax
	movl	112(%edi), %edx
	movl	96(%edi), %ecx
	movl	80(%edi), %ebx
	movl	%eax, 64(%esp)
	movl	%edx, 80(%esp)
	movl	%ecx, 96(%esp)
	movl	%ebx, 112(%esp)

	movl	%esi, %edx
	leal	131072(%esi), %ecx
xmm_scrypt_core_loop1:
	movdqa	0(%esp), %xmm0
	movdqa	16(%esp), %xmm1
	movdqa	32(%esp), %xmm2
	movdqa	48(%esp), %xmm3
	movdqa	64(%esp), %xmm4
	movdqa	80(%esp), %xmm5
	movdqa	96(%esp), %xmm6
	movdqa	112(%esp), %xmm7
	movdqa	%xmm0, 0(%edx)
	movdqa	%xmm1, 16(%edx)
	movdqa	%xmm2, 32(%edx)
	movdqa	%xmm3, 48(%edx)
	movdqa	%xmm4, 64(%edx)
	movdqa	%xmm5, 80(%edx)
	movdqa	%xmm6, 96(%edx)
	movdqa	%xmm7, 112(%edx)

	pxor	%xmm4, %xmm0
	pxor	%xmm5, %xmm1
	pxor	%xmm6, %xmm2
	pxor	%xmm7, %xmm3
	movdqa	%xmm0, 0(%esp)
	movdqa	%xmm1, 16(%esp)
	movdqa	%xmm2, 32(%esp)
	movdqa	%xmm3, 48(%esp)
	xmm_salsa8_core()
	paddd	0(%esp), %xmm0
	paddd	16(%esp), %xmm1
	paddd	32(%esp), %xmm2
	paddd	48(%esp), %xmm3
	movdqa	%xmm0, 0(%esp)
	movdqa	%xmm1, 16(%esp)
	movdqa	%xmm2, 32(%esp)
	movdqa	%xmm3, 48(%esp)

	pxor	64(%esp), %xmm0
	pxor	80(%esp), %xmm1
	pxor	96(%esp), %xmm2
	pxor	112(%esp), %xmm3
	movdqa	%xmm0, 64(%esp)
	movdqa	%xmm1, 80(%esp)
	movdqa	%xmm2, 96(%esp)
	movdqa	%xmm3, 112(%esp)
	xmm_salsa8_core()
	paddd	64(%esp), %xmm0
	paddd	80(%esp), %xmm1
	paddd	96(%esp), %xmm2
	paddd	112(%esp), %xmm3
	movdqa	%xmm0, 64(%esp)
	movdqa	%xmm1, 80(%esp)
	movdqa	%xmm2, 96(%esp)
	movdqa	%xmm3, 112(%esp)

	addl	$128, %edx
	cmpl	%ecx, %edx
	jne xmm_scrypt_core_loop1

	movl	$1024, %ecx
xmm_scrypt_core_loop2:
	movdqa	0(%esp), %xmm0
	movdqa	16(%esp), %xmm1
	movdqa	32(%esp), %xmm2
	movdqa	48(%esp), %xmm3
	movdqa	64(%esp), %xmm4
	movdqa	80(%esp), %xmm5
	movdqa	96(%esp), %xmm6
	movdqa	112(%esp), %xmm7
	movd	%xmm4, %edx
	andl	$1023, %edx
	shll	$7, %edx
	pxor	0(%esi, %edx), %xmm0
	pxor	16(%esi, %edx), %xmm1
	pxor	32(%esi, %edx), %xmm2
	pxor	48(%esi, %edx), %xmm3
	pxor	64(%esi, %edx), %xmm4
	pxor	80(%esi, %edx), %xmm5
	pxor	96(%esi, %edx), %xmm6
	pxor	112(%esi, %edx), %xmm7
	movdqa	%xmm4, 64(%esp)
	movdqa	%xmm5, 80(%esp)
	movdqa	%xmm6, 96(%esp)
	movdqa	%xmm7, 112(%esp)

	pxor	%xmm4, %xmm0
	pxor	%xmm5, %xmm1
	pxor	%xmm6, %xmm2
	pxor	%xmm7, %xmm3
	movdqa	%xmm0, 0(%esp)
	movdqa	%xmm1, 16(%esp)
	movdqa	%xmm2, 32(%esp)
	movdqa	%xmm3, 48(%esp)
	xmm_salsa8_core()
	paddd	0(%esp), %xmm0
	paddd	16(%esp), %xmm1
	paddd	32(%esp), %xmm2
	paddd	48(%esp), %xmm3
	movdqa	%xmm0, 0(%esp)
	movdqa	%xmm1, 16(%esp)
	movdqa	%xmm2, 32(%esp)
	movdqa	%xmm3, 48(%esp)

	pxor	64(%esp), %xmm0
	pxor	80(%esp), %xmm1
	pxor	96(%esp), %xmm2
	pxor	112(%esp), %xmm3
	movdqa	%xmm0, 64(%esp)
	movdqa	%xmm1, 80(%esp)
	movdqa	%xmm2, 96(%esp)
	movdqa	%xmm3, 112(%esp)
	xmm_salsa8_core()
	paddd	64(%esp), %xmm0
	paddd	80(%esp), %xmm1
	paddd	96(%esp), %xmm2
	paddd	112(%esp), %xmm3
	movdqa	%xmm0, 64(%esp)
	movdqa	%xmm1, 80(%esp)
	movdqa	%xmm2, 96(%esp)
	movdqa	%xmm3, 112(%esp)

	subl	$1, %ecx
	ja xmm_scrypt_core_loop2

	# re-shuffle 1st block back
	movl	60(%esp), %edx
	movl	44(%esp), %ecx
	movl	28(%esp), %ebx
	movl	12(%esp), %eax
	movl	%edx, 12(%edi)
	movl	%ecx, 28(%edi)
	movl	%ebx, 44(%edi)
	movl	%eax, 60(%edi)
	movl	40(%esp), %ecx
	movl	24(%esp), %ebx
	movl	8(%esp), %eax
	movl	56(%esp), %edx
	movl	%ecx, 8(%edi)
	movl	%ebx, 24(%edi)
	movl	%eax, 40(%edi)
	movl	%edx, 56(%edi)
	movl	20(%esp), %ebx
	movl	4(%esp), %eax
	movl	52(%esp), %edx
	movl	36(%esp), %ecx
	movl	%ebx, 4(%edi)
	movl	%eax, 20(%edi)
	movl	%edx, 36(%edi)
	movl	%ecx, 52(%edi)
	movl	0(%esp), %eax
	movl	48(%esp), %edx
	movl	32(%esp), %ecx
	movl	16(%esp), %ebx
	movl	%eax, 0(%edi)
	movl	%edx, 16(%edi)
	movl	%ecx, 32(%edi)
	movl	%ebx, 48(%edi)

	# re-shuffle 2nd block back
	movl	124(%esp), %edx
	movl	108(%esp), %ecx
	movl	92(%esp), %ebx
	movl	76(%esp), %eax
	movl	%edx, 76(%edi)
	movl	%ecx, 92(%edi)
	movl	%ebx, 108(%edi)
	movl	%eax, 124(%edi)
	movl	104(%esp), %ecx
	movl	88(%esp), %ebx
	movl	72(%esp), %eax
	movl	120(%esp), %edx
	movl	%ecx, 72(%edi)
	movl	%ebx, 88(%edi)
	movl	%eax, 104(%edi)
	movl	%edx, 120(%edi)
	movl	84(%esp), %ebx
	movl	68(%esp), %eax
	movl	116(%esp), %edx
	movl	100(%esp), %ecx
	movl	%ebx, 68(%edi)
	movl	%eax, 84(%edi)
	movl	%edx, 100(%edi)
	movl	%ecx, 116(%edi)
	movl	64(%esp), %eax
	movl	112(%esp), %edx
	movl	96(%esp), %ecx
	movl	80(%esp), %ebx
	movl	%eax, 64(%edi)
	movl	%edx, 80(%edi)
	movl	%ecx, 96(%edi)
	movl	%ebx, 112(%edi)

	movl	%ebp, %esp
	popl	%esi
	popl	%edi
	popl	%ebp
	popl	%ebx
	ret

#endif

// x86_64
//
#if defined(OPTIMIZED_SALSA) && defined(__x86_64__)

#if defined(__linux__) && defined(__ELF__)
	.section .note.GNU-stack,"",%progbits
#endif

#define scrypt_shuffle(src, so, dest, do) \
	movl	so+60(src), %r8d; \
	movl	so+44(src), %r9d; \
	movl	so+28(src), %r10d; \
	movl	so+12(src), %r11d; \
	movl	%r8d, do+12(dest); \
	movl	%r9d, do+28(dest); \
	movl	%r10d, do+44(dest); \
	movl	%r11d, do+60(dest); \
	movl	so+40(src), %r8d; \
	movl	so+8(src), %r9d; \
	movl	so+48(src), %r10d; \
	movl	so+16(src), %r11d; \
	movl	%r8d, do+8(dest); \
	movl	%r9d, do+40(dest); \
	movl	%r10d, do+16(dest); \
	movl	%r11d, do+48(dest); \
	movl	so+20(src), %r8d; \
	movl	so+4(src), %r9d; \
	movl	so+52(src), %r10d; \
	movl	so+36(src), %r11d; \
	movl	%r8d, do+4(dest); \
	movl	%r9d, do+20(dest); \
	movl	%r10d, do+36(dest); \
	movl	%r11d, do+52(dest); \
	movl	so+0(src), %r8d; \
	movl	so+24(src), %r9d; \
	movl	so+32(src), %r10d; \
	movl	so+56(src), %r11d; \
	movl	%r8d, do+0(dest); \
	movl	%r9d, do+24(dest); \
	movl	%r10d, do+32(dest); \
	movl	%r11d, do+56(dest); \


#define gen_salsa8_core_doubleround() \
	movq	72(%rsp), %r15; \
	leaq	(%r14, %rdx), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %r9; \
	leaq	(%rdi, %r15), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %r10; \
	leaq	(%rdx, %r9), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %r11; \
	leaq	(%r15, %r10), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %r13; \
	leaq	(%r9, %r11), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %r14; \
	leaq	(%r10, %r13), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %rdi; \
	leaq	(%r11, %r14), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %rdx; \
	leaq	(%r13, %rdi), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %r15; \
	movq	48(%rsp), %rbp; \
	movq	%r15, 72(%rsp); \
	leaq	(%rax, %rbp), %r15; \
	roll	$7, %r15d; \
	xorq	%r15, %rbx; \
	leaq	(%rbp, %rbx), %r15; \
	roll	$9, %r15d; \
	xorq	%r15, %rcx; \
	leaq	(%rbx, %rcx), %r15; \
	roll	$13, %r15d; \
	xorq	%r15, %rax; \
	leaq	(%rcx, %rax), %r15; \
	roll	$18, %r15d; \
	xorq	%r15, %rbp; \
	movq	88(%rsp), %r15; \
	movq	%rbp, 48(%rsp); \
	leaq	(%r12, %r15), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %rsi; \
	leaq	(%r15, %rsi), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %r8; \
	leaq	(%rsi, %r8), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %r12; \
	leaq	(%r8, %r12), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %r15; \
	movq	%r15, 88(%rsp); \
	movq	72(%rsp), %r15; \
	leaq	(%rsi, %rdx), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %rdi; \
	leaq	(%r9, %r15), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %rax; \
	leaq	(%rdx, %rdi), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %rcx; \
	leaq	(%r15, %rax), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %r8; \
	leaq	(%rdi, %rcx), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %rsi; \
	leaq	(%rax, %r8), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %r9; \
	leaq	(%rcx, %rsi), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %rdx; \
	leaq	(%r8, %r9), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %r15; \
	movq	48(%rsp), %rbp; \
	movq	%r15, 72(%rsp); \
	leaq	(%r10, %rbp), %r15; \
	roll	$7, %r15d; \
	xorq	%r15, %r12; \
	leaq	(%rbp, %r12), %r15; \
	roll	$9, %r15d; \
	xorq	%r15, %r11; \
	leaq	(%r12, %r11), %r15; \
	roll	$13, %r15d; \
	xorq	%r15, %r10; \
	leaq	(%r11, %r10), %r15; \
	roll	$18, %r15d; \
	xorq	%r15, %rbp; \
	movq	88(%rsp), %r15; \
	movq	%rbp, 48(%rsp); \
	leaq	(%rbx, %r15), %rbp; \
	roll	$7, %ebp; \
	xorq	%rbp, %r14; \
	leaq	(%r15, %r14), %rbp; \
	roll	$9, %ebp; \
	xorq	%rbp, %r13; \
	leaq	(%r14, %r13), %rbp; \
	roll	$13, %ebp; \
	xorq	%rbp, %rbx; \
	leaq	(%r13, %rbx), %rbp; \
	roll	$18, %ebp; \
	xorq	%rbp, %r15; \
	movq	%r15, 88(%rsp); \


	.text
	.align 32
gen_salsa8_core:
	# 0: %rdx, %rdi, %rcx, %rsi
	movq	8(%rsp), %rdi
	movq	%rdi, %rdx
	shrq	$32, %rdi
	movq	16(%rsp), %rsi
	movq	%rsi, %rcx
	shrq	$32, %rsi
	# 1: %r9, 72(%rsp), %rax, %r8
	movq	24(%rsp), %r8
	movq	%r8, %r9
	shrq	$32, %r8
	movq	%r8, 72(%rsp)
	movq	32(%rsp), %r8
	movq	%r8, %rax
	shrq	$32, %r8
	# 2: %r11, %r10, 48(%rsp), %r12
	movq	40(%rsp), %r10
	movq	%r10, %r11
	shrq	$32, %r10
	movq	48(%rsp), %r12
	#movq	%r12, %r13
	#movq	%r13, 48(%rsp)
	shrq	$32, %r12
	# 3: %r14, %r13, %rbx, 88(%rsp)
	movq	56(%rsp), %r13
	movq	%r13, %r14
	shrq	$32, %r13
	movq	64(%rsp), %r15
	movq	%r15, %rbx
	shrq	$32, %r15
	movq	%r15, 88(%rsp)

	gen_salsa8_core_doubleround()
	gen_salsa8_core_doubleround()
	gen_salsa8_core_doubleround()
	gen_salsa8_core_doubleround()

	movl	%edx, %edx
	shlq	$32, %rdi
	addq	%rdi, %rdx
	movd	%rdx, %xmm0

	movl	%ecx, %ecx
	shlq	$32, %rsi
	addq	%rsi, %rcx
	movd	%rcx, %xmm4

	movq	72(%rsp), %rdi
	movl	%r9d, %r9d
	shlq	$32, %rdi
	addq	%rdi, %r9
	movd	%r9, %xmm1

	movl	%eax, %eax
	shlq	$32, %r8
	addq	%r8, %rax
	movd	%rax, %xmm5

	movl	%r11d, %r11d
	shlq	$32, %r10
	addq	%r10, %r11
	movd	%r11, %xmm2

	movl	48(%rsp), %r8d
	shlq	$32, %r12
	addq	%r12, %r8
	movd	%r8, %xmm6

	movl	%r14d, %r14d
	shlq	$32, %r13
	addq	%r13, %r14
	movd	%r14, %xmm3

	movq	88(%rsp), %rdi
	movl	%ebx, %ebx
	shlq	$32, %rdi
	addq	%rdi, %rbx
	movd	%rbx, %xmm7

	punpcklqdq	%xmm4, %xmm0
	punpcklqdq	%xmm5, %xmm1
	punpcklqdq	%xmm6, %xmm2
	punpcklqdq	%xmm7, %xmm3

	#movq	%rdx, 8(%rsp)
	#movq	%rcx, 16(%rsp)
	#movq	%r9, 24(%rsp)
	#movq	%rax, 32(%rsp)
	#movq	%r11, 40(%rsp)
	#movq	%r8, 48(%rsp)
	#movq	%r14, 56(%rsp)
	#movq	%rbx, 64(%rsp)

	ret


	.text
	.align 32
	.globl scrypt_core
	.globl _scrypt_core
scrypt_core:
_scrypt_core:
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
#if defined(WIN64)
	subq	$176, %rsp
	movdqa	%xmm6, 8(%rsp)
	movdqa	%xmm7, 24(%rsp)
	movdqa	%xmm8, 40(%rsp)
	movdqa	%xmm9, 56(%rsp)
	movdqa	%xmm10, 72(%rsp)
	movdqa	%xmm11, 88(%rsp)
	movdqa	%xmm12, 104(%rsp)
	movdqa	%xmm13, 120(%rsp)
	movdqa	%xmm14, 136(%rsp)
	movdqa	%xmm15, 152(%rsp)
	pushq	%rdi
	pushq	%rsi
	movq	%rcx, %rdi
	movq	%rdx, %rsi
#endif

#define scrypt_core_cleanup() \
	popq	%r15; \
	popq	%r14; \
	popq	%r13; \
	popq	%r12; \
	popq	%rbp; \
	popq	%rbx; \


	# GenuineIntel processors have fast SIMD
	xorl	%eax, %eax
	cpuid
	cmpl	$0x6c65746e, %ecx
	jne gen_scrypt_core
	cmpl	$0x49656e69, %edx
	jne gen_scrypt_core
	cmpl	$0x756e6547, %ebx
	je xmm_scrypt_core

gen_scrypt_core:
	subq	$136, %rsp
	movdqa	0(%rdi), %xmm8
	movdqa	16(%rdi), %xmm9
	movdqa	32(%rdi), %xmm10
	movdqa	48(%rdi), %xmm11
	movdqa	64(%rdi), %xmm12
	movdqa	80(%rdi), %xmm13
	movdqa	96(%rdi), %xmm14
	movdqa	112(%rdi), %xmm15

	leaq	131072(%rsi), %rcx
	movq	%rdi, 104(%rsp)
	movq	%rsi, 112(%rsp)
	movq	%rcx, 120(%rsp)
gen_scrypt_core_loop1:
	movdqa	%xmm8, 0(%rsi)
	movdqa	%xmm9, 16(%rsi)
	movdqa	%xmm10, 32(%rsi)
	movdqa	%xmm11, 48(%rsi)
	movdqa	%xmm12, 64(%rsi)
	movdqa	%xmm13, 80(%rsi)
	movdqa	%xmm14, 96(%rsi)
	movdqa	%xmm15, 112(%rsi)

	pxor	%xmm12, %xmm8
	pxor	%xmm13, %xmm9
	pxor	%xmm14, %xmm10
	pxor	%xmm15, %xmm11
	movdqa	%xmm8, 0(%rsp)
	movdqa	%xmm9, 16(%rsp)
	movdqa	%xmm10, 32(%rsp)
	movdqa	%xmm11, 48(%rsp)
	movq	%rsi, 128(%rsp)
	call gen_salsa8_core
	paddd	%xmm0, %xmm8
	paddd	%xmm1, %xmm9
	paddd	%xmm2, %xmm10
	paddd	%xmm3, %xmm11

	pxor	%xmm8, %xmm12
	pxor	%xmm9, %xmm13
	pxor	%xmm10, %xmm14
	pxor	%xmm11, %xmm15
	movdqa	%xmm12, 0(%rsp)
	movdqa	%xmm13, 16(%rsp)
	movdqa	%xmm14, 32(%rsp)
	movdqa	%xmm15, 48(%rsp)
	call gen_salsa8_core
	movq	128(%rsp), %rsi
	paddd	%xmm0, %xmm12
	paddd	%xmm1, %xmm13
	paddd	%xmm2, %xmm14
	paddd	%xmm3, %xmm15

	addq	$128, %rsi
	movq	120(%rsp), %rcx
	cmpq	%rcx, %rsi
	jne gen_scrypt_core_loop1

	movq	$1024, %rcx
gen_scrypt_core_loop2:
	movq	112(%rsp), %rsi
	movd	%xmm12, %edx
	andl	$1023, %edx
	shll	$7, %edx
	movdqa	0(%rsi, %rdx), %xmm0
	movdqa	16(%rsi, %rdx), %xmm1
	movdqa	32(%rsi, %rdx), %xmm2
	movdqa	48(%rsi, %rdx), %xmm3
	movdqa	64(%rsi, %rdx), %xmm4
	movdqa	80(%rsi, %rdx), %xmm5
	movdqa	96(%rsi, %rdx), %xmm6
	movdqa	112(%rsi, %rdx), %xmm7
	pxor	%xmm0, %xmm8
	pxor	%xmm1, %xmm9
	pxor	%xmm2, %xmm10
	pxor	%xmm3, %xmm11
	pxor	%xmm4, %xmm12
	pxor	%xmm5, %xmm13
	pxor	%xmm6, %xmm14
	pxor	%xmm7, %xmm15

	pxor	%xmm12, %xmm8
	pxor	%xmm13, %xmm9
	pxor	%xmm14, %xmm10
	pxor	%xmm15, %xmm11
	movdqa	%xmm8, 0(%rsp)
	movdqa	%xmm9, 16(%rsp)
	movdqa	%xmm10, 32(%rsp)
	movdqa	%xmm11, 48(%rsp)
	movq	%rcx, 128(%rsp)
	call gen_salsa8_core
	paddd	%xmm0, %xmm8
	paddd	%xmm1, %xmm9
	paddd	%xmm2, %xmm10
	paddd	%xmm3, %xmm11

	pxor	%xmm8, %xmm12
	pxor	%xmm9, %xmm13
	pxor	%xmm10, %xmm14
	pxor	%xmm11, %xmm15
	movdqa	%xmm12, 0(%rsp)
	movdqa	%xmm13, 16(%rsp)
	movdqa	%xmm14, 32(%rsp)
	movdqa	%xmm15, 48(%rsp)
	call gen_salsa8_core
	movq	128(%rsp), %rcx
	paddd	%xmm0, %xmm12
	paddd	%xmm1, %xmm13
	paddd	%xmm2, %xmm14
	paddd	%xmm3, %xmm15

	subq	$1, %rcx
	ja gen_scrypt_core_loop2

	movq	104(%rsp), %rdi
	movdqa	%xmm8, 0(%rdi)
	movdqa	%xmm9, 16(%rdi)
	movdqa	%xmm10, 32(%rdi)
	movdqa	%xmm11, 48(%rdi)
	movdqa	%xmm12, 64(%rdi)
	movdqa	%xmm13, 80(%rdi)
	movdqa	%xmm14, 96(%rdi)
	movdqa	%xmm15, 112(%rdi)

	addq	$136, %rsp
	scrypt_core_cleanup()
	ret


#define xmm_salsa8_core_doubleround() \
	movdqa	%xmm1, %xmm4; \
	paddd	%xmm0, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$7, %xmm4; \
	psrld	$25, %xmm5; \
	pxor	%xmm4, %xmm3; \
	pxor	%xmm5, %xmm3; \
	movdqa	%xmm0, %xmm4; \
	paddd	%xmm3, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$9, %xmm4; \
	psrld	$23, %xmm5; \
	pxor	%xmm4, %xmm2; \
	movdqa	%xmm3, %xmm4; \
	pshufd	$0x93, %xmm3, %xmm3; \
	pxor	%xmm5, %xmm2; \
	paddd	%xmm2, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$13, %xmm4; \
	psrld	$19, %xmm5; \
	pxor	%xmm4, %xmm1; \
	movdqa	%xmm2, %xmm4; \
	pshufd	$0x4e, %xmm2, %xmm2; \
	pxor	%xmm5, %xmm1; \
	paddd	%xmm1, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$18, %xmm4; \
	psrld	$14, %xmm5; \
	pxor	%xmm4, %xmm0; \
	pshufd	$0x39, %xmm1, %xmm1; \
	pxor	%xmm5, %xmm0; \
	movdqa	%xmm3, %xmm4; \
	paddd	%xmm0, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$7, %xmm4; \
	psrld	$25, %xmm5; \
	pxor	%xmm4, %xmm1; \
	pxor	%xmm5, %xmm1; \
	movdqa	%xmm0, %xmm4; \
	paddd	%xmm1, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$9, %xmm4; \
	psrld	$23, %xmm5; \
	pxor	%xmm4, %xmm2; \
	movdqa	%xmm1, %xmm4; \
	pshufd	$0x93, %xmm1, %xmm1; \
	pxor	%xmm5, %xmm2; \
	paddd	%xmm2, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$13, %xmm4; \
	psrld	$19, %xmm5; \
	pxor	%xmm4, %xmm3; \
	movdqa	%xmm2, %xmm4; \
	pshufd	$0x4e, %xmm2, %xmm2; \
	pxor	%xmm5, %xmm3; \
	paddd	%xmm3, %xmm4; \
	movdqa	%xmm4, %xmm5; \
	pslld	$18, %xmm4; \
	psrld	$14, %xmm5; \
	pxor	%xmm4, %xmm0; \
	pshufd	$0x39, %xmm3, %xmm3; \
	pxor	%xmm5, %xmm0; \


#define xmm_salsa8_core() \
	xmm_salsa8_core_doubleround(); \
	xmm_salsa8_core_doubleround(); \
	xmm_salsa8_core_doubleround(); \
	xmm_salsa8_core_doubleround(); \


	.align 32
xmm_scrypt_core:
	# shuffle 1st block into %xmm8-%xmm11
	movl	60(%rdi), %edx
	movl	44(%rdi), %ecx
	movl	28(%rdi), %ebx
	movl	12(%rdi), %eax
	movd	%edx, %xmm0
	movd	%ecx, %xmm1
	movd	%ebx, %xmm2
	movd	%eax, %xmm3
	movl	40(%rdi), %ecx
	movl	24(%rdi), %ebx
	movl	8(%rdi), %eax
	movl	56(%rdi), %edx
	pshufd	$0x93, %xmm0, %xmm0
	pshufd	$0x93, %xmm1, %xmm1
	pshufd	$0x93, %xmm2, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	movd	%ecx, %xmm4
	movd	%ebx, %xmm5
	movd	%eax, %xmm6
	movd	%edx, %xmm7
	paddd	%xmm4, %xmm0
	paddd	%xmm5, %xmm1
	paddd	%xmm6, %xmm2
	paddd	%xmm7, %xmm3
	movl	20(%rdi), %ebx
	movl	4(%rdi), %eax
	movl	52(%rdi), %edx
	movl	36(%rdi), %ecx
	pshufd	$0x93, %xmm0, %xmm0
	pshufd	$0x93, %xmm1, %xmm1
	pshufd	$0x93, %xmm2, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	movd	%ebx, %xmm4
	movd	%eax, %xmm5
	movd	%edx, %xmm6
	movd	%ecx, %xmm7
	paddd	%xmm4, %xmm0
	paddd	%xmm5, %xmm1
	paddd	%xmm6, %xmm2
	paddd	%xmm7, %xmm3
	movl	0(%rdi), %eax
	movl	48(%rdi), %edx
	movl	32(%rdi), %ecx
	movl	16(%rdi), %ebx
	pshufd	$0x93, %xmm0, %xmm0
	pshufd	$0x93, %xmm1, %xmm1
	pshufd	$0x93, %xmm2, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	movd	%eax, %xmm8
	movd	%edx, %xmm9
	movd	%ecx, %xmm10
	movd	%ebx, %xmm11
	paddd	%xmm0, %xmm8
	paddd	%xmm1, %xmm9
	paddd	%xmm2, %xmm10
	paddd	%xmm3, %xmm11

	# shuffle 2nd block into %xmm12-%xmm15
	movl	124(%rdi), %edx
	movl	108(%rdi), %ecx
	movl	92(%rdi), %ebx
	movl	76(%rdi), %eax
	movd	%edx, %xmm0
	movd	%ecx, %xmm1
	movd	%ebx, %xmm2
	movd	%eax, %xmm3
	movl	104(%rdi), %ecx
	movl	88(%rdi), %ebx
	movl	72(%rdi), %eax
	movl	120(%rdi), %edx
	pshufd	$0x93, %xmm0, %xmm0
	pshufd	$0x93, %xmm1, %xmm1
	pshufd	$0x93, %xmm2, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	movd	%ecx, %xmm4
	movd	%ebx, %xmm5
	movd	%eax, %xmm6
	movd	%edx, %xmm7
	paddd	%xmm4, %xmm0
	paddd	%xmm5, %xmm1
	paddd	%xmm6, %xmm2
	paddd	%xmm7, %xmm3
	movl	84(%rdi), %ebx
	movl	68(%rdi), %eax
	movl	116(%rdi), %edx
	movl	100(%rdi), %ecx
	pshufd	$0x93, %xmm0, %xmm0
	pshufd	$0x93, %xmm1, %xmm1
	pshufd	$0x93, %xmm2, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	movd	%ebx, %xmm4
	movd	%eax, %xmm5
	movd	%edx, %xmm6
	movd	%ecx, %xmm7
	paddd	%xmm4, %xmm0
	paddd	%xmm5, %xmm1
	paddd	%xmm6, %xmm2
	paddd	%xmm7, %xmm3
	movl	64(%rdi), %eax
	movl	112(%rdi), %edx
	movl	96(%rdi), %ecx
	movl	80(%rdi), %ebx
	pshufd	$0x93, %xmm0, %xmm0
	pshufd	$0x93, %xmm1, %xmm1
	pshufd	$0x93, %xmm2, %xmm2
	pshufd	$0x93, %xmm3, %xmm3
	movd	%eax, %xmm12
	movd	%edx, %xmm13
	movd	%ecx, %xmm14
	movd	%ebx, %xmm15
	paddd	%xmm0, %xmm12
	paddd	%xmm1, %xmm13
	paddd	%xmm2, %xmm14
	paddd	%xmm3, %xmm15

	movq	%rsi, %rdx
	leaq	131072(%rsi), %rcx
xmm_scrypt_core_loop1:
	movdqa	%xmm8, 0(%rdx)
	movdqa	%xmm9, 16(%rdx)
	movdqa	%xmm10, 32(%rdx)
	movdqa	%xmm11, 48(%rdx)
	movdqa	%xmm12, 64(%rdx)
	movdqa	%xmm13, 80(%rdx)
	movdqa	%xmm14, 96(%rdx)
	movdqa	%xmm15, 112(%rdx)

	pxor	%xmm12, %xmm8
	pxor	%xmm13, %xmm9
	pxor	%xmm14, %xmm10
	pxor	%xmm15, %xmm11
	movdqa	%xmm8, %xmm0
	movdqa	%xmm9, %xmm1
	movdqa	%xmm10, %xmm2
	movdqa	%xmm11, %xmm3
	xmm_salsa8_core()
	paddd	%xmm0, %xmm8
	paddd	%xmm1, %xmm9
	paddd	%xmm2, %xmm10
	paddd	%xmm3, %xmm11

	pxor	%xmm8, %xmm12
	pxor	%xmm9, %xmm13
	pxor	%xmm10, %xmm14
	pxor	%xmm11, %xmm15
	movdqa	%xmm12, %xmm0
	movdqa	%xmm13, %xmm1
	movdqa	%xmm14, %xmm2
	movdqa	%xmm15, %xmm3
	xmm_salsa8_core()
	paddd	%xmm0, %xmm12
	paddd	%xmm1, %xmm13
	paddd	%xmm2, %xmm14
	paddd	%xmm3, %xmm15

	addq	$128, %rdx
	cmpq	%rcx, %rdx
	jne xmm_scrypt_core_loop1

	movq	$1024, %rcx
xmm_scrypt_core_loop2:
	movd	%xmm12, %edx
	andl	$1023, %edx
	shll	$7, %edx
	movdqa	0(%rsi, %rdx), %xmm0
	movdqa	16(%rsi, %rdx), %xmm1
	movdqa	32(%rsi, %rdx), %xmm2
	movdqa	48(%rsi, %rdx), %xmm3
	movdqa	64(%rsi, %rdx), %xmm4
	movdqa	80(%rsi, %rdx), %xmm5
	movdqa	96(%rsi, %rdx), %xmm6
	movdqa	112(%rsi, %rdx), %xmm7
	pxor	%xmm0, %xmm8
	pxor	%xmm1, %xmm9
	pxor	%xmm2, %xmm10
	pxor	%xmm3, %xmm11
	pxor	%xmm4, %xmm12
	pxor	%xmm5, %xmm13
	pxor	%xmm6, %xmm14
	pxor	%xmm7, %xmm15

	pxor	%xmm12, %xmm8
	pxor	%xmm13, %xmm9
	pxor	%xmm14, %xmm10
	pxor	%xmm15, %xmm11
	movdqa	%xmm8, %xmm0
	movdqa	%xmm9, %xmm1
	movdqa	%xmm10, %xmm2
	movdqa	%xmm11, %xmm3
	xmm_salsa8_core()
	paddd	%xmm0, %xmm8
	paddd	%xmm1, %xmm9
	paddd	%xmm2, %xmm10
	paddd	%xmm3, %xmm11

	pxor	%xmm8, %xmm12
	pxor	%xmm9, %xmm13
	pxor	%xmm10, %xmm14
	pxor	%xmm11, %xmm15
	movdqa	%xmm12, %xmm0
	movdqa	%xmm13, %xmm1
	movdqa	%xmm14, %xmm2
	movdqa	%xmm15, %xmm3
	xmm_salsa8_core()
	paddd	%xmm0, %xmm12
	paddd	%xmm1, %xmm13
	paddd	%xmm2, %xmm14
	paddd	%xmm3, %xmm15

	subq	$1, %rcx
	ja xmm_scrypt_core_loop2

	# re-shuffle 1st block back
	movd	%xmm8, %eax
	movd	%xmm9, %edx
	movd	%xmm10, %ecx
	movd	%xmm11, %ebx
	pshufd	$0x39, %xmm8, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pshufd	$0x39, %xmm10, %xmm10
	pshufd	$0x39, %xmm11, %xmm11
	movl	%eax, 0(%rdi)
	movl	%edx, 48(%rdi)
	movl	%ecx, 32(%rdi)
	movl	%ebx, 16(%rdi)
	movd	%xmm8, %ebx
	movd	%xmm9, %eax
	movd	%xmm10, %edx
	movd	%xmm11, %ecx
	pshufd	$0x39, %xmm8, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pshufd	$0x39, %xmm10, %xmm10
	pshufd	$0x39, %xmm11, %xmm11
	movl	%ebx, 20(%rdi)
	movl	%eax, 4(%rdi)
	movl	%edx, 52(%rdi)
	movl	%ecx, 36(%rdi)
	movd	%xmm8, %ecx
	movd	%xmm9, %ebx
	movd	%xmm10, %eax
	movd	%xmm11, %edx
	pshufd	$0x39, %xmm8, %xmm8
	pshufd	$0x39, %xmm9, %xmm9
	pshufd	$0x39, %xmm10, %xmm10
	pshufd	$0x39, %xmm11, %xmm11
	movl	%ecx, 40(%rdi)
	movl	%ebx, 24(%rdi)
	movl	%eax, 8(%rdi)
	movl	%edx, 56(%rdi)
	movd	%xmm8, %edx
	movd	%xmm9, %ecx
	movd	%xmm10, %ebx
	movd	%xmm11, %eax
	movl	%edx, 60(%rdi)
	movl	%ecx, 44(%rdi)
	movl	%ebx, 28(%rdi)
	movl	%eax, 12(%rdi)

	# re-shuffle 2nd block back
	movd	%xmm12, %eax
	movd	%xmm13, %edx
	movd	%xmm14, %ecx
	movd	%xmm15, %ebx
	pshufd	$0x39, %xmm12, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	pshufd	$0x39, %xmm14, %xmm14
	pshufd	$0x39, %xmm15, %xmm15
	movl	%eax, 64(%rdi)
	movl	%edx, 112(%rdi)
	movl	%ecx, 96(%rdi)
	movl	%ebx, 80(%rdi)
	movd	%xmm12, %ebx
	movd	%xmm13, %eax
	movd	%xmm14, %edx
	movd	%xmm15, %ecx
	pshufd	$0x39, %xmm12, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	pshufd	$0x39, %xmm14, %xmm14
	pshufd	$0x39, %xmm15, %xmm15
	movl	%ebx, 84(%rdi)
	movl	%eax, 68(%rdi)
	movl	%edx, 116(%rdi)
	movl	%ecx, 100(%rdi)
	movd	%xmm12, %ecx
	movd	%xmm13, %ebx
	movd	%xmm14, %eax
	movd	%xmm15, %edx
	pshufd	$0x39, %xmm12, %xmm12
	pshufd	$0x39, %xmm13, %xmm13
	pshufd	$0x39, %xmm14, %xmm14
	pshufd	$0x39, %xmm15, %xmm15
	movl	%ecx, 104(%rdi)
	movl	%ebx, 88(%rdi)
	movl	%eax, 72(%rdi)
	movl	%edx, 120(%rdi)
	movd	%xmm12, %edx
	movd	%xmm13, %ecx
	movd	%xmm14, %ebx
	movd	%xmm15, %eax
	movl	%edx, 124(%rdi)
	movl	%ecx, 108(%rdi)
	movl	%ebx, 92(%rdi)
	movl	%eax, 76(%rdi)

	scrypt_core_cleanup()
	ret

	addq	$392, %rsp
#if defined(WIN64)
	popq	%rsi
	popq	%rdi
	movdqa	8(%rsp), %xmm6
	movdqa	24(%rsp), %xmm7
	movdqa	40(%rsp), %xmm8
	movdqa	56(%rsp), %xmm9
	movdqa	72(%rsp), %xmm10
	movdqa	88(%rsp), %xmm11
	movdqa	104(%rsp), %xmm12
	movdqa	120(%rsp), %xmm13
	movdqa	136(%rsp), %xmm14
	movdqa	152(%rsp), %xmm15
	addq	$176, %rsp
#endif
	popq	%rbp
	popq	%rbx
	ret

#endif
