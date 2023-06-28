// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

#include "textflag.h"

// The trampolines are ABIInternal as they are address-taken in
// Go code.

TEXT ·gost509_CFArrayGetCount_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_CFArrayGetCount(SB)
TEXT ·gost509_CFArrayGetValueAtIndex_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_CFArrayGetValueAtIndex(SB)
TEXT ·gost509_CFDataGetBytePtr_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_CFDataGetBytePtr(SB)
TEXT ·gost509_CFDataGetLength_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_CFDataGetLength(SB)
TEXT ·gost509_CFStringCreateWithBytes_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_CFStringCreateWithBytes(SB)
TEXT ·gost509_CFRelease_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_CFRelease(SB)
TEXT ·gost509_CFDictionaryGetValueIfPresent_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_CFDictionaryGetValueIfPresent(SB)
TEXT ·gost509_CFNumberGetValue_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_CFNumberGetValue(SB)
TEXT ·gost509_CFEqual_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_CFEqual(SB)
TEXT ·gost509_CFArrayCreateMutable_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_CFArrayCreateMutable(SB)
TEXT ·gost509_CFArrayAppendValue_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_CFArrayAppendValue(SB)
TEXT ·gost509_CFDateCreate_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_CFDateCreate(SB)
TEXT ·gost509_CFDataCreate_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_CFDataCreate(SB)
TEXT ·gost509_CFErrorCopyDescription_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_CFErrorCopyDescription(SB)
TEXT ·gost509_CFStringCreateExternalRepresentation_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_CFStringCreateExternalRepresentation(SB)
