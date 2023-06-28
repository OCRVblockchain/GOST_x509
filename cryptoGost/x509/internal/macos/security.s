// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin

#include "textflag.h"

// The trampolines are ABIInternal as they are address-taken in
// Go code.

TEXT ·gost509_SecTrustSettingsCopyCertificates_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_SecTrustSettingsCopyCertificates(SB)
TEXT ·gost509_SecTrustSettingsCopyTrustSettings_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_SecTrustSettingsCopyTrustSettings(SB)
TEXT ·gost509_SecPolicyCopyProperties_trampoline(SB),NOSPLIT,$0-0
	JMP	gost509_SecPolicyCopyProperties(SB)
TEXT ·gost509_SecTrustCreateWithCertificates_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_SecTrustCreateWithCertificates(SB)
TEXT ·gost509_SecCertificateCreateWithData_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_SecCertificateCreateWithData(SB)
TEXT ·gost509_SecPolicyCreateSSL_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_SecPolicyCreateSSL(SB)
TEXT ·gost509_SecTrustSetVerifyDate_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_SecTrustSetVerifyDate(SB)
TEXT ·gost509_SecTrustEvaluate_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_SecTrustEvaluate(SB)
TEXT ·gost509_SecTrustGetResult_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_SecTrustGetResult(SB)
TEXT ·gost509_SecTrustEvaluateWithError_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_SecTrustEvaluateWithError(SB)
TEXT ·gost509_SecTrustGetCertificateCount_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_SecTrustGetCertificateCount(SB)
TEXT ·gost509_SecTrustGetCertificateAtIndex_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_SecTrustGetCertificateAtIndex(SB)
TEXT ·gost509_SecCertificateCopyData_trampoline(SB),NOSPLIT,$0-0
	JMP gost509_SecCertificateCopyData(SB)
