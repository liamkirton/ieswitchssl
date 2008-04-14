////////////////////////////////////////////////////////////////////////////////////////////////////
// IeSwitchSsl
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// SspiHook.cpp
//
// Created: 15/02/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#include "SspiHook.h"

#include <strsafe.h>

#include <exception>

////////////////////////////////////////////////////////////////////////////////////////////////////

void __stdcall AcquireCredentialsHandleHookAProc(SEC_CHAR * pszPrincipal,
												 SEC_CHAR * pszPackage,
												 unsigned long fCredentialUse,
												 void * pvLogonId,
												 void * pAuthData,
												 SEC_GET_KEY_FN pGetKeyFn,
												 void * pvGetKeyArgument,
												 PCredHandle phCredential,
												 PTimeStamp ptsExpiry)
{
	if(lstrcmpA(pszPackage, UNISP_NAME_A) == 0)
	{
		SCHANNEL_CRED *pSchannelCred = reinterpret_cast<SCHANNEL_CRED *>(pAuthData);
		pSchannelCred->grbitEnabledProtocols = SspiHook::GetInstance().dwProtocols_;
		pSchannelCred->dwMinimumCipherStrength = SspiHook::GetInstance().dwCiphers_;
		pSchannelCred->dwMaximumCipherStrength = SspiHook::GetInstance().dwCiphers_;

		if(SspiHook::GetInstance().supportedAlgorithms_.size() == 0)
		{
			pSchannelCred->cSupportedAlgs = 0;
			pSchannelCred->palgSupportedAlgs = NULL;
		}
		else
		{
			SecureZeroMemory(&SspiHook::GetInstance().hookSupportedAlgorithmsBuffer, sizeof(SspiHook::GetInstance().hookSupportedAlgorithmsBuffer));

			pSchannelCred->cSupportedAlgs = 0;
			pSchannelCred->palgSupportedAlgs = reinterpret_cast<ALG_ID *>(&SspiHook::GetInstance().hookSupportedAlgorithmsBuffer);
			
			for(std::vector<ALG_ID>::iterator i = SspiHook::GetInstance().supportedAlgorithms_.begin(); i != SspiHook::GetInstance().supportedAlgorithms_.end(); ++i)
			{
				pSchannelCred->palgSupportedAlgs[pSchannelCred->cSupportedAlgs++] = (*i);
			}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void __stdcall AcquireCredentialsHandleHookWProc(SEC_WCHAR * pszPrincipal,
												 SEC_WCHAR * pszPackage,
												 unsigned long fCredentialUse,
												 void * pvLogonId,
												 void * pAuthData,
												 SEC_GET_KEY_FN pGetKeyFn,
												 void * pvGetKeyArgument,
												 PCredHandle phCredential,
												 PTimeStamp ptsExpiry)
{
	if(lstrcmpW(pszPackage, UNISP_NAME_W) == 0)
	{
		SCHANNEL_CRED *pSchannelCred = reinterpret_cast<SCHANNEL_CRED *>(pAuthData);
		pSchannelCred->grbitEnabledProtocols = SspiHook::GetInstance().dwProtocols_;
		pSchannelCred->dwMinimumCipherStrength = SspiHook::GetInstance().dwCiphers_;
		pSchannelCred->dwMaximumCipherStrength = SspiHook::GetInstance().dwCiphers_;

		if(SspiHook::GetInstance().supportedAlgorithms_.size() == 0)
		{
			pSchannelCred->cSupportedAlgs = 0;
			pSchannelCred->palgSupportedAlgs = NULL;
		}
		else
		{
			pSchannelCred->cSupportedAlgs = 0;
			pSchannelCred->palgSupportedAlgs = reinterpret_cast<ALG_ID *>(&SspiHook::GetInstance().hookSupportedAlgorithmsBuffer);

			for(std::vector<ALG_ID>::iterator i = SspiHook::GetInstance().supportedAlgorithms_.begin(); i != SspiHook::GetInstance().supportedAlgorithms_.end(); ++i)
			{
				pSchannelCred->palgSupportedAlgs[pSchannelCred->cSupportedAlgs++] = (*i);
			}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void __stdcall InitializeSecurityContextHookAProc(PCredHandle phCredential,
												  PCtxtHandle phContext,
												  SEC_CHAR * pszTargetName,
												  unsigned long fContextReq,
												  unsigned long Reserved1,
												  unsigned long TargetDataRep,
												  PSecBufferDesc pInput,
												  unsigned long Reserved2,
												  PCtxtHandle phNewContext,
												  PSecBufferDesc pOutput,
												  unsigned long * pfContextAttr,
												  PTimeStamp ptsExpiry)
{
	if((phContext == NULL) &&
	   (SspiHook::GetInstance().bHook_ && (SspiHook::GetInstance().dwCiphers_ != 0) ||
										  (SspiHook::GetInstance().dwProtocols_ != 0) || 
										  (SspiHook::GetInstance().supportedAlgorithms_.size() != 0)))
	{
		FreeCredentialsHandle(phCredential);

		SCHANNEL_CRED sChannelCred;
		SecureZeroMemory(&sChannelCred, sizeof(SCHANNEL_CRED));
		sChannelCred.dwVersion = SCHANNEL_CRED_VERSION;
		sChannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
		sChannelCred.dwMaximumCipherStrength = 0;
		sChannelCred.grbitEnabledProtocols = 0;
		
		AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &sChannelCred, NULL, NULL, phCredential, NULL);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void __stdcall InitializeSecurityContextHookWProc(PCredHandle phCredential,
												  PCtxtHandle phContext,
												  SEC_WCHAR * pszTargetName,
												  unsigned long fContextReq,
												  unsigned long Reserved1,
												  unsigned long TargetDataRep,
												  PSecBufferDesc pInput,
												  unsigned long Reserved2,
												  PCtxtHandle phNewContext,
												  PSecBufferDesc pOutput,
												  unsigned long * pfContextAttr,
												  PTimeStamp ptsExpiry)
{
	if((phContext == NULL) &&
	   (SspiHook::GetInstance().bHook_ && (SspiHook::GetInstance().dwCiphers_ != 0) ||
										  (SspiHook::GetInstance().dwProtocols_ != 0) || 
										  (SspiHook::GetInstance().supportedAlgorithms_.size() != 0)))
	{
		FreeCredentialsHandle(phCredential);

		SCHANNEL_CRED sChannelCred;
		SecureZeroMemory(&sChannelCred, sizeof(SCHANNEL_CRED));
		sChannelCred.dwVersion = SCHANNEL_CRED_VERSION;
		sChannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
		sChannelCred.dwMaximumCipherStrength = 0;
		sChannelCred.grbitEnabledProtocols = 0;
		
		AcquireCredentialsHandleW(NULL, UNISP_NAME_W, SECPKG_CRED_OUTBOUND, NULL, &sChannelCred, NULL, NULL, phCredential, NULL);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void __stdcall CertVerifyCertificateChainPolicyHookProc(LPCSTR pszPolicyOID,
														PCCERT_CHAIN_CONTEXT pChainContext,
														PCERT_CHAIN_POLICY_PARA pPolicyPara,
														PCERT_CHAIN_POLICY_STATUS pPolicyStatus)
{
	if(SspiHook::GetInstance().bHook_ && !SspiHook::GetInstance().bCertVerification_)
	{
		pPolicyStatus->dwError = 0;
		__asm
		{
			mov eax, 1
		}
	}
	else
	{
		__asm
		{
			mov eax, 0xFFFFFFFF
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

static void __declspec(naked) AcquireCredentialsHandleHookA()
{
	__asm
	{
		push ebp
		mov ebp, esp
		pushad

		mov eax, dword ptr[ebp+0x28]
		push eax
		mov eax, dword ptr[ebp+0x24]
		push eax
		mov eax, dword ptr[ebp+0x20]
		push eax
		mov eax, dword ptr[ebp+0x1c]
		push eax
		mov eax, dword ptr[ebp+0x18]
		push eax
		mov eax, dword ptr[ebp+0x14]
		push eax
		mov eax, dword ptr[ebp+0x10]
		push eax
		mov eax, dword ptr[ebp+0x0C]
		push eax
		mov eax, dword ptr[ebp+0x08]
		push eax
		call AcquireCredentialsHandleHookAProc

		popad
		
		_emit 0xE9 ; JMP
		_emit 0x90
		_emit 0x90
		_emit 0x90
		_emit 0x90
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

static void __declspec(naked) AcquireCredentialsHandleHookW()
{
	__asm
	{
		push ebp
		mov ebp, esp
		pushad

		mov eax, dword ptr[ebp+0x28]
		push eax
		mov eax, dword ptr[ebp+0x24]
		push eax
		mov eax, dword ptr[ebp+0x20]
		push eax
		mov eax, dword ptr[ebp+0x1c]
		push eax
		mov eax, dword ptr[ebp+0x18]
		push eax
		mov eax, dword ptr[ebp+0x14]
		push eax
		mov eax, dword ptr[ebp+0x10]
		push eax
		mov eax, dword ptr[ebp+0x0C]
		push eax
		mov eax, dword ptr[ebp+0x08]
		push eax
		call AcquireCredentialsHandleHookWProc

		popad
		
		_emit 0xE9 ; JMP
		_emit 0x90
		_emit 0x90
		_emit 0x90
		_emit 0x90
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

static void __declspec(naked) InitializeSecurityContextHookA()
{
	__asm
	{
		push ebp
		mov ebp, esp
		pushad

		mov eax, dword ptr[ebp+0x34]
		push eax
		mov eax, dword ptr[ebp+0x30]
		push eax
		mov eax, dword ptr[ebp+0x2c]
		push eax
		mov eax, dword ptr[ebp+0x28]
		push eax
		mov eax, dword ptr[ebp+0x24]
		push eax
		mov eax, dword ptr[ebp+0x20]
		push eax
		mov eax, dword ptr[ebp+0x1c]
		push eax
		mov eax, dword ptr[ebp+0x18]
		push eax
		mov eax, dword ptr[ebp+0x14]
		push eax
		mov eax, dword ptr[ebp+0x10]
		push eax
		mov eax, dword ptr[ebp+0x0C]
		push eax
		mov eax, dword ptr[ebp+0x08]
		push eax
		call InitializeSecurityContextHookAProc

		popad
		
		_emit 0xE9 ; JMP
		_emit 0x90
		_emit 0x90
		_emit 0x90
		_emit 0x90
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

static void __declspec(naked) InitializeSecurityContextHookW()
{
	__asm
	{
		push ebp
		mov ebp, esp
		pushad

		mov eax, dword ptr[ebp+0x34]
		push eax
		mov eax, dword ptr[ebp+0x30]
		push eax
		mov eax, dword ptr[ebp+0x2c]
		push eax
		mov eax, dword ptr[ebp+0x28]
		push eax
		mov eax, dword ptr[ebp+0x24]
		push eax
		mov eax, dword ptr[ebp+0x20]
		push eax
		mov eax, dword ptr[ebp+0x1c]
		push eax
		mov eax, dword ptr[ebp+0x18]
		push eax
		mov eax, dword ptr[ebp+0x14]
		push eax
		mov eax, dword ptr[ebp+0x10]
		push eax
		mov eax, dword ptr[ebp+0x0C]
		push eax
		mov eax, dword ptr[ebp+0x08]
		push eax
		call InitializeSecurityContextHookWProc

		popad
		
		_emit 0xE9 ; JMP
		_emit 0x90
		_emit 0x90
		_emit 0x90
		_emit 0x90
	}
}


////////////////////////////////////////////////////////////////////////////////////////////////////

static void __declspec(naked) CertVerifyCertificateChainPolicyHook()
{
	__asm
	{
		push ebp
		mov ebp, esp
		pushad

		mov eax, dword ptr[ebp+0x14]
		push eax
		mov eax, dword ptr[ebp+0x10]
		push eax
		mov eax, dword ptr[ebp+0x0C]
		push eax
		mov eax, dword ptr[ebp+0x08]
		push eax
		call CertVerifyCertificateChainPolicyHookProc

		cmp eax, 0xFFFFFFFF
		popad
		je exec_function
		
		leave
		ret 0x0010

exec_function:
		_emit 0xE9 ; JMP
		_emit 0x90
		_emit 0x90
		_emit 0x90
		_emit 0x90		
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

SspiHook &SspiHook::GetInstance()
{
	static SspiHook sspiHook;
	return sspiHook;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

SspiHook::SspiHook() : bHook_(false),
					   bCertVerification_(true),
					   dwProtocols_(0),
					   dwCiphers_(0)
{
	InstallHooks();
}

////////////////////////////////////////////////////////////////////////////////////////////////////

SspiHook::~SspiHook()
{
	UninstallHooks();
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SspiHook::InstallHooks()
{
	HMODULE hSecur32Module;
	FARPROC fpAcquireCredentialsHandleA;
	FARPROC fpAcquireCredentialsHandleW;
	FARPROC fpInitializeSecurityContextA;
	FARPROC fpInitializeSecurityContextW;

	HMODULE hCrypt32Module;
	FARPROC fpCertVerifyCertificateChainPolicy;

	try
	{
		if((hSecur32Module = GetModuleHandle(L"secur32.dll")) == NULL)
		{
			throw std::exception("secur32.dll Not Loaded By Process.");
		}

		if((fpAcquireCredentialsHandleA = GetProcAddress(hSecur32Module, "AcquireCredentialsHandleA")) == NULL)
		{
			throw std::exception("GetProcAddress(\"AcquireCredentialsHandleA\") Failed.");
		}

		if((fpAcquireCredentialsHandleW = GetProcAddress(hSecur32Module, "AcquireCredentialsHandleW")) == NULL)
		{
			throw std::exception("GetProcAddress(\"AcquireCredentialsHandleW\") Failed.");
		}

		if((fpInitializeSecurityContextA = GetProcAddress(hSecur32Module, "InitializeSecurityContextA")) == NULL)
		{
			throw std::exception("GetProcAddress(\"InitializeSecurityContextA\") Failed.");
		}

		if((fpInitializeSecurityContextW = GetProcAddress(hSecur32Module, "InitializeSecurityContextW")) == NULL)
		{
			throw std::exception("GetProcAddress(\"InitializeSecurityContextW\") Failed.");
		}

		unsigned char *lpAcquireCredentialsHandleA = reinterpret_cast<unsigned char *>(fpAcquireCredentialsHandleA);
		unsigned char *lpAcquireCredentialsHandleW = reinterpret_cast<unsigned char *>(fpAcquireCredentialsHandleW);
		unsigned char *lpAcquireCredentialsHandleHookA = reinterpret_cast<unsigned char *>(AcquireCredentialsHandleHookA);
		unsigned char *lpAcquireCredentialsHandleHookW = reinterpret_cast<unsigned char *>(AcquireCredentialsHandleHookW);
		
		InstallPrologueHook(lpAcquireCredentialsHandleA, lpAcquireCredentialsHandleHookA);
		InstallPrologueHook(lpAcquireCredentialsHandleW, lpAcquireCredentialsHandleHookW);
		
		unsigned char *lpInitializeSecurityContextA = reinterpret_cast<unsigned char *>(fpInitializeSecurityContextA);
		unsigned char *lpInitializeSecurityContextW = reinterpret_cast<unsigned char *>(fpInitializeSecurityContextW);
		unsigned char *lpInitializeSecurityContextHookA = reinterpret_cast<unsigned char *>(InitializeSecurityContextHookA);
		unsigned char *lpInitializeSecurityContextHookW = reinterpret_cast<unsigned char *>(InitializeSecurityContextHookW);

		InstallPrologueHook(lpInitializeSecurityContextA, lpInitializeSecurityContextHookA);
		InstallPrologueHook(lpInitializeSecurityContextW, lpInitializeSecurityContextHookW);

		if((hCrypt32Module = LoadLibrary(L"crypt32.dll")) == NULL)
		{
			throw std::exception("LoadLibrary(\"crypt32.dll\") Failed.");
		}

		if((fpCertVerifyCertificateChainPolicy = GetProcAddress(hCrypt32Module, "CertVerifyCertificateChainPolicy")) == NULL)
		{
			throw std::exception("GetProcAddress(\"CertVerifyCertificateChainPolicy\") Failed.");
		}

		unsigned char *lpCertVerifyCertificateChainPolicy = reinterpret_cast<unsigned char *>(fpCertVerifyCertificateChainPolicy);
		unsigned char *lpCertVerifyCertificateChainPolicyHook = reinterpret_cast<unsigned char *>(CertVerifyCertificateChainPolicyHook);
		
		InstallPrologueHook(lpCertVerifyCertificateChainPolicy, lpCertVerifyCertificateChainPolicyHook);
	}
	catch(const std::exception &e)
	{
		MessageBoxA(NULL, e.what(), "IeSwitchSsl Error", MB_ICONEXCLAMATION);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SspiHook::UninstallHooks()
{
	HMODULE hSecur32Module;
	FARPROC fpAcquireCredentialsHandleA;
	FARPROC fpAcquireCredentialsHandleW;
	FARPROC fpInitializeSecurityContextA;
	FARPROC fpInitializeSecurityContextW;

	try
	{
		if((hSecur32Module = GetModuleHandle(L"secur32.dll")) == NULL)
		{
			throw std::exception("secur32.dll Not Loaded By Process.");
		}

		if((fpAcquireCredentialsHandleA = GetProcAddress(hSecur32Module, "AcquireCredentialsHandleA")) == NULL)
		{
			throw std::exception("GetProcAddress(\"AcquireCredentialsHandleA\") Failed.");
		}

		if((fpAcquireCredentialsHandleW = GetProcAddress(hSecur32Module, "AcquireCredentialsHandleW")) == NULL)
		{
			throw std::exception("GetProcAddress(\"AcquireCredentialsHandleW\") Failed.");
		}

		if((fpInitializeSecurityContextA = GetProcAddress(hSecur32Module, "InitializeSecurityContextA")) == NULL)
		{
			throw std::exception("GetProcAddress(\"InitializeSecurityContextA\") Failed.");
		}

		if((fpInitializeSecurityContextW = GetProcAddress(hSecur32Module, "InitializeSecurityContextW")) == NULL)
		{
			throw std::exception("GetProcAddress(\"InitializeSecurityContextW\") Failed.");
		}

		unsigned char *lpAcquireCredentialsHandleA = reinterpret_cast<unsigned char *>(fpAcquireCredentialsHandleA);
		unsigned char *lpAcquireCredentialsHandleW = reinterpret_cast<unsigned char *>(fpAcquireCredentialsHandleW);
		unsigned char *lpAcquireCredentialsHandleHookA = reinterpret_cast<unsigned char *>(AcquireCredentialsHandleHookA);
		unsigned char *lpAcquireCredentialsHandleHookW = reinterpret_cast<unsigned char *>(AcquireCredentialsHandleHookW);
		
		UninstallPrologueHook(lpAcquireCredentialsHandleA, lpAcquireCredentialsHandleHookA);
		UninstallPrologueHook(lpAcquireCredentialsHandleW, lpAcquireCredentialsHandleHookW);
		
		unsigned char *lpInitializeSecurityContextA = reinterpret_cast<unsigned char *>(fpInitializeSecurityContextA);
		unsigned char *lpInitializeSecurityContextW = reinterpret_cast<unsigned char *>(fpInitializeSecurityContextW);
		unsigned char *lpInitializeSecurityContextHookA = reinterpret_cast<unsigned char *>(InitializeSecurityContextHookA);
		unsigned char *lpInitializeSecurityContextHookW = reinterpret_cast<unsigned char *>(InitializeSecurityContextHookW);

		UninstallPrologueHook(lpInitializeSecurityContextA, lpInitializeSecurityContextHookA);
		UninstallPrologueHook(lpInitializeSecurityContextW, lpInitializeSecurityContextHookW);
	}
	catch(const std::exception &e)
	{
		MessageBoxA(NULL, e.what(), "IeSwitchSsl Error", MB_ICONEXCLAMATION);
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SspiHook::InstallPrologueHook(unsigned char *lpFunction, unsigned char *lpHook)
{
	DWORD dwOldFunctionProtection;
	DWORD dwOldHookProtection;
	
	if(!VirtualProtect(lpFunction, 4096, PAGE_EXECUTE_READWRITE, &dwOldFunctionProtection))
	{
		throw std::exception("VirtualProtect() Failed.");
	}

	if(!VirtualProtect(lpHook, 4096, PAGE_EXECUTE_READWRITE, &dwOldHookProtection))
	{
		throw std::exception("VirtualProtect() Failed.");
	}

	lpFunction[0] = 0xE9;
	DWORD *pFunctionHookRel32 = reinterpret_cast<DWORD *>(&lpFunction[1]);
	*pFunctionHookRel32 = static_cast<DWORD>(lpHook -
													 reinterpret_cast<unsigned char *>(pFunctionHookRel32) - 4);
	
	while(true)
	{
		if((lpHook[0] == 0xE9) &&
		   (lpHook[1] == 0x90) &&
		   (lpHook[2] == 0x90) &&
		   (lpHook[3] == 0x90) &&
		   (lpHook[4] == 0x90))
		{
			DWORD *pFunctionRel32 = reinterpret_cast<DWORD *>(&lpHook[1]);
			*pFunctionRel32 = static_cast<DWORD>((lpFunction + 5) - 
														 reinterpret_cast<unsigned char *>(pFunctionRel32) - 4);
			break;
		}
		lpHook++;
	}

	if(!VirtualProtect(lpFunction, 4096, dwOldFunctionProtection, &dwOldFunctionProtection))
	{
		throw std::exception("VirtualProtect() Failed.");
	}

	if(!VirtualProtect(lpHook, 4096, dwOldHookProtection, &dwOldHookProtection))
	{
		throw std::exception("VirtualProtect() Failed.");
	}

	FlushInstructionCache(GetCurrentProcess(), lpFunction, 4096);
	FlushInstructionCache(GetCurrentProcess(), lpHook, 4096);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SspiHook::InstallEpilogueHook(unsigned char *lpFunction, unsigned char *lpHook)
{
	DWORD dwOldFunctionProtection;

	if(!VirtualProtect(lpFunction, 4096, PAGE_EXECUTE_READWRITE, &dwOldFunctionProtection))
	{
		throw std::exception("VirtualProtect() Failed.");
	}

	while(true)
	{
		if((lpFunction[0] == 0x5E) &&
		   (lpFunction[1] == 0xC9) &&
		   (lpFunction[2] == 0xC2) &&
		   (lpFunction[3] == 0x10) &&
		   (lpFunction[4] == 0x00))
		{
			lpFunction[0] = 0xE9;

			DWORD *pHookRel32 = reinterpret_cast<DWORD *>(&lpFunction[1]);
			*pHookRel32 = static_cast<DWORD>(lpHook -
											 reinterpret_cast<unsigned char *>(pHookRel32) - 4);

			break;
		}
		lpFunction++;
	}

	if(!VirtualProtect(lpFunction, 4096, dwOldFunctionProtection, &dwOldFunctionProtection))
	{
		throw std::exception("VirtualProtect() Failed.");
	}

	FlushInstructionCache(GetCurrentProcess(), lpFunction, 4096);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void SspiHook::UninstallPrologueHook(unsigned char *lpFunction, unsigned char *lpHook)
{
	DWORD dwOldFunctionProtection;
	DWORD dwOldHookProtection;
	
	if(!VirtualProtect(lpFunction, 4096, PAGE_EXECUTE_READWRITE, &dwOldFunctionProtection))
	{
		throw std::exception("VirtualProtect() Failed.");
	}

	if(!VirtualProtect(lpHook, 4096, PAGE_EXECUTE_READWRITE, &dwOldHookProtection))
	{
		throw std::exception("VirtualProtect() Failed.");
	}

	lpFunction[0] = 0x8B;
	lpFunction[1] = 0xFF;
	lpFunction[2] = 0x55;
	lpFunction[3] = 0x8B;
	lpFunction[4] = 0xEC;
	lpFunction[5] = 0x6A;

	while(true)
	{
		if(lpHook[0] == 0xE9)
		{
			DWORD *pFunctionRel32 = reinterpret_cast<DWORD *>(&lpHook[1]);
			DWORD dwJmpOffset = static_cast<DWORD>((lpFunction + 5) - reinterpret_cast<unsigned char *>(pFunctionRel32) - 4);

			if((lpHook[1] == (dwJmpOffset & 0x000000FF)) &&
			   (lpHook[2] == ((dwJmpOffset & 0x0000FF00) >> 8)) &&
			   (lpHook[3] == ((dwJmpOffset & 0x00FF0000) >> 16)) &&
			   (lpHook[4] == ((dwJmpOffset & 0xFF000000) >> 24)))
			{
				*pFunctionRel32 = 0x90909090;
				break;
			}
		}
		lpHook++;
	}

	if(!VirtualProtect(lpFunction, 4096, dwOldFunctionProtection, &dwOldFunctionProtection))
	{
		throw std::exception("VirtualProtect() Failed.");
	}

	if(!VirtualProtect(lpHook, 4096, dwOldHookProtection, &dwOldHookProtection))
	{
		throw std::exception("VirtualProtect() Failed.");
	}

	FlushInstructionCache(GetCurrentProcess(), lpFunction, 4096);
	FlushInstructionCache(GetCurrentProcess(), lpHook, 4096);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
