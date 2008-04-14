////////////////////////////////////////////////////////////////////////////////////////////////////
// IeSwitchSsl
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// IeSwitchSsl.cpp
//
// Created: 15/02/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#include <windows.h>
#include <shlwapi.h>

#include <exception>

#include "ClassFactory.h"
#include "IeSwitchSsl.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

UINT g_DllRefCount = 0;
HINSTANCE g_hInstance = NULL;

////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpvReserved)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			INITCOMMONCONTROLSEX ex;
			ex.dwSize = sizeof(INITCOMMONCONTROLSEX);
			ex.dwICC = ICC_COOL_CLASSES | ICC_WIN95_CLASSES;
			InitCommonControlsEx(&ex);

			g_DllRefCount = 0;
			g_hInstance = hInstance;
			
			break;

		case DLL_PROCESS_DETACH:
			break;
	}
	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDAPI DllCanUnloadNow()
{
	return S_FALSE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppReturn)
{
	HRESULT hResult = CLASS_E_CLASSNOTAVAILABLE;
	
	*ppReturn = NULL;

	if(IsEqualCLSID(rclsid, CLSID_IeSwitchSslBand))
	{
		ClassFactory *pClassFactory = new ClassFactory(rclsid);
		hResult = pClassFactory->QueryInterface(riid, ppReturn);
		pClassFactory->Release();
	}

	return hResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDAPI DllRegisterServer()
{
	HRESULT hResult = S_OK;
	
	HKEY hKey = NULL;
	HKEY hKeyBand = NULL;
	HKEY hKeyInProcServer = NULL;
	HKEY hKeyIeToolbar = NULL;

	LPOLESTR pClsidStr = NULL;

	try
	{
		if(RegOpenKeyEx(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
		{
			throw std::exception("RegOpenKeyEx() Failed.");
		}

		if(StringFromCLSID(CLSID_IeSwitchSslBand, &pClsidStr) != S_OK)
		{
			throw std::exception("StringFromCLSID() Failed.");
		}

		if(RegCreateKeyEx(hKey,
						  reinterpret_cast<wchar_t *>(pClsidStr),
						  0,
						  NULL,
						  REG_OPTION_NON_VOLATILE,
						  KEY_ALL_ACCESS,
						  NULL,
						  &hKeyBand,
						  NULL) != ERROR_SUCCESS)
		{
			throw std::exception("RegCreateKeyEx() Failed.");
		}

		wchar_t *hKeyValue = L"IeSwitchSsl";
		if(RegSetValueEx(hKeyBand,
						 NULL,
						 0,
						 REG_SZ,
						 reinterpret_cast<const BYTE *>(hKeyValue),
						 11 * sizeof(wchar_t)) != ERROR_SUCCESS)
		{
			throw std::exception("RegSetValueEx() Failed.");
		}

		if(RegCreateKeyEx(hKeyBand,
						  L"InProcServer32",
						  0,
						  NULL,
						  REG_OPTION_NON_VOLATILE,
						  KEY_ALL_ACCESS,
						  NULL,
						  &hKeyInProcServer,
						  NULL) != ERROR_SUCCESS)
		{
			throw std::exception("RegCreateKeyEx() Failed.");
		}

		wchar_t moduleFileName[1024];
		GetModuleFileName(g_hInstance, moduleFileName, sizeof(moduleFileName) / sizeof(wchar_t));

		if(RegSetValueEx(hKeyInProcServer,
						 L"",
						 0,
						 REG_SZ,
						 reinterpret_cast<const BYTE *>(&moduleFileName),
						 lstrlenW(moduleFileName) * sizeof(wchar_t)) != ERROR_SUCCESS)
		{
			throw std::exception("RegSetValueEx() Failed.");
		}

		wchar_t *threadingModelValue = L"Apartment";
		if(RegSetValueEx(hKeyInProcServer,
						 L"ThreadingModel",
						 0,
						 REG_SZ,
						 reinterpret_cast<const BYTE *>(threadingModelValue),
						 10 * sizeof(wchar_t)) != ERROR_SUCCESS)
		{
			throw std::exception("RegSetValueEx() Failed.");
		}

		if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
						L"SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar",
						0,
						KEY_ALL_ACCESS,
						&hKeyIeToolbar) != ERROR_SUCCESS)
		{
			throw std::exception("RegOpenKeyEx() Failed.");
		}

		wchar_t *toolbarClsidValue = L"";
		if(RegSetValueEx(hKeyIeToolbar,
						 pClsidStr,
						 0,
						 REG_SZ,
						 reinterpret_cast<const BYTE *>(toolbarClsidValue),
						 1 * sizeof(wchar_t)) != ERROR_SUCCESS)
		{
			throw std::exception("RegSetValueEx() Failed.");
		}
	}
	catch(const std::exception &)
	{
		hResult = E_FAIL;
	}

	if(hKey != NULL)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}
	if(hKeyBand != NULL)
	{
		RegCloseKey(hKeyBand);
		hKeyBand = NULL;
	}
	if(hKeyInProcServer != NULL)
	{
		RegCloseKey(hKeyInProcServer);
		hKeyInProcServer = NULL;
	}
	if(hKeyIeToolbar != NULL)
	{
		RegCloseKey(hKeyIeToolbar);
		hKeyIeToolbar = NULL;
	}

	if(pClsidStr != NULL)
	{
		CoTaskMemFree(pClsidStr);
		pClsidStr = NULL;
	}

	return hResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDAPI DllUnregisterServer()
{
	HRESULT hResult = S_OK;

	LPOLESTR pClsidStr = NULL;
	if(StringFromCLSID(CLSID_IeSwitchSslBand, &pClsidStr) == S_OK)
	{
		HKEY hKey;
		if(RegOpenKeyEx(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
		{
			SHDeleteKey(hKey, pClsidStr);
			RegCloseKey(hKey);
			hKey = NULL;
		}
		
		if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,
						L"SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar",
						0,
						KEY_ALL_ACCESS,
						&hKey) == ERROR_SUCCESS)
		{
			RegDeleteValue(hKey, pClsidStr);
			RegCloseKey(hKey);
			hKey = NULL;
		}

		CoTaskMemFree(pClsidStr);
		pClsidStr = NULL;

		if(RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\int3.ws", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
		{
			SHDeleteKey(hKey, L"IeSwitchSsl");
			RegCloseKey(hKey);
			hKey = NULL;
		}
	}
	else
	{
		hResult = E_FAIL;
	}

	return hResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
