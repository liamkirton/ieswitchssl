////////////////////////////////////////////////////////////////////////////////////////////////////
// IeSwitchSsl
//
// Copyright ©2008 Liam Kirton <liam@int3.ws>
////////////////////////////////////////////////////////////////////////////////////////////////////
// IeSwitchSslBand.cpp
//
// Created: 15/02/2008
////////////////////////////////////////////////////////////////////////////////////////////////////

#include "IeSwitchSslBand.h"

#include <shlwapi.h>
#include <strsafe.h>
#include <uxtheme.h>
#include <vssym32.h>
#include <wininet.h>

#include "Resources.h"

////////////////////////////////////////////////////////////////////////////////////////////////////

IeSwitchSslBand::IeSwitchSslBand()
{
	InterlockedIncrement(reinterpret_cast<volatile LONG *>(&g_DllRefCount));

	dwBandID_ = -1;
	dwObjRefCount_ = 1;

	site_ = NULL;

	hWndParent_ = NULL;
	hWnd_ = NULL;
	hWndToolbar_ = NULL;

	hTheme_ = NULL;
	hImageList_ = NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

IeSwitchSslBand::~IeSwitchSslBand()
{
	InterlockedDecrement(reinterpret_cast<volatile LONG *>(&g_DllRefCount));
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::QueryInterface(REFIID riid, LPVOID *ppReturn)
{
	*ppReturn = NULL;

	HRESULT hResult = E_NOINTERFACE;

	if(IsEqualIID(riid, IID_IUnknown))
	{
		*ppReturn = this;
	}
	else if (IsEqualIID(riid, IID_IOleWindow))
	{
		*ppReturn = dynamic_cast<IOleWindow *>(this);
	}
	else if (IsEqualIID(riid, IID_IDockingWindow))
	{
		*ppReturn = dynamic_cast<IDockingWindow *>(this);
	}
	else if (IsEqualIID(riid, IID_IDeskBand))
	{
		*ppReturn = dynamic_cast<IDeskBand *>(this);
	}
	else if (IsEqualIID(riid, IID_IInputObject))
	{
		*ppReturn = dynamic_cast<IInputObject *>(this);
	}
	else if (IsEqualIID(riid, IID_IObjectWithSite))
	{
		*ppReturn = dynamic_cast<IObjectWithSite *>(this);
	}
	else if (IsEqualIID(riid, IID_IPersist))
	{
		*ppReturn = dynamic_cast<IPersist *>(this);
	}
	else if (IsEqualIID(riid, IID_IPersistStream))
	{
		*ppReturn = dynamic_cast<IPersistStream *>(this);
	}

	if(*ppReturn != NULL)
	{
		AddRef();
		hResult = S_OK;
	}
	
	return hResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP_(DWORD) IeSwitchSslBand::AddRef()
{
	return InterlockedIncrement(reinterpret_cast<volatile LONG *>(&dwObjRefCount_));
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP_(DWORD) IeSwitchSslBand::Release()
{
	if(InterlockedDecrement(reinterpret_cast<volatile LONG *>(&dwObjRefCount_)) == 0)
	{
		delete this;
		return 0;
	}
	return dwObjRefCount_;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::ContextSensitiveHelp(BOOL fEnterMode)
{
	return E_NOTIMPL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::GetWindow(HWND *phwnd)
{
	*phwnd = hWnd_;
	return S_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::CloseDW(DWORD dwReserved)
{
	return S_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::ResizeBorderDW(LPCRECT prcBorder, IUnknown* punkToolbarSite, BOOL fReserved)
{
	return E_NOTIMPL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::ShowDW(BOOL bShow)
{
	if(bShow)
	{
		ShowWindow(hWnd_, SW_SHOW);
	}
	else
	{
		ShowWindow(hWnd_, SW_HIDE);
	}
	return S_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::GetBandInfo(DWORD dwBandID, DWORD dwViewMode, DESKBANDINFO* pdbi)
{
	HRESULT hResult = E_INVALIDARG;

	dwBandID_ = dwBandID;
	
	if(pdbi != NULL)
	{
		if(pdbi->dwMask & DBIM_TITLE)
		{
			StringCchCopy(pdbi->wszTitle, sizeof(pdbi->wszTitle) / sizeof(WCHAR), L"Ssl");
		}
		if(pdbi->dwMask & DBIM_MINSIZE)
		{
			pdbi->ptMinSize.x = 0;
			pdbi->ptMinSize.y = 22;
		}
		if(pdbi->dwMask & DBIM_MAXSIZE)
		{
			pdbi->ptMaxSize.x = -1;
			pdbi->ptMaxSize.y = 22;
		}
		if(pdbi->dwMask & DBIM_INTEGRAL)
		{
			pdbi->ptIntegral.x = 1;
			pdbi->ptIntegral.y = 1;
		}
		if(pdbi->dwMask & DBIM_ACTUAL)
		{
			pdbi->ptActual.x = 0;
			pdbi->ptActual.y = 0;
		}
		if(pdbi->dwMask & DBIM_MODEFLAGS)
		{
			pdbi->dwModeFlags = DBIMF_NORMAL;
		}
		if(pdbi->dwMask & DBIM_BKCOLOR)
		{
			pdbi->dwMask &= ~DBIM_BKCOLOR;
		}
		hResult = S_OK;
	}

	return hResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::HasFocusIO()
{
	return S_FALSE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::TranslateAcceleratorIO(LPMSG lpMsg)
{
	return S_FALSE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::UIActivateIO(BOOL fActivate, LPMSG lpMsg)
{
	if(hWnd_ != NULL)
	{
		SetFocus(hWnd_);
	}
	return S_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::SetSite(IUnknown* pUnkSite)
{
	HRESULT hResult = S_OK;

	if(site_ != NULL)
	{
		site_->Release();
		site_ = NULL;
	}

	if(pUnkSite != NULL)
	{
		hWndParent_ = NULL;

		IOleWindow *pParentOleWindow;
		if(SUCCEEDED(pUnkSite->QueryInterface(IID_IOleWindow, reinterpret_cast<LPVOID *>(&pParentOleWindow))))
		{
			pParentOleWindow->GetWindow(&hWndParent_);
			pParentOleWindow->Release();
			pParentOleWindow = NULL;
		}

		if(!SUCCEEDED(pUnkSite->QueryInterface(IID_IInputObjectSite,
											   reinterpret_cast<LPVOID *>(&site_))))
		{
			hResult = E_FAIL;
		}

		hResult = CreateIeSwitchSslWindow();
	}

	return S_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::GetSite(REFIID riid, void** ppvSite)
{
	HRESULT hResult = E_FAIL;

	*ppvSite = NULL;

	if(site_ != NULL)
	{
		hResult = site_->QueryInterface(riid, ppvSite);
	}

	return hResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::GetClassID(CLSID *pClassID)
{
	*pClassID = CLSID_IeSwitchSslBand;
	return S_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::IsDirty()
{
	return S_FALSE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::Load(IStream *pStm)
{
	return E_NOTIMPL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::Save(IStream *pStm, BOOL fClearDirty)
{
	return E_NOTIMPL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

STDMETHODIMP IeSwitchSslBand::GetSizeMax(ULARGE_INTEGER *pcbSize)
{
	return E_NOTIMPL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void IeSwitchSslBand::GetStatus()
{
	protocolsText_ = L"";
	ciphersText_ = L"";
	algorithmsText_ = L"";

	switch(SspiHook::GetInstance().dwProtocols_)
	{
	case 0:
		protocolsText_ = L"Any";
		break;
	case SP_PROT_SSL2_CLIENT:
		protocolsText_ = L"SSLv2";
		break;
	case SP_PROT_SSL3_CLIENT:
		protocolsText_ = L"SSLv3";
		break;
	case SP_PROT_TLS1_CLIENT:
		protocolsText_ = L"TLSv1";
		break;
	}

	switch(SspiHook::GetInstance().dwCiphers_)
	{
	case 0:
		ciphersText_ = L"Any";
		break;
	case 40:
		ciphersText_ = L"40bit";
		break;
	case 56:
		ciphersText_ = L"56bit";
		break;
	case 128:
		ciphersText_ = L"128bit";
		break;
	case 256:
		ciphersText_ = L"256bit";
		break;
	}

	switch(SspiHook::GetInstance().supportedAlgorithms_.size())
	{
	case 0:
		algorithmsText_ = L"Any";
		break;
	default:
		algorithmsText_ = L"Restrictions";
		break;
	}

	TBBUTTONINFO tbButtonInfo;
	SecureZeroMemory(&tbButtonInfo, sizeof(TBBUTTONINFO));
	tbButtonInfo.cbSize = sizeof(TBBUTTONINFO);
	tbButtonInfo.dwMask = TBIF_TEXT;
	tbButtonInfo.pszText = const_cast<LPWSTR>(protocolsText_.c_str());
	SendMessage(hWndToolbar_, TB_SETBUTTONINFO, 1, reinterpret_cast<LPARAM>(&tbButtonInfo));
	SendMessage(hWndToolbar_, TB_SETSTATE, 1, MAKELONG(SspiHook::GetInstance().bHook_ ? TBSTATE_ENABLED : 0, 0));

	tbButtonInfo.pszText = const_cast<LPWSTR>(ciphersText_.c_str());
	SendMessage(hWndToolbar_, TB_SETBUTTONINFO, 2, reinterpret_cast<LPARAM>(&tbButtonInfo));
	SendMessage(hWndToolbar_, TB_SETSTATE, 2, MAKELONG(SspiHook::GetInstance().bHook_ ? TBSTATE_ENABLED : 0, 0));

	tbButtonInfo.pszText = const_cast<LPWSTR>(algorithmsText_.c_str());
	SendMessage(hWndToolbar_, TB_SETBUTTONINFO, 3, reinterpret_cast<LPARAM>(&tbButtonInfo));
	SendMessage(hWndToolbar_, TB_SETSTATE, 3, MAKELONG(SspiHook::GetInstance().bHook_ ? TBSTATE_ENABLED : 0, 0));

	SecureZeroMemory(&tbButtonInfo, sizeof(TBBUTTONINFO));
	tbButtonInfo.cbSize = sizeof(TBBUTTONINFO);
	tbButtonInfo.dwMask = TBIF_IMAGE | TBIF_STATE | TBIF_TEXT;
	tbButtonInfo.fsState = TBSTATE_ENABLED | (SspiHook::GetInstance().bHook_ ? TBSTATE_CHECKED : 0);
	tbButtonInfo.iImage = SspiHook::GetInstance().bHook_ ? 1 : 0;
	tbButtonInfo.pszText = SspiHook::GetInstance().bHook_ ? L"On" : L"Off";
	SendMessage(hWndToolbar_, TB_SETBUTTONINFO, 0, reinterpret_cast<LPARAM>(&tbButtonInfo));
	
	SecureZeroMemory(&tbButtonInfo, sizeof(TBBUTTONINFO));
	tbButtonInfo.cbSize = sizeof(TBBUTTONINFO);
	tbButtonInfo.dwMask = TBIF_STATE;
	tbButtonInfo.fsState = (SspiHook::GetInstance().bHook_ ? TBSTATE_ENABLED : 0) | (SspiHook::GetInstance().bCertVerification_ ? TBSTATE_CHECKED : 0);
	SendMessage(hWndToolbar_, TB_SETBUTTONINFO, 4, reinterpret_cast<LPARAM>(&tbButtonInfo));
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void IeSwitchSslBand::SetSslProtocols()
{
	HMENU hMenu = CreatePopupMenu();

	std::wstring protocolStrings[4];
	protocolStrings[0] = L"&1. Any";
	protocolStrings[1] = L"&2. SSLv2";
	protocolStrings[2] = L"&3. SSLv3";
	protocolStrings[3] = L"&4. TLSv1";

	MENUITEMINFO menuItemInfo[4];
	SecureZeroMemory(&menuItemInfo, sizeof(menuItemInfo));
	
	for(int i = 0; i < sizeof(menuItemInfo) / sizeof(MENUITEMINFO); ++i)
	{
		menuItemInfo[i].cbSize = sizeof(MENUITEMINFO);
		menuItemInfo[i].fMask = MIIM_TYPE | MIIM_STATE | MIIM_ID;
		menuItemInfo[i].fType = MFT_STRING;
		menuItemInfo[i].fState = MFS_ENABLED;
		menuItemInfo[i].wID = i + 1;
		menuItemInfo[i].dwTypeData = const_cast<LPWSTR>(protocolStrings[i].c_str());
		InsertMenuItem(hMenu, i + 1, false, &menuItemInfo[i]);
	}
		
	POINT cursorPt;
	GetCursorPos(&cursorPt);

	switch(TrackPopupMenu(hMenu,
						  TPM_RIGHTALIGN | TPM_NONOTIFY | TPM_RETURNCMD,
						  cursorPt.x,
						  cursorPt.y,
						  0,
						  hWnd_,
						  NULL))
	{
	case 1:
		SspiHook::GetInstance().dwProtocols_ = 0;
		break;
	case 2:
		SspiHook::GetInstance().dwProtocols_ = SP_PROT_SSL2_CLIENT;
		break;
	case 3:
		SspiHook::GetInstance().dwProtocols_ = SP_PROT_SSL3_CLIENT;
		break;
	case 4:
		SspiHook::GetInstance().dwProtocols_ = SP_PROT_TLS1_CLIENT;
		break;
	}

	DestroyMenu(hMenu);

	GetStatus();
	UpdateBroadcast(1);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void IeSwitchSslBand::SetSslCiphers()
{
	HMENU hMenu = CreatePopupMenu();

	std::wstring cipherStrings[5];
	cipherStrings[0] = L"&1. Any";
	cipherStrings[1] = L"&2. 40bit";
	cipherStrings[2] = L"&3. 56bit";
	cipherStrings[3] = L"&4. 128bit";
	cipherStrings[4] = L"&5. 256bit";

	MENUITEMINFO menuItemInfo[5];
	SecureZeroMemory(&menuItemInfo, sizeof(menuItemInfo));
	
	for(int i = 0; i < sizeof(menuItemInfo) / sizeof(MENUITEMINFO); ++i)
	{
		menuItemInfo[i].cbSize = sizeof(MENUITEMINFO);
		menuItemInfo[i].fMask = MIIM_TYPE | MIIM_STATE | MIIM_ID;
		menuItemInfo[i].fType = MFT_STRING;
		menuItemInfo[i].fState = MFS_ENABLED;
		menuItemInfo[i].wID = i + 1;
		menuItemInfo[i].dwTypeData = const_cast<LPWSTR>(cipherStrings[i].c_str());
		InsertMenuItem(hMenu, i + 1, false, &menuItemInfo[i]);
	}
		
	POINT cursorPt;
	GetCursorPos(&cursorPt);

	switch(TrackPopupMenu(hMenu,
						  TPM_RIGHTALIGN | TPM_NONOTIFY | TPM_RETURNCMD,
						  cursorPt.x,
						  cursorPt.y,
						  0,
						  hWnd_,
						  NULL))
	{
	case 1:
		SspiHook::GetInstance().dwCiphers_ = 0;
		break;
	case 2:
		SspiHook::GetInstance().dwCiphers_ = 40;
		break;
	case 3:
		SspiHook::GetInstance().dwCiphers_ = 56;
		break;
	case 4:
		SspiHook::GetInstance().dwCiphers_ = 128;
		break;
	case 5:
		SspiHook::GetInstance().dwCiphers_ = 256;
		break;
	}

	DestroyMenu(hMenu);

	GetStatus();
	UpdateBroadcast(1);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void IeSwitchSslBand::SetSslAlgorithms()
{
	HMENU hMenu = CreatePopupMenu();

	std::wstring algorithmStrings[17];
	MENUITEMINFO menuItemInfo[17];
	SecureZeroMemory(&menuItemInfo, sizeof(menuItemInfo));

	algorithmStrings[0] = L"&1. No Restrictions";
	algorithmStrings[1] = L"Algorithms";
	algorithmStrings[2] = L"&2. AES (Not Supported)";
	algorithmStrings[3] = L"&3. DES";
	algorithmStrings[4] = L"&4. 3DES";
	algorithmStrings[5] = L"&5. RC2";
	algorithmStrings[6] = L"&6. RC4";
	algorithmStrings[7] = L"Hashing";
	algorithmStrings[8] = L"7. MD2";
	algorithmStrings[9] = L"8. MD5";
	algorithmStrings[10] = L"9. SHA1";
	algorithmStrings[11] = L"10. SSL3 SHAMD5";
	algorithmStrings[12] = L"Key Exchange and Signing";
	algorithmStrings[13] = L"11. RSA Key Exchange";
	algorithmStrings[14] = L"12. RSA Signing";
	algorithmStrings[15] = L"13. DH Ephemeral";
	algorithmStrings[16] = L"14. DH Store and Forward";
	
	for(int i = 0; i < sizeof(menuItemInfo) / sizeof(MENUITEMINFO); ++i)
	{
		menuItemInfo[i].cbSize = sizeof(MENUITEMINFO);
		menuItemInfo[i].fMask = MIIM_TYPE | MIIM_STATE | MIIM_ID;
		menuItemInfo[i].fType = MFT_STRING;
		menuItemInfo[i].fState = MFS_ENABLED;
		menuItemInfo[i].wID = i + 1;
		menuItemInfo[i].dwTypeData = const_cast<LPWSTR>(algorithmStrings[i].c_str());
		InsertMenuItem(hMenu, i + 1, false, &menuItemInfo[i]);
	}

	SspiHook &sspiHook = SspiHook::GetInstance();
	if(sspiHook.supportedAlgorithms_.size() == 0)
	{
		CheckMenuItem(hMenu, 1, MF_CHECKED);
	}
	else
	{
		for(std::vector<ALG_ID>::iterator i = sspiHook.supportedAlgorithms_.begin(); i != sspiHook.supportedAlgorithms_.end(); ++i)
		{
			switch(*i)
			{
			case CALG_AES:
				CheckMenuItem(hMenu, 3, MF_CHECKED);
				break;
			case CALG_DES:
				CheckMenuItem(hMenu, 4, MF_CHECKED);
				break;
			case CALG_3DES:
				CheckMenuItem(hMenu, 5, MF_CHECKED);
				break;
			case CALG_RC2:
				CheckMenuItem(hMenu, 6, MF_CHECKED);
				break;
			case CALG_RC4:
				CheckMenuItem(hMenu, 7, MF_CHECKED);
				break;
			case CALG_MD2:
				CheckMenuItem(hMenu, 9, MF_CHECKED);
				break;
			case CALG_MD5:
				CheckMenuItem(hMenu, 10, MF_CHECKED);
				break;
			case CALG_SHA1:
				CheckMenuItem(hMenu, 11, MF_CHECKED);
				break;
			case CALG_SSL3_SHAMD5:
				CheckMenuItem(hMenu, 12, MF_CHECKED);
				break;
			case CALG_RSA_KEYX:
				CheckMenuItem(hMenu, 14, MF_CHECKED);
				break;
			case CALG_RSA_SIGN:
				CheckMenuItem(hMenu, 15, MF_CHECKED);
				break;
			case CALG_DH_EPHEM:
				CheckMenuItem(hMenu, 16, MF_CHECKED);
				break;
			case CALG_DH_SF:
				CheckMenuItem(hMenu, 17, MF_CHECKED);
				break;
			}
		}
	}

	EnableMenuItem(hMenu, 2, MFS_DISABLED);
	EnableMenuItem(hMenu, 3, MFS_DISABLED);
	EnableMenuItem(hMenu, 8, MFS_DISABLED);
	EnableMenuItem(hMenu, 13, MFS_DISABLED);
		
	POINT cursorPt;
	GetCursorPos(&cursorPt);

	ALG_ID toAdd = 0;
	ALG_ID toRemove = 0;

	switch(TrackPopupMenu(hMenu,
						  TPM_RIGHTALIGN | TPM_NONOTIFY | TPM_RETURNCMD,
						  cursorPt.x,
						  cursorPt.y,
						  0,
						  hWnd_,
						  NULL))
	{
	case 1:
		sspiHook.supportedAlgorithms_.clear();
		break;
	case 3:
		(GetMenuState(hMenu, 3, 0) & MF_CHECKED) ? toRemove = CALG_AES : toAdd = CALG_AES;
		break;
	case 4:
		(GetMenuState(hMenu, 4, 0) & MF_CHECKED) ? toRemove = CALG_DES : toAdd = CALG_DES;
		break;
	case 5:
		(GetMenuState(hMenu, 5, 0) & MF_CHECKED) ? toRemove = CALG_3DES : toAdd = CALG_3DES;
		break;
	case 6:
		(GetMenuState(hMenu, 6, 0) & MF_CHECKED) ? toRemove = CALG_RC2 : toAdd = CALG_RC2;
		break;
	case 7:
		(GetMenuState(hMenu, 7, 0) & MF_CHECKED) ? toRemove = CALG_RC4 : toAdd = CALG_RC4;
		break;
	case 9:
		(GetMenuState(hMenu, 9, 0) & MF_CHECKED) ? toRemove = CALG_MD2 : toAdd = CALG_MD2;
		break;
	case 10:
		(GetMenuState(hMenu, 10, 0) & MF_CHECKED) ? toRemove = CALG_MD5 : toAdd = CALG_MD5;
		break;
	case 11:
		(GetMenuState(hMenu, 11, 0) & MF_CHECKED) ? toRemove = CALG_SHA1 : toAdd = CALG_SHA1;
		break;
	case 12:
		(GetMenuState(hMenu, 12, 0) & MF_CHECKED) ? toRemove = CALG_SSL3_SHAMD5 : toAdd = CALG_SSL3_SHAMD5;
		break;
	case 14:
		(GetMenuState(hMenu, 14, 0) & MF_CHECKED) ? toRemove = CALG_RSA_KEYX : toAdd = CALG_RSA_KEYX;
		break;
	case 15:
		(GetMenuState(hMenu, 15, 0) & MF_CHECKED) ? toRemove = CALG_RSA_SIGN : toAdd = CALG_RSA_SIGN;
		break;
	case 16:
		(GetMenuState(hMenu, 16, 0) & MF_CHECKED) ? toRemove = CALG_DH_EPHEM : toAdd = CALG_DH_EPHEM;
		break;
	case 17:
		(GetMenuState(hMenu, 17, 0) & MF_CHECKED) ? toRemove = CALG_DH_SF : toAdd = CALG_DH_SF;
		break;
	}

	if(toAdd != 0)
	{
		sspiHook.supportedAlgorithms_.push_back(toAdd);
	}
	else if(toRemove != 0)
	{
		for(std::vector<ALG_ID>::iterator i = sspiHook.supportedAlgorithms_.begin(); i != sspiHook.supportedAlgorithms_.end(); ++i)
		{
			if((*i) == toRemove)
			{
				sspiHook.supportedAlgorithms_.erase(i);
				break;
			}
		}
	}

	DestroyMenu(hMenu);

	GetStatus();
	UpdateBroadcast(1);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void IeSwitchSslBand::UpdateBroadcast(UINT code)
{
	EnumWindows(s_EnumWindowsProc, static_cast<LRESULT>(code));
}

////////////////////////////////////////////////////////////////////////////////////////////////////

void IeSwitchSslBand::CloseIeSwitchSslWindow()
{
	if(hWndToolbar_ != NULL)
	{
		DestroyWindow(hWndToolbar_);
		hWndToolbar_ = NULL;
	}
	if(hWnd_ != NULL)
	{
		SetWindowLongPtr(hWnd_, GWLP_USERDATA, NULL);
		DestroyWindow(hWnd_);
		hWnd_ = NULL;
	}
	if(hTheme_ != NULL)
	{
		CloseThemeData(hTheme_);
		hTheme_ = NULL;
	}
	if(hImageList_ != NULL)
	{
		ImageList_Destroy(hImageList_);
		hImageList_ = NULL;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////

HRESULT IeSwitchSslBand::CreateIeSwitchSslWindow()
{
	HRESULT hResult = S_OK;

	WNDCLASS wndClass;
	SecureZeroMemory(&wndClass, sizeof(WNDCLASS));

	wndClass.cbClsExtra = 0;
	wndClass.cbWndExtra = 0;
	wndClass.hbrBackground = static_cast<HBRUSH>(GetStockObject(WHITE_BRUSH));
	wndClass.hCursor = LoadCursor(NULL, IDC_ARROW);
	wndClass.hIcon = NULL;
	wndClass.hInstance = g_hInstance;
	wndClass.lpfnWndProc = IeSwitchSslBand::s_IeSwitchSslWindowProc;
	wndClass.lpszClassName = L"IeSwitchSsl";
	wndClass.lpszMenuName = NULL;
	wndClass.style = CS_HREDRAW | CS_VREDRAW | CS_GLOBALCLASS;
	
	if(!RegisterClass(&wndClass))
	{
		hResult = E_FAIL;
	}

	RECT parentRect;
	GetClientRect(hWndParent_, &parentRect);

	if(!CreateWindowEx(0,
					   L"IeSwitchSsl",
					   NULL,
					   WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
					   parentRect.left,
					   parentRect.top,
					   parentRect.right - parentRect.left,
					   parentRect.bottom - parentRect.top,
					   hWndParent_,
					   NULL,
					   g_hInstance,
					   reinterpret_cast<void *>(this)))
	{
		hResult = E_FAIL;
	}

	hTheme_ = OpenThemeData(hWnd_, L"ReBar");

	if((hWndToolbar_ = CreateWindowEx(0,
									  TOOLBARCLASSNAME,
									  NULL,
									  WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS |
									  TBSTYLE_FLAT | TBSTYLE_LIST |
									  CCS_NODIVIDER | CCS_NORESIZE,
									  parentRect.left,
									  parentRect.top,
									  parentRect.right - parentRect.left,
									  parentRect.bottom - parentRect.top,
									  hWnd_,
									  0,
									  g_hInstance,
									  NULL)) != NULL)
	{
		SendMessage(hWndToolbar_, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);
		ShowWindow(hWndToolbar_, SW_SHOWNORMAL);
	}
	else
	{
		hResult = E_FAIL;
	}

	hImageList_ = ImageList_Create(16, 16, ILC_COLOR24 | ILC_MASK, 7, 7);

	SecureZeroMemory(&tbButtons_, sizeof(tbButtons_));

	HBITMAP hBitmap = LoadBitmap(g_hInstance, MAKEINTRESOURCE(TBI_OFF));
	tbButtons_[0].iBitmap = ImageList_AddMasked(hImageList_, hBitmap, RGB(255, 0, 255));
	tbButtons_[0].idCommand = 0;
	tbButtons_[0].fsState = TBSTATE_ENABLED;
	tbButtons_[0].fsStyle = BTNS_BUTTON | BTNS_CHECK | BTNS_AUTOSIZE;
	tbButtons_[0].dwData = 0;
	tbButtons_[0].iString = NULL;
	hBitmap = LoadBitmap(g_hInstance, MAKEINTRESOURCE(TBI_ON));
	ImageList_AddMasked(hImageList_, hBitmap, RGB(255, 0, 255));
	
	hBitmap = LoadBitmap(g_hInstance, MAKEINTRESOURCE(TBI_PROTOCOLS));
	tbButtons_[1].iBitmap = ImageList_AddMasked(hImageList_, hBitmap, RGB(255, 0, 255));
	tbButtons_[1].idCommand = 1;
	tbButtons_[1].fsState = 0;
	tbButtons_[1].fsStyle = BTNS_BUTTON | BTNS_WHOLEDROPDOWN | BTNS_AUTOSIZE;
	tbButtons_[1].dwData = 0;
	tbButtons_[1].iString = reinterpret_cast<INT_PTR>(L"???");

	hBitmap = LoadBitmap(g_hInstance, MAKEINTRESOURCE(TBI_SSL));
	tbButtons_[2].iBitmap = ImageList_AddMasked(hImageList_, hBitmap, RGB(255, 0, 255));
	tbButtons_[2].idCommand = 2;
	tbButtons_[2].fsState = 0;
	tbButtons_[2].fsStyle = BTNS_BUTTON | BTNS_WHOLEDROPDOWN | BTNS_AUTOSIZE;
	tbButtons_[2].dwData = 0;
	tbButtons_[2].iString = reinterpret_cast<INT_PTR>(L"???");

	hBitmap = LoadBitmap(g_hInstance, MAKEINTRESOURCE(TBI_ALGS));
	tbButtons_[3].iBitmap = ImageList_AddMasked(hImageList_, hBitmap, RGB(255, 0, 255));
	tbButtons_[3].idCommand = 3;
	tbButtons_[3].fsState = 0;
	tbButtons_[3].fsStyle = BTNS_BUTTON | BTNS_WHOLEDROPDOWN | BTNS_AUTOSIZE;
	tbButtons_[3].dwData = 0;
	tbButtons_[3].iString = reinterpret_cast<INT_PTR>(L"???");

	hBitmap = LoadBitmap(g_hInstance, MAKEINTRESOURCE(TBI_CERTVERIFY));
	tbButtons_[4].iBitmap = ImageList_AddMasked(hImageList_, hBitmap, RGB(255, 0, 255));
	tbButtons_[4].idCommand = 4;
	tbButtons_[4].fsState = 0;
	tbButtons_[4].fsStyle = BTNS_BUTTON | BTNS_CHECK | BTNS_AUTOSIZE;
	tbButtons_[4].dwData = 0;
	tbButtons_[4].iString = reinterpret_cast<INT_PTR>(L"Certificate Verification");

	hBitmap = LoadBitmap(g_hInstance, MAKEINTRESOURCE(TBI_HELP));
	tbButtons_[5].iBitmap = ImageList_AddMasked(hImageList_, hBitmap, RGB(255, 0, 255));
	tbButtons_[5].idCommand = 5;
	tbButtons_[5].fsState = TBSTATE_ENABLED;
	tbButtons_[5].fsStyle = BTNS_BUTTON | BTNS_AUTOSIZE;
	tbButtons_[5].dwData = 0;
	tbButtons_[5].iString = reinterpret_cast<INT_PTR>(L"About");
	DeleteObject(hBitmap);	

	SendMessage(hWndToolbar_, TB_SETIMAGELIST, 0, reinterpret_cast<LPARAM>(hImageList_));
	SendMessage(hWndToolbar_, TB_ADDBUTTONS, sizeof(tbButtons_) / sizeof(TBBUTTON), reinterpret_cast<LPARAM>(&tbButtons_));
	SendMessage(hWndToolbar_, TB_AUTOSIZE, 0, 0);

	GetStatus();

	return hResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT IeSwitchSslBand::OnCommand(WPARAM wParam, LPARAM lParam)
{
	if(reinterpret_cast<HWND>(lParam) == hWndToolbar_)
	{
		switch(LOWORD(wParam))
		{
			case 0:
				{
					if(!SspiHook::GetInstance().bHook_)
					{
						SspiHook::GetInstance().bHook_ = SendMessage(hWndToolbar_, TB_ISBUTTONCHECKED, 0, 0) != 0 ? true : false;
					}
					else
					{
						MessageBox(hWnd_, L"Please close and restart Internet Explorer in order to disable SSL API manipulation.", L"IeSwitchSsl", MB_ICONEXCLAMATION);
					}

					GetStatus();
					UpdateBroadcast(1);
				}
				break;
			case 4:
				{
					SspiHook::GetInstance().bCertVerification_ = SendMessage(hWndToolbar_, TB_ISBUTTONCHECKED, 4, 0) != 0 ? true : false;
					
					GetStatus();
					UpdateBroadcast(1);
				}
				break;

			case 5:
				MessageBox(NULL,
						   L"IeSwitchSsl 0.3.1\nCopyright ©2008 Liam Kirton <liam@int3.ws>\n\nhttp://int3.ws/",
						   L"IeSwitchSsl",
						   MB_ICONINFORMATION);
				break;

			default:
				break;
		}
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT IeSwitchSslBand::OnEraseBackground(WPARAM wParam, LPARAM lParam)
{
	RECT clientRect;
	GetClientRect(hWnd_, &clientRect);

	HDC hDC = reinterpret_cast<HDC>(wParam);
	
	DrawThemeParentBackground(hWnd_, hDC, &clientRect);
	
	if(hTheme_ != NULL)
	{
		DrawThemeBackground(hTheme_, hDC, RP_BAND, 0, &clientRect, NULL);
	}
	
	return 1;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT IeSwitchSslBand::OnKillFocus(WPARAM wParam, LPARAM lParam)
{
	if(site_ != NULL)
	{
		site_->OnFocusChangeIS(dynamic_cast<IDockingWindow *>(this), false);
	}
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT IeSwitchSslBand::OnMove(WPARAM wParam, LPARAM lParam)
{
	InvalidateRect(hWnd_, NULL, TRUE);
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT IeSwitchSslBand::OnNotify(WPARAM wParam, LPARAM lParam)
{
	switch (reinterpret_cast<LPNMHDR>(lParam)->code)
	{
		case TBN_DROPDOWN:
			{
				switch(reinterpret_cast<NMTOOLBAR *>(lParam)->iItem)
				{
				case 1:
					SetSslProtocols();
					break;

				case 2:
					SetSslCiphers();
					break;

				case 3:
					SetSslAlgorithms();
					break;
				}
			}
			return TBDDRET_DEFAULT;

		default:
			break;
	}

	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT IeSwitchSslBand::OnPaint(WPARAM wParam, LPARAM lParam)
{
	PAINTSTRUCT paintStruct;
	HDC hDC;
	
	hDC = BeginPaint(hWnd_, &paintStruct);
	EndPaint(hWnd_, &paintStruct);
	
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT IeSwitchSslBand::OnSetFocus(WPARAM wParam, LPARAM lParam)
{
	if(site_ != NULL)
    {
		site_->OnFocusChangeIS(dynamic_cast<IDockingWindow *>(this), true);
    }
	return 0;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

LRESULT CALLBACK IeSwitchSslBand::s_IeSwitchSslWindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	IeSwitchSslBand *pIeSwitchSslBand = reinterpret_cast<IeSwitchSslBand *>(GetWindowLongPtr(hWnd, GWL_USERDATA));

	switch(uMsg)
	{
		case WM_NCCREATE:
			{
				LPCREATESTRUCT lpCreateStruct = reinterpret_cast<LPCREATESTRUCT>(lParam);
				pIeSwitchSslBand = reinterpret_cast<IeSwitchSslBand *>(lpCreateStruct->lpCreateParams);
				SetWindowLongPtr(hWnd, GWL_USERDATA, reinterpret_cast<LONG_PTR>(pIeSwitchSslBand));
				pIeSwitchSslBand->hWnd_ = hWnd;
			}
			break;

		case WM_COMMAND:
			if(pIeSwitchSslBand != NULL)
			{
				return pIeSwitchSslBand->OnCommand(wParam, lParam);
			}
			break;

		case WM_ERASEBKGND:
			if(pIeSwitchSslBand != NULL)
			{
				return pIeSwitchSslBand->OnEraseBackground(wParam, lParam);
			}
			break;

		case WM_KILLFOCUS:
			if(pIeSwitchSslBand != NULL)
			{
				return pIeSwitchSslBand->OnKillFocus(wParam, lParam);
			}
			break;

		case WM_MOVE:
			if(pIeSwitchSslBand != NULL)
			{
				return pIeSwitchSslBand->OnMove(wParam, lParam);
			}
			break;

		case WM_NOTIFY:
			if(pIeSwitchSslBand != NULL)
			{
				return pIeSwitchSslBand->OnNotify(wParam, lParam);
			}
			break;

		case WM_PAINT:
			if(pIeSwitchSslBand != NULL)
			{
				return pIeSwitchSslBand->OnPaint(wParam, lParam);
			}
			break;

		case WM_SETFOCUS:
			if(pIeSwitchSslBand != NULL)
			{
				return pIeSwitchSslBand->OnSetFocus(wParam, lParam);
			}
			break;

		case WM_SIZE:
			if((pIeSwitchSslBand != NULL) && (pIeSwitchSslBand->hWndToolbar_ != NULL))
			{
				SetWindowPos(pIeSwitchSslBand->hWndToolbar_, NULL, 0, 0, LOWORD(lParam), HIWORD(lParam), 0);
			}
			break;

		case WM_THEMECHANGED:
			if(pIeSwitchSslBand != NULL)
			{
				if(pIeSwitchSslBand->hTheme_ != NULL)
				{
					CloseThemeData(pIeSwitchSslBand->hTheme_);
					pIeSwitchSslBand->hTheme_ = NULL;
				}
				pIeSwitchSslBand->hTheme_ = OpenThemeData(pIeSwitchSslBand->hWnd_, L"ReBar");
			}
			break;

		case WM_USER + 1:
			pIeSwitchSslBand->GetStatus();
			break;

		default:
			break;
	}

	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL CALLBACK IeSwitchSslBand::s_EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
	EnumChildWindows(hWnd, s_EnumChildWindowsProc, lParam);
	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL CALLBACK IeSwitchSslBand::s_EnumChildWindowsProc(HWND hWnd, LPARAM lParam)
{
	wchar_t wndClassName[1024];
	GetClassName(hWnd, wndClassName, 1023);
	
	if(lstrcmpW(L"IeSwitchSsl", wndClassName) == 0)
	{
		PostMessage(hWnd, WM_USER + static_cast<UINT>(lParam), 0, 0);
	}

	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
