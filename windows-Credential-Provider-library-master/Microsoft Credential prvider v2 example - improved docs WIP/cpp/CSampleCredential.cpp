//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "CSampleCredential.h"
#include "guid.h"

#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "netapi32.lib")

//#import "shdocvw.dll"
#include <wininet.h>
#pragma comment(lib,"Wininet.lib")
#include <lm.h>

BOOL g_bLockFlag = FALSE;

CSampleCredential::CSampleCredential():
    _cRef(1),
   // _pCredProvCredentialEvents(nullptr),
    _pCredProvCredentialEventsV1(nullptr),
    _pCredProvCredentialEventsV2(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fChecked(false),
    _fShowControls(false),
    _dwComboIndex(0),
    _workgroup(false),
    _domain(false)
{
    PrintLn(L" Added CSampleCredential::CSampleCredential()");
    DllAddRef();
    m_bCpusLock = FALSE;
    bPaswwordexpire = FALSE;

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
    PrintLn(L" Added CSampleCredential::~CSampleCredential()");
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                      _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
                                      _In_ FIELD_STATE_PAIR const *rgfsp,
                                      _In_ ICredentialProviderUser *pcpUser)
{

    PrintLn(L" Added CSampleCredential::Initialize()");
   
    HRESULT hr = S_OK;
    _cpus = cpus;
    GUID guidProvider;
    LPOLESTR clsid;

    if (pcpUser != nullptr)
    {
        
        pcpUser->GetProviderID(&guidProvider);
        StringFromCLSID(guidProvider, &clsid);
        CoTaskMemFree(clsid);
        _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);
    }
    else 
    {
        _fIsLocalUser = true;
    }

    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Credential Provider", &_rgFieldStrings[SFI_LABEL]);
    }

    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_LOGIN_NAME]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"TECNICS MFA", &_rgFieldStrings[SFI_LARGE_TEXT]);
    }
    // commented for changes

    ///////////////////////////////////////

    // added for changes	

    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_USERNAMELABLE]);
    }

    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Old Password", &_rgFieldStrings[SFI_OLDPASSWORD_TEXT]);
    }

    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_OLDPASSWORD]);
    }

    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Enter New Password", &_rgFieldStrings[SFI_NEWPASSWORD_TEXT]);
    }

    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_NEWPASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Confirm New Password", &_rgFieldStrings[SFI_CONFPASSWORD_TEXT]);
    }

    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_CONFPASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    }

    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }

    // added for changes
//////////////////////////////////////////////////////////


    hr = S_OK;
    if (SUCCEEDED(hr))
    {
        if (pcpUser != nullptr)
        {           
            hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);//get username from the LogonUI user object          
            PWSTR pszUserName1;
            pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName1);
            if (_fIsLocalUser)
            {
                PWSTR pszUserName;
                pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
                if (pszUserName != nullptr)
                {
                    wchar_t szString[256];
                    StringCchPrintf(szString, ARRAYSIZE(szString), L"User Name: %s", pszUserName);                   
                    hr = SHStrDupW(pszUserName, &_rgFieldStrings[SFI_LARGE_TEXT]);
                    if (CPUS_CREDUI == cpus)
                    {
                        _rgFieldStatePairs[SFI_LARGE_TEXT].cpfs = CPFS_DISPLAY_IN_BOTH;
                    }                   
                    CoTaskMemFree(pszUserName);
                }
                else
                {
                    hr = SHStrDupW(L"User Name is NULL", &_rgFieldStrings[SFI_LARGE_TEXT]);
                }
            }
            else
            {                
               
                if (CPUS_CREDUI == cpus)
                {
                    hr = SHStrDupW(_pszQualifiedUserName, &_rgFieldStrings[SFI_LARGE_TEXT]);
                    _rgFieldStatePairs[SFI_LARGE_TEXT].cpfs = CPFS_DISPLAY_IN_BOTH;
                }
            }
        }
        else
        {
            PWSTR connectedDomainName = getNetworkName();
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Sign in to: %s", connectedDomainName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_DOMAIN_NAME_TEXT]);
            hr = SHStrDupW(L"", &_pszQualifiedUserName);
            _fUserNameVisible = true;
            _rgFieldStatePairs[SFI_LOGIN_NAME].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;

            if (_cpus == CPUS_LOGON) 
            {
                PrintLn(L"CSampleCredential:: Initialize() _cpus == CPUS_LOGON ");
                _rgFieldStatePairs[SFI_USERNAMELABLE].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_LOGIN_NAME].cpfis = CPFIS_FOCUSED;
                _rgFieldStatePairs[SFI_PASSWORD].cpfis = CPFIS_NONE;
                _rgFieldStatePairs[SFI_OLDPASSWORD_TEXT].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_OLDPASSWORD].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_NEWPASSWORD_TEXT].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_NEWPASSWORD].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_CONFPASSWORD_TEXT].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_CONFPASSWORD].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_SUBMIT_BUTTON].cpfs = CPFS_DISPLAY_IN_SELECTED_TILE;

            }
        }
    }


    if (pcpUser != nullptr)
    {
        hr = pcpUser->GetSid(&_pszUserSid);
    }
    return hr;
}
//
//// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    PrintLn(L" Added CSampleCredential::Advise()");  

    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));  

}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    PrintLn(L" Added CSampleCredential::UnAdvise()");
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;

}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    PrintLn(L" Added CSampleCredential::SetSelected()");
    *pbAutoLogon = FALSE;

    if (((bPaswwordexpire) && (_cpus == CPUS_CHANGE_PASSWORD)))   // for displaying the components for password change scenario for change password
    {
        PrintLn(L"CSampleCredential:: SetSelected()   _cpus == CPUS_CHANGE_PASSWORD ");

        HRESULT hr;
        hr = _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_USERNAMELABLE, CPFS_DISPLAY_IN_SELECTED_TILE);
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_USERNAMELABLE: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_USERNAMELABLE: %d ", GetLastError());
        }
        hr = _pCredProvCredentialEvents->SetFieldString(this, SFI_USERNAMELABLE, m_pstrUserName);
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_USERNAMELABLE: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_USERNAMELABLE: %d ", GetLastError());
        }       
        hr = _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_LOGIN_NAME, CPFS_HIDDEN);
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_LOGIN_NAME: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_LOGIN_NAME: %d ", GetLastError());
        }
        hr = _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGIN_NAME, m_pstrUserName);
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_LOGIN_NAME: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_LOGIN_NAME: %d ", GetLastError());
        }
        hr = _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_PASSWORD, CPFS_HIDDEN);
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_PASSWORD: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_PASSWORD: %d ", GetLastError());
        }
        hr = _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_OLDPASSWORD_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE);
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_OLDPASSWORD_TEXT: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_OLDPASSWORD_TEXT: %d ", GetLastError());
        }
        hr = _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_OLDPASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_OLDPASSWORD: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_OLDPASSWORD: %d ", GetLastError());
        }       
        hr = SHStrDupW(m_pssword, &_rgFieldStrings[SFI_PASSWORD]);
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SHStrDupW(m_pssword, &_rgFieldStrings[SFI_PASSWORD]): %d ", GetLastError());
        }
       
        hr = _pCredProvCredentialEvents->SetFieldString(this, SFI_OLDPASSWORD, m_pssword);
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_OLDPASSWORD: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_OLDPASSWORD: %d ", GetLastError());
        }
        hr = _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_NEWPASSWORD_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE );
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_NEWPASSWORD_TEXT: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_NEWPASSWORD_TEXT: %d ", GetLastError());
        }       
        hr = _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_NEWPASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);

        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_NEWPASSWORD: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_NEWPASSWORD: %d ", GetLastError());
        }
        hr = _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_CONFPASSWORD_TEXT, CPFS_DISPLAY_IN_SELECTED_TILE );
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_CONFPASSWORD_TEXT: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_CONFPASSWORD_TEXT: %d ", GetLastError());
        }
       	 
        hr = _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_CONFPASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_CONFPASSWORD: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_CONFPASSWORD: %d ", GetLastError());
        }
        hr = _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_SUBMIT_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE );
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_SUBMIT_BUTTON: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_SUBMIT_BUTTON: %d ", GetLastError());
        }
        hr = _pCredProvCredentialEvents->SetFieldSubmitButton((ICredentialProviderCredential*)this, SFI_SUBMIT_BUTTON, SFI_CONFPASSWORD);
        if (!SUCCEEDED(hr))
        {
            PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_SUBMIT_BUTTON: %d ", GetLastError());
        }
        else
        {
            PrintLn(L"CSampleCredential:: SetSelected() SUCCEEDED SFI_SUBMIT_BUTTON: %d ", GetLastError());
        }
    }
    else if ((bPaswwordexpire == FALSE) && (_cpus == CPUS_CHANGE_PASSWORD))   // for login into the system after password change.
    {
            HRESULT hr;
            PrintLn(L" Added In CUserCredential::SetSelected() - if(bPaswwordexpire == FALSE) ");
            hr = SHStrDupW(m_pstrUserName, &_rgFieldStrings[SFI_LOGIN_NAME]);
            if (SUCCEEDED(hr))
            {
                PrintLn(L"Added In CUserCredential::SetSelected() - if (bPaswwordexpire == FALSE) UserName :", m_pstrUserName);
                hr = SHStrDupW(m_pstrNewPassword, &_rgFieldStrings[SFI_PASSWORD]);
                if (SUCCEEDED(hr))
                {
                    *pbAutoLogon = TRUE;
                    _cpus = CPUS_LOGON;  
                }

                PrintLn(L"Added In CUserCredential::SetSelected() - if (bPaswwordexpire == FALSE) PassWord :", m_pstrNewPassword);
            }          

            _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGIN_NAME, _rgFieldStrings[SFI_LOGIN_NAME]);
            _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_LOGIN_NAME, CPFS_DISPLAY_IN_SELECTED_TILE);
            _rgFieldStatePairs[SFI_LOGIN_NAME].cpfis = CPFIS_FOCUSED;

            _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE);
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);


            _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_OLDPASSWORD_TEXT, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_OLDPASSWORD, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_NEWPASSWORD_TEXT, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_NEWPASSWORD, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_CONFPASSWORD_TEXT, CPFS_HIDDEN);
            _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_CONFPASSWORD, CPFS_HIDDEN);

            _pCredProvCredentialEvents->SetFieldState((ICredentialProviderCredential*)this, SFI_SUBMIT_BUTTON, CPFS_DISPLAY_IN_SELECTED_TILE);
            _pCredProvCredentialEvents->SetFieldSubmitButton((ICredentialProviderCredential*)this, SFI_SUBMIT_BUTTON, SFI_PASSWORD);
        }
        else if ((!g_bLockFlag) && (_cpus == CPUS_UNLOCK_WORKSTATION))  // for displaying Lock screen with only password field.
        {
            PrintLn(L"In CUserCredential::SetSelected() if (g_bLockFlag) is FALSE.");
            wchar_t* pchWhack = wcschr(_pszQualifiedUserName, L'\\');
            HRESULT hr;
            if (pchWhack != nullptr)
            {
                wchar_t* pchUsernameBegin = pchWhack + 1;
                PrintLn(L"In CUserCredential::SetSelected() the user name is:", pchUsernameBegin);
                PrintLn(L"In CUserCredential::SetSelected() the user name is  _pszQualifiedUserName:", _pszQualifiedUserName);
                PrintLn(L"In CUserCredential::SetSelected() the Password is _rgFieldStrings[SFI_PASSWORD]:", _rgFieldStrings[SFI_PASSWORD]);
                PrintLn(L"In CUserCredential::SetSelected() the user name is _rgFieldStrings[SFI_LOGIN_NAME]:", _rgFieldStrings[SFI_LOGIN_NAME]);               
                hr = _pCredProvCredentialEvents->SetFieldString(this, SFI_LOGIN_NAME, /*pchUsernameBegin*/_pszQualifiedUserName);
                if (!SUCCEEDED(hr))
                {
                    PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_LOGIN_NAME: %d ", GetLastError());
                }
                hr = _pCredProvCredentialEvents->SetFieldState(this, SFI_LOGIN_NAME, CPFS_HIDDEN);
                if (!SUCCEEDED(hr))
                {
                    PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_LOGIN_NAME: %d ", GetLastError());
                }
                hr = _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, L"");  //CPFIS_FOCUSED
                if (!SUCCEEDED(hr))
                {
                    PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_PASSWORD: %d ", GetLastError());
                }
                hr = _pCredProvCredentialEvents->SetFieldInteractiveState(this, SFI_PASSWORD, CPFIS_FOCUSED);
                if (!SUCCEEDED(hr))
                {
                    PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_PASSWORD: %d ", GetLastError());
                }
                hr = _pCredProvCredentialEvents->SetFieldSubmitButton(this, SFI_SUBMIT_BUTTON, SFI_PASSWORD);
                if (!SUCCEEDED(hr))
                {
                    PrintLn(L"CSampleCredential:: SetSelected() FAILED SFI_SUBMIT_BUTTON: %d ", GetLastError());
                }
                _rgFieldStatePairs[SFI_OLDPASSWORD_TEXT].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_OLDPASSWORD].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_NEWPASSWORD_TEXT].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_NEWPASSWORD].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_CONFPASSWORD_TEXT].cpfs = CPFS_HIDDEN;
                _rgFieldStatePairs[SFI_CONFPASSWORD].cpfs = CPFS_HIDDEN;                
            }
        }
    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
    PrintLn(L" Added CSampleCredential::SetDeselected()");
    HRESULT hr = S_OK;
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
        CoTaskMemFree(_rgFieldStrings[SFI_PASSWORD]);
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
        if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
        {
            _pCredProvCredentialEvents->SetFieldString(this, SFI_PASSWORD, _rgFieldStrings[SFI_PASSWORD]);
        }
    }  
    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
                                         _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    PrintLn(L" Added CSampleCredential::GetFieldState()");
    HRESULT hr;
    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    PrintLn(L" Added CSampleCredential::GetStringValue()");
    HRESULT hr;
    *ppwsz = nullptr;
   
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Get the image to show in the user tile
HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    PrintLn(L" Added CSampleCredential::GetBitmapValue()");
    HRESULT hr;
    *phbmp = nullptr;

    if ((SFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CSampleCredential::GetSubmitButtonValue(DWORD dwFieldID, _Out_ DWORD *pdwAdjacentTo)
{
    PrintLn(L" Added CSampleCredential::GetSubmitButtonValue()");
    HRESULT hr;
    if (SFI_SUBMIT_BUTTON == dwFieldID)
    {       
        *pdwAdjacentTo = SFI_PASSWORD;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    PrintLn(L" Added CSampleCredential::SetStringValue()"); 
    HRESULT hr;
    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT CSampleCredential::GetCheckboxValue(DWORD dwFieldID, _Out_ BOOL *pbChecked, _Outptr_result_nullonfailure_ PWSTR *ppwszLabel)
{
    PrintLn(L" Added CSampleCredential::GetCheckboxValue()");   
    return S_OK;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CSampleCredential::SetCheckboxValue(DWORD dwFieldID, BOOL bChecked)
{
    PrintLn(L" Added CSampleCredential::SetCheckboxValue()");
    HRESULT hr;
    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_CHECKBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _fChecked = bChecked;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(<, *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    PrintLn(L" Added CSampleCredential::GetComboBoxValueCount()");
    HRESULT hr;
    *pcItems = 0;
    *pdwSelectedItem = 0;
    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    PrintLn(L" Added CSampleCredential::GetComboBoxValueAt()");
    HRESULT hr;
    *ppwszItem = nullptr;
   
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    PrintLn(L" Added CSampleCredential::SetComboBoxSelectedValue()");
    HRESULT hr;
   
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Called when the user clicks a command link.
HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    PrintLn(L" Added CSampleCredential::CommandLinkClicked()");
    HRESULT hr = S_OK;   
    return hr;
}

// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
HRESULT CSampleCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *pcpgsr,
                                            _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcs,
                                            _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                            _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{   
    PrintLn(L" Added CSampleCredential::GetSerialization()");
    HRESULT hr = E_UNEXPECTED;
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;
    ZeroMemory(pcpcs, sizeof(*pcpcs));
    wchar_t uname[1024];
    if (_fUserNameVisible)
    {
        //username is entered by the user      
        CoTaskMemFree(_pszQualifiedUserName);
        hr = SHStrDupW(_rgFieldStrings[SFI_LOGIN_NAME], &_pszQualifiedUserName);
    }   
    const wchar_t* pchWhack = wcschr(_pszQualifiedUserName, L'\\');

    if (pchWhack != nullptr) {
        const wchar_t* pchUsernameBegin = pchWhack + 1;
        hr = wcscpy_s(uname, 1024, pchUsernameBegin);       
        if (wcslen(_rgFieldStrings[SFI_LOGIN_NAME]) > 0)
        {
            _fIsLocalUser = true;//false
        }
    }
    else {
        hr = wcscpy_s(uname, 1024, _pszQualifiedUserName);
        LPWSTR defaultNetworkName = getNetworkName();
        wchar_t defaultDomainAndUserName[1024] = L""/*_T("")*/;
        StringCchCat(defaultDomainAndUserName, 1024, defaultNetworkName);
        StringCchCat(defaultDomainAndUserName, 1024, L"\\");
        StringCchCat(defaultDomainAndUserName, 1024, _pszQualifiedUserName);      
        CoTaskMemFree(_pszQualifiedUserName);
        hr = SHStrDupW(defaultDomainAndUserName, &_pszQualifiedUserName);   
        if (wcslen(_rgFieldStrings[SFI_LOGIN_NAME]) > 0)
        {
            _fIsLocalUser = true;
        }
    }   
    if (_pszQualifiedUserName)
    {
        hr = SplitDomainAndUsername(_pszQualifiedUserName, &pszDomain, &pszUsername);       
    }
    else
    {      
    }
    WCHAR wsz[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD cch = ARRAYSIZE(wsz);
    DWORD cb = 0;
    BYTE* rgb = NULL;
    // For local user, the domain and user name can be split from _pszQualifiedUserName (domain\username).
    // CredPackAuthenticationBuffer() cannot be used because it won't work with unlock scenario.
    if (_fIsLocalUser)
    {        
        PWSTR pwzProtectedPassword;
        hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[SFI_PASSWORD], _cpus, &pwzProtectedPassword);
        SHStrDupW(_rgFieldStrings[SFI_PASSWORD], &_password);
        if (SUCCEEDED(hr))
        {           
            KERB_INTERACTIVE_UNLOCK_LOGON kiul;
            hr = KerbInteractiveUnlockLogonInit(pszDomain, pszUsername, pwzProtectedPassword, _cpus, &kiul);
            if (SUCCEEDED(hr))
            {
                // We use KERB_INTERACTIVE_UNLOCK_LOGON in both unlock and logon scenarios. It contains a
                // KERB_INTERACTIVE_LOGON to hold the creds plus a LUID that is filled in for us by Winlogon
                // as necessary.
                hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
                if (SUCCEEDED(hr))
                {
                    ULONG ulAuthPackage;
                    hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                    if (SUCCEEDED(hr))
                    {
                        pcpcs->ulAuthenticationPackage = ulAuthPackage;
                        pcpcs->clsidCredentialProvider = CLSID_CSample;
                        // At this point the credential has created the serialized credential used for logon
                        // By setting this to CPGSR_RETURN_CREDENTIAL_FINISHED we are letting logonUI know
                        // that we have all the information we need and it should attempt to submit the
                        // serialized credential.
                        *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
                    }
                }
            }
            CoTaskMemFree(pwzProtectedPassword);
        }
    }
    CoTaskMemFree(pszDomain);
    CoTaskMemFree(pszUsername);
    return hr;
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS, L"Incorrect password or username.", CPSI_ERROR, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED, L"The account is disabled.", CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(NTSTATUS ntsStatus,
                                        NTSTATUS ntsSubstatus,
                                        _Outptr_result_maybenull_ PWSTR *ppwszOptionalStatusText,
                                        _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *pcpsiOptionalStatusIcon)
{
    PrintLn(L" Added CSampleCredential::ReportResult()");
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    DWORD dwStatusInfo = (DWORD)-1;

    if (ntsStatus == STATUS_PASSWORD_MUST_CHANGE || (ntsStatus == STATUS_ACCOUNT_RESTRICTION && ntsSubstatus == STATUS_PASSWORD_EXPIRED))
    {
        HRESULT hr = S_OK;      
        if (_cpus == CPUS_UNLOCK_WORKSTATION && ntsStatus == STATUS_PASSWORD_MUST_CHANGE)
        {
            PrintLn(L" CSampleCredential:: ReportResult() in if ( _cpus == CPUS_UNLOCK_WORKSTATION with STATUS_PASSWORD_MUST_CHANGE ) ");
            m_bCpusLock = TRUE;
            bPaswwordexpire = TRUE;
            _cpus = CPUS_CHANGE_PASSWORD;
            g_bLockFlag = TRUE;
        }
        else if ((_cpus == CPUS_LOGON) && (ntsStatus == STATUS_PASSWORD_MUST_CHANGE))
        {
            PrintLn(L" STATUS_PASSWORD_MUST_CHANGE::ReportResult()  calling Initialize() CPUS_LOGON  scenario  STATUS_PASSWORD_MUST_CHANGE  ");
            _cpus = CPUS_CHANGE_PASSWORD;
            bPaswwordexpire = TRUE;
            g_bLockFlag = TRUE;
            m_pstrUserName = _rgFieldStrings[SFI_LOGIN_NAME];
            m_pssword = _rgFieldStrings[SFI_PASSWORD];
        }
    }
    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }
    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }
   
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CSampleCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *ppszSid)
{
    PrintLn(L" Added CSampleCredential::GetUserSid()");
    *ppszSid = nullptr;
    HRESULT hr = E_UNEXPECTED;
    if (_pszUserSid != nullptr)
    {
        hr = SHStrDupW(_pszUserSid, ppszSid);
    }
    // Return S_FALSE with a null SID in ppszSid for the
    // credential to be associated with an empty user tile.

    return hr;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID,
                                           _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    PrintLn(L" Added CSampleCredential::GetFieldOptions()");
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
    return S_OK;
}
PWSTR CSampleCredential::getNetworkName() 
{
    PrintLn(L" Added CSampleCredential::getNetworkName()");
    NET_API_STATUS nas;
    NETSETUP_JOIN_STATUS BufferType;
    // get info
    nas = NetGetJoinInformation(NULL, &_lpNameBuffer, &BufferType);
    if (nas != NERR_Success)
    {        
        return 0;
    }
    switch (BufferType)
    {
    case NetSetupDomainName:      
        _domain = true;
        break;

    case NetSetupWorkgroupName:
        _workgroup = true;
        break;
    case NetSetupUnjoined:
        break;
    case NetSetupUnknownStatus:       
        break;
    }
    return _lpNameBuffer;
}