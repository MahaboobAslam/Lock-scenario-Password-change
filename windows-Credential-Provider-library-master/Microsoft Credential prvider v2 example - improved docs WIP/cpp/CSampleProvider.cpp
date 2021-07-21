//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// CSampleProvider implements ICredentialProvider, which is the main
// interface that logonUI uses to decide which tiles to display.
// In this sample, we will display one tile that uses each of the nine
// available UI controls.

#include <initguid.h>
#include "CSampleProvider.h"
#include "CSampleCredential.h"
#include "guid.h"

CSampleProvider::CSampleProvider():
    _localDomain(false),
    _cRef(1),
    _pCredProviderUserArray(nullptr)
{
    PrintLn(L" Added CSampleProvider::CSampleProvider()");
    _pCredential.clear();
    DllAddRef();
}

CSampleProvider::~CSampleProvider()
{
    PrintLn(L" Added CSampleProvider::~CSampleProvider()");   
    _ReleaseEnumeratedCredentials();
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->Release();
        _pCredProviderUserArray = nullptr;
    }
    DllRelease();
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT CSampleProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD /*dwFlags*/)
{
    PrintLn(L" Added CSampleProvider::SetUsageScenario()");
    HRESULT hr;

    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
    switch (cpus)
    {
    case CPUS_LOGON:
        PrintLn(L" CSampleProvider::SetUsageScenario() CPUS_LOGON ");
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;
    case CPUS_UNLOCK_WORKSTATION:
        PrintLn(L" CSampleProvider::SetUsageScenario() CPUS_UNLOCK_WORKSTATION");
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;
    case CPUS_CHANGE_PASSWORD:
        // The reason why we need _fRecreateEnumeratedCredentials is because ICredentialProviderSetUserArray::SetUserArray() is called after ICredentialProvider::SetUsageScenario(),
        // while we need the ICredentialProviderUserArray during enumeration in ICredentialProvider::GetCredentialCount()
        PrintLn(L" CSampleProvider::SetUsageScenario() CPUS_CHANGE_PASSWORD ");
        _cpus = cpus;
        _fRecreateEnumeratedCredentials = true;
        hr = S_OK;
        break;   
    case CPUS_CREDUI:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }
    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a tile.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// If you wish to see an example of SetSerialization, please see either the SampleCredentialProvider
// sample or the SampleCredUICredentialProvider sample.  [The logonUI team says, "The original sample that
// this was built on top of didn't have SetSerialization.  And when we decided SetSerialization was
// important enough to have in the sample, it ended up being a non-trivial amount of work to integrate
// it into the main sample.  We felt it was more important to get these samples out to you quickly than to
// hold them in order to do the work to integrate the SetSerialization changes from SampleCredentialProvider
// into this sample.]
HRESULT CSampleProvider::SetSerialization(
    _In_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION const * /*pcpcs*/)
{
    PrintLn(L" Added CSampleProvider::SetSerialization()");
    return E_NOTIMPL;
}

// Called by LogonUI to give you a callback.  Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated.
HRESULT CSampleProvider::Advise(
    _In_ ICredentialProviderEvents * /*pcpe*/,
    _In_ UINT_PTR /*upAdviseContext*/)
{
    PrintLn(L" Added CSampleProvider::Advise()");
    return E_NOTIMPL;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CSampleProvider::UnAdvise()
{
    PrintLn(L" Added CSampleProvider::UnAdvise()");
    return E_NOTIMPL;
}

// Called by LogonUI to determine the number of fields in your tiles.  This
// does mean that all your tiles must have the same number of fields.
// This number must include both visible and invisible fields. If you want a tile
// to have different fields from the other tiles you enumerate for a given usage
// scenario you must include them all in this count and then hide/show them as desired
// using the field descriptors.
HRESULT CSampleProvider::GetFieldDescriptorCount(
    _Out_ DWORD *pdwCount)
{
    PrintLn(L" Added CSampleProvider::GetFieldDescriptorCount()");
    *pdwCount = SFI_NUM_FIELDS;
    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT CSampleProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR **ppcpfd)
{
    PrintLn(L" Added CSampleProvider::GetFieldDescriptorAt()");
    HRESULT hr;
    *ppcpfd = nullptr;
    // Verify dwIndex is a valid field.
    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
// Sets pdwDefault to the index of the tile which should be used as the default.
// The default tile is the tile which will be shown in the zoomed view by default. If
// more than one provider specifies a default the last used cred prov gets to pick
// the default. If *pbAutoLogonWithDefault is TRUE, LogonUI will immediately call
// GetSerialization on the credential you've specified as the default and will submit
// that credential for authentication without showing any further UI.
HRESULT CSampleProvider::GetCredentialCount(
    _Out_ DWORD *pdwCount,
    _Out_ DWORD *pdwDefault,
    _Out_ BOOL *pbAutoLogonWithDefault)
{
    PrintLn(L" Added CSampleProvider::GetCredentialCount()");
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;
    if (_fRecreateEnumeratedCredentials)
    {
        _fRecreateEnumeratedCredentials = false;
        _ReleaseEnumeratedCredentials();
        _CreateEnumeratedCredentials();
    }
    DWORD dwUserCount;
    HRESULT hr;
    if (_pCredProviderUserArray != nullptr)
    {
        hr = _pCredProviderUserArray->GetCount(&dwUserCount);
        if (hr == 0)
        {          
        }
        else
        {           
            dwUserCount = 1;
        }
    }
    else
    {
        dwUserCount = 1;
    }
    if (1) PrintLn("CSampleProvider::User count:(%d)", dwUserCount);

    if ((dwUserCount == 0) || (IsOS(OS_DOMAINMEMBER) == 1))
    {
        dwUserCount += 1;//display additional empty tile
        _localDomain = true;      
    }   
    *pdwCount = dwUserCount;
    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called by logonUI to enumerate
// the tiles.
HRESULT CSampleProvider::GetCredentialAt(
    DWORD dwIndex,
    _Outptr_result_nullonfailure_ ICredentialProviderCredential **ppcpc)
{
    PrintLn(L" Added CSampleProvider::GetCredentialAt()");
    HRESULT hr = E_INVALIDARG;
    *ppcpc = nullptr;

    if ((dwIndex < _pCredential.size()) && ppcpc)
    {       
        hr = _pCredential[dwIndex]->QueryInterface(IID_PPV_ARGS(ppcpc));
    }
    return hr;
}

// This function will be called by LogonUI after SetUsageScenario succeeds.
// Sets the User Array with the list of users to be enumerated on the logon screen.
HRESULT CSampleProvider::SetUserArray(_In_ ICredentialProviderUserArray *users)
{
    PrintLn(L" Added CSampleProvider::SetUserArray()");
    if (_pCredProviderUserArray)
    {
        _pCredProviderUserArray->Release();
    }
    _pCredProviderUserArray = users;
    _pCredProviderUserArray->AddRef();
    return S_OK;
}

void CSampleProvider::_CreateEnumeratedCredentials()
{
    PrintLn(L" Added CSampleProvider::_CreateEnumeratedCredentials()");
    switch (_cpus)
    {
    case CPUS_LOGON:
        {
             PrintLn("CSampleProvider::_CreateEnumeratedCredentials CPUS_LOGON");
             _EnumerateCredentials();
             break;
        }
    case CPUS_UNLOCK_WORKSTATION:
        {
            PrintLn("CSampleProvider::_CreateEnumeratedCredentials CPUS_UNLOCK_WORKSTATION");
            _EnumerateCredentials();
            break;
        }
    case CPUS_CHANGE_PASSWORD:
        {
             PrintLn("CSampleProvider::_CreateEnumeratedCredentials CPUS_CHANGE_PASSWORD");
             _EnumerateCredentials();
             break;
        }
    default:
        break;
    }
}

void CSampleProvider::_ReleaseEnumeratedCredentials()
{
    PrintLn(L" Added CSampleProvider::_ReleaseEnumeratedCredentials()");
    for (DWORD i = 0; i < _pCredential.size(); i++)
    {
        if (_pCredential[i] != nullptr)
        {
            _pCredential[i]->Release();
            _pCredential[i] = nullptr;
        }
    }
    _pCredential.clear();
}

HRESULT CSampleProvider::_EnumerateCredentials()
{
    PrintLn(L" Added CSampleProvider::_EnumerateCredentials()");   
    HRESULT hr = E_UNEXPECTED;
    DWORD dwUserCount = 0;
    if (_pCredProviderUserArray != nullptr)
    {
        _pCredProviderUserArray->GetCount(&dwUserCount);
        if (dwUserCount > 0)
        {           
            for (DWORD i = 0; i < dwUserCount; i++)
            {
                ICredentialProviderUser* pCredUser;
                hr = _pCredProviderUserArray->GetAt(i, &pCredUser);
                if (SUCCEEDED(hr))
                {
                    _pCredential.push_back(new(std::nothrow) CSampleCredential());
                    if (_pCredential[i] != nullptr)
                    {
                        //logfile << "new CSampleCredential()\n";                       
                        hr = _pCredential[i]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, pCredUser);
                        if (FAILED(hr))
                        {
                            _pCredential[i]->Release();
                            _pCredential[i] = nullptr;                          
                        }
                    }
                    else
                    {
                        hr = E_OUTOFMEMORY;
                    }
                    pCredUser->Release();
                }
            }
        }
        else
        {           
        }
    }
    else
    {      
        //it is probably Credential Provider V1 System...
        //create empty user tile later       
    }
    //if you are in a domain or have no users on the list you have to show "Other user tile"   
    if ((dwUserCount == 0) || (IsOS(OS_DOMAINMEMBER) == 1))
    {        
        _pCredential.push_back(new(std::nothrow) CSampleCredential());
        if (_pCredential[_pCredential.size() - 1] != nullptr)
        {            
            hr = _pCredential[_pCredential.size() - 1]->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, nullptr);          
          
        }
        else
        {
        }
    }

    return hr;   
}

// Boilerplate code to create our provider.
HRESULT CSample_CreateInstance(_In_ REFIID riid, _Outptr_ void **ppv)
{
    PrintLn(L" Added CSampleProvider::CSample_CreateInstance");
    HRESULT hr;
    CSampleProvider *pProvider = new(std::nothrow) CSampleProvider();
    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    return hr;
}
