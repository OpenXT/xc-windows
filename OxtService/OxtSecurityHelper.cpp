/*
 * Copyright (c) 2012 Citrix Systems, Inc.
 * Copyright (c) 2016 Assured Information Security, Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "stdafx.h"
#include "resource.h"
#include "oxtmsg.h"
#include <sddl.h>
#include <accctrl.h>
#include <aclapi.h>
#include "OxtSecurityHelper.h"

#define XSH_PRINCIPAL_COUNT 3
#define XSH_NAME_LEN		255

#define SDTYPE_APPLICATION_LAUNCH 0x10L
#define SDTYPE_APPLICATION_ACCESS 0x20L

static const TCHAR *g_ptszPrincipals[XSH_PRINCIPAL_COUNT] = {
	_T("NT AUTHORITY\\INTERACTIVE"),
	_T("NT AUTHORITY\\SYSTEM"),
	_T("BUILTIN\\Administrators")
};

static const TCHAR *g_ptszSidStrings[XSH_PRINCIPAL_COUNT] = {
	_T("S-1-5-4"),
	_T("S-1-5-18"),
	_T("S-1-5-32-544")
};

const DWORD g_dwAccessAccessMask = COM_RIGHTS_EXECUTE_REMOTE|COM_RIGHTS_EXECUTE;
const DWORD g_dwLaunchActivateMask = COM_RIGHTS_ACTIVATE_REMOTE|COM_RIGHTS_EXECUTE_REMOTE|COM_RIGHTS_EXECUTE;

void COxtSecurityHelper::LogSecuritySetupFailure(LPCTSTR tszPrincipal,
												 LPCTSTR tszPermissionName,
												 LPCTSTR tszOp,
												 DWORD dwError)
{
	m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_PRINCIPAL__zS_PERMISSION__zS_OPE_OXTSECURITYHELPER_35),
							 EVENTLOG_ERROR_TYPE,
							 EVMSG_SECURITY_SETUP_FAILURE,
							 tszPrincipal,
							 tszPermissionName,
							 tszOp,
							 dwError);
}

bool COxtSecurityHelper::IsLegacySecurityModel()
{
	bool				   br	= false;
	const OSVERSIONINFOEX *posvi = m_pclOxtSvc->GetOsInfo();

	if (posvi->dwMajorVersion == 5) // = 2k, xp, 2k3
	{
		if (posvi->dwMinorVersion < 1) // < xp
		{
			br = true;
		}
		else if (posvi->dwMinorVersion == 1) // = xp
		{
			if (posvi->wServicePackMajor < 2) // < xpsp2
				br = true;
		}
		else if (posvi->dwMinorVersion == 2) // = 2k3
		{
			if (posvi->wServicePackMajor < 1) // < 2k3sp1
				br = true;
		}

	}
	else if (posvi->dwMajorVersion < 5) // nt?
		br = true;

	return br;
}

DWORD COxtSecurityHelper::CopyACL(PACL paclOld, PACL paclNew)
{
	ACL_SIZE_INFORMATION  aclSizeInfo = {0};
	LPVOID				  pvAce	      = NULL;
	ACE_HEADER		     *pAceHeader  = NULL;
	ULONG				  i;

	if(!::GetAclInformation(paclOld, (LPVOID)&aclSizeInfo,
							sizeof(aclSizeInfo), AclSizeInformation))
	{
		return ::GetLastError();
	}

	// Copy all of the ACEs to the new ACL
	for (i = 0; i < aclSizeInfo.AceCount; i++)
	{
		// Get the ACE and header info
		if (!::GetAce(paclOld, i, &pvAce))
			return ::GetLastError();

		pAceHeader = (ACE_HEADER *)pvAce;

		// Add the ACE to the new list
		if (!::AddAce(paclNew, ACL_REVISION, 0xffffffff, pvAce, pAceHeader->AceSize))
			return ::GetLastError();
	}

	return ERROR_SUCCESS;
}

DWORD COxtSecurityHelper::AddAccessAllowedACEToACL(PACL *paclOrig,
												   DWORD dwAccessMask,
												   LPCTSTR tszPrincipal)
{
	ACL_SIZE_INFORMATION aclSizeInfo   = {0};
	int				     cbAclSize	   = 0;
	DWORD				 dwReturnValue = ERROR_SUCCESS;
	PSID				 psidPrincipal = NULL;
	PACL				 paclOld	   = NULL;
	PACL				 paclNew	   = NULL;

	if (paclOrig == NULL)
		return ERROR_BAD_ARGUMENTS;

	paclOld = *paclOrig;

	do {
		dwReturnValue = GetPrincipalSID(tszPrincipal, &psidPrincipal);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		if (!::GetAclInformation(paclOld, (LPVOID)&aclSizeInfo,
								 sizeof (ACL_SIZE_INFORMATION), AclSizeInformation))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		cbAclSize = aclSizeInfo.AclBytesInUse + sizeof (ACL) + sizeof (ACCESS_ALLOWED_ACE) +
					::GetLengthSid(psidPrincipal) - sizeof (DWORD);

		paclNew = (PACL)malloc(cbAclSize);
		if (paclNew == NULL)
		{
			dwReturnValue = ERROR_OUTOFMEMORY;
			break;
		}

		if (!::InitializeAcl(paclNew, cbAclSize, ACL_REVISION))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		dwReturnValue = CopyACL(paclOld, paclNew);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		if (!::AddAccessAllowedAce(paclNew, ACL_REVISION2, dwAccessMask, psidPrincipal))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		*paclOrig = paclNew;

	} while (false);

	if((dwReturnValue != ERROR_SUCCESS)&&(paclNew != NULL))
		free(paclNew);

	if (psidPrincipal != NULL)
		::LocalFree(psidPrincipal);

	return dwReturnValue;
}

DWORD COxtSecurityHelper::AddAccessDeniedACEToACL(PACL *paclOrig,
												  DWORD dwAccessMask,
												  LPCTSTR tszPrincipal)
{
	ACL_SIZE_INFORMATION  aclSizeInfo   = {0};
	int				      cbAclSize	    = 0;
	DWORD				  dwReturnValue = ERROR_SUCCESS;
	PSID				  psidPrincipal = NULL;
	PACL				  paclOld	    = NULL;
	PACL				  paclNew	    = NULL;

	if (paclOrig == NULL)
		return ERROR_BAD_ARGUMENTS;

	paclOld = *paclOrig;

	do {
		dwReturnValue = GetPrincipalSID(tszPrincipal, &psidPrincipal);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		if (!::GetAclInformation(paclOld, (LPVOID)&aclSizeInfo,
								 sizeof (ACL_SIZE_INFORMATION), AclSizeInformation))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		cbAclSize = aclSizeInfo.AclBytesInUse + sizeof (ACL) + sizeof (ACCESS_DENIED_ACE) +
					::GetLengthSid (psidPrincipal) - sizeof (DWORD);

		paclNew = (PACL)malloc(cbAclSize);
		if (paclNew == NULL)
		{
			dwReturnValue = ERROR_OUTOFMEMORY;
			break;
		}

		if (!::InitializeAcl(paclNew, cbAclSize, ACL_REVISION))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		if (!::AddAccessDeniedAce(paclNew, ACL_REVISION2, dwAccessMask, psidPrincipal))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		dwReturnValue = CopyACL(paclOld, paclNew);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		*paclOrig = paclNew;
	} while (false);

	if (psidPrincipal != NULL)
		::LocalFree(psidPrincipal);

	return dwReturnValue;
}

DWORD COxtSecurityHelper::SetLegacyACLDefaults(PACL *ppDacl, DWORD dwSDType)
{
	DWORD dwReturnValue = ERROR_BAD_ARGUMENTS;

	switch (dwSDType)
	{
	case SDTYPE_APPLICATION_LAUNCH:
		{
		dwReturnValue = AddAccessAllowedACEToACL(ppDacl,
												 COM_RIGHTS_EXECUTE,
												 g_ptszPrincipals[1]); // SYSTEM

		if (dwReturnValue != ERROR_SUCCESS)
			break;

		dwReturnValue = AddAccessAllowedACEToACL(ppDacl,
												 COM_RIGHTS_EXECUTE,
												 g_ptszPrincipals[2]); // Administrators

		if (dwReturnValue != ERROR_SUCCESS)
			break;

		dwReturnValue = AddAccessAllowedACEToACL(ppDacl,
												 COM_RIGHTS_EXECUTE,
												 g_ptszPrincipals[0]); // INTERACTIVE
		break;
		}
	case SDTYPE_APPLICATION_ACCESS:
		{
		dwReturnValue = AddAccessAllowedACEToACL(ppDacl,
												 COM_RIGHTS_EXECUTE,
												 g_ptszPrincipals[1]); // SYSTEM

		if (dwReturnValue != ERROR_SUCCESS)
			break;

		dwReturnValue = AddAccessAllowedACEToACL(ppDacl,
												 COM_RIGHTS_EXECUTE,
												 g_ptszPrincipals[0]); // INTERACTIVE
		break;
		}
	default:
		break;
	}

	return dwReturnValue;
}

DWORD COxtSecurityHelper::SetACLDefaults(PACL *ppDacl, DWORD dwSDType)
{
	DWORD dwReturnValue = ERROR_BAD_ARGUMENTS;

	if (IsLegacySecurityModel())
		return SetLegacyACLDefaults(ppDacl, dwSDType);

	switch (dwSDType)
	{
	case SDTYPE_APPLICATION_LAUNCH:
		{
		dwReturnValue = AddAccessAllowedACEToACL(ppDacl,
												 COM_RIGHTS_ACTIVATE_LOCAL |
												 COM_RIGHTS_EXECUTE_LOCAL |
												 COM_RIGHTS_EXECUTE,
												 g_ptszPrincipals[1]); // SYSTEM

		if (dwReturnValue != ERROR_SUCCESS)
			break;

		dwReturnValue = AddAccessAllowedACEToACL(ppDacl,
												 COM_RIGHTS_ACTIVATE_LOCAL |
												 COM_RIGHTS_EXECUTE_LOCAL |
												 COM_RIGHTS_EXECUTE,
												 g_ptszPrincipals[2]); // Administrators

		if (dwReturnValue != ERROR_SUCCESS)
			break;

		dwReturnValue = AddAccessAllowedACEToACL(ppDacl,
												 COM_RIGHTS_ACTIVATE_LOCAL |
												 COM_RIGHTS_EXECUTE_LOCAL |
												 COM_RIGHTS_EXECUTE,
												 g_ptszPrincipals[0]); // INTERACTIVE
		break;
		}
	case SDTYPE_APPLICATION_ACCESS:
		{
		dwReturnValue = AddAccessAllowedACEToACL(ppDacl,
												 COM_RIGHTS_EXECUTE_LOCAL |
												 COM_RIGHTS_EXECUTE,
												 g_ptszPrincipals[1]); // SYSTEM

		if (dwReturnValue != ERROR_SUCCESS)
			break;

		dwReturnValue = AddAccessAllowedACEToACL(ppDacl,
												 COM_RIGHTS_EXECUTE_LOCAL |
												 COM_RIGHTS_EXECUTE,
												 g_ptszPrincipals[2]); // Administrators

		if (dwReturnValue != ERROR_SUCCESS)
			break;

		dwReturnValue = AddAccessAllowedACEToACL(ppDacl,
												 COM_RIGHTS_EXECUTE_LOCAL |
												 COM_RIGHTS_EXECUTE,
												 g_ptszPrincipals[0]); // INTERACTIVE

		break;
		}
	default:
		break;
	}

	return dwReturnValue;
}

DWORD COxtSecurityHelper::CreateNewSecurityDescriptor(SECURITY_DESCRIPTOR **ppSecurityDesc)
{
	PACL					 pAcl			  = NULL;
	DWORD					 cbSid			  = 0;
	PSID					 pSid			  = NULL;
	PSID					 psidGroup		  = NULL;
	PSID					 psidOwner		  = NULL;
	DWORD					 dwReturnValue	  = ERROR_SUCCESS;
	SID_IDENTIFIER_AUTHORITY SystemSidAuthority = SECURITY_NT_AUTHORITY;

	if (!ppSecurityDesc)
		return ERROR_BAD_ARGUMENTS;

	*ppSecurityDesc = NULL;

	do {
		if (!::AllocateAndInitializeSid(&SystemSidAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
										DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSid))
		{
			dwReturnValue = GetLastError();
			break;
		}

		cbSid = ::GetLengthSid(pSid);

		*ppSecurityDesc = (SECURITY_DESCRIPTOR*)malloc(sizeof(ACL) + (2*cbSid) + sizeof(SECURITY_DESCRIPTOR));
		if (*ppSecurityDesc == NULL)
		{
			dwReturnValue = ERROR_OUTOFMEMORY;
			break;
		}

		psidGroup = (SID *)(*ppSecurityDesc + 1);
		psidOwner = (SID *)(((BYTE *) psidGroup) + cbSid);
		pAcl = (ACL *)(((BYTE *) psidOwner) + cbSid);

		if (!::InitializeSecurityDescriptor(*ppSecurityDesc, SECURITY_DESCRIPTOR_REVISION))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		if (!::InitializeAcl(pAcl, (sizeof(ACL) + sizeof (ACCESS_ALLOWED_ACE) + cbSid), ACL_REVISION2))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		if (!::SetSecurityDescriptorDacl(*ppSecurityDesc, TRUE, pAcl, FALSE))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		memcpy(psidGroup, pSid, cbSid);
		if (!::SetSecurityDescriptorGroup(*ppSecurityDesc, psidGroup, FALSE))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		memcpy(psidOwner, pSid, cbSid);
		if (!::SetSecurityDescriptorOwner(*ppSecurityDesc, psidOwner, FALSE))
		{
			dwReturnValue = ::GetLastError();
			break;
		}
	} while (false);

	if (dwReturnValue != ERROR_SUCCESS)
	{
		if (*ppSecurityDesc)
			free(*ppSecurityDesc);
	}

	if (pSid)
		::FreeSid(pSid);

	return dwReturnValue;
}

DWORD COxtSecurityHelper::GetPrincipalSIDByName(LPCTSTR tszPrincipal, PSID *ppSid)
{
	SID_NAME_USE snu;
	DWORD		 cbSid         = 0;
	DWORD		 cbRefDomain   = 0;
	DWORD		 dwReturnValue = ERROR_SUCCESS;
	TCHAR		 tszRefDomain[XSH_NAME_LEN + 1] = {0};

	cbSid = 0;
	cbRefDomain = XSH_NAME_LEN;

	::LookupAccountName(NULL, tszPrincipal, *ppSid, &cbSid,
						tszRefDomain, &cbRefDomain, &snu);

	dwReturnValue = ::GetLastError();
	if (dwReturnValue != ERROR_INSUFFICIENT_BUFFER)
		return dwReturnValue;

	dwReturnValue = ERROR_SUCCESS;

	*ppSid = (PSID)::LocalAlloc(LMEM_FIXED, cbSid);
	if (*ppSid == NULL)
		return ERROR_OUTOFMEMORY;

	cbRefDomain = XSH_NAME_LEN;

	if (!::LookupAccountName(NULL, tszPrincipal, *ppSid, &cbSid,
							 tszRefDomain, &cbRefDomain, &snu))
	{
		dwReturnValue = ::GetLastError();
		::LocalFree(*ppSid);
		*ppSid = NULL;
	}

	return dwReturnValue;
}

DWORD COxtSecurityHelper::GetPrincipalSID(LPCTSTR tszPrincipal, PSID *ppSid)
{
	const TCHAR *tszStringSid  = NULL;
	DWORD		i;

	*ppSid = NULL;

	for (i = 0; i < XSH_PRINCIPAL_COUNT; i++)
	{
		if (_tcsicmp(g_ptszPrincipals[i], tszPrincipal) == 0)
		{
			tszStringSid = g_ptszSidStrings[i];
			break;
		}
	}

	if (tszStringSid == NULL)
		return ERROR_BAD_ARGUMENTS;

	if (!::ConvertStringSidToSid(tszStringSid, ppSid))
	{
		*ppSid = NULL;
		return ::GetLastError();
	}

	return ERROR_SUCCESS;
}

DWORD COxtSecurityHelper::GetSecurityDescripterByName(LPCTSTR tszPermissionName,
													  SECURITY_DESCRIPTOR **ppSecurityDesc,
													  BOOL *pbNew)
{
	DWORD  dwReturnValue = ERROR_SUCCESS;
	HKEY   hkeyReg	     = NULL;
	DWORD  dwType		 = 0;
	DWORD  cbSize		 = 0;

	if (pbNew)
		*pbNew = FALSE;

	if (!ppSecurityDesc)
		return ERROR_BAD_ARGUMENTS;

	*ppSecurityDesc = NULL;

	do {
		// Get the security descriptor from the named value. If it doesn't
		// exist, create a fresh one.
		dwReturnValue = ::RegOpenKeyEx(HKEY_CLASSES_ROOT, m_tszAppIdKey, 0, KEY_ALL_ACCESS, &hkeyReg);

		if (dwReturnValue != ERROR_SUCCESS)
			break;

		dwReturnValue = ::RegQueryValueEx(hkeyReg, tszPermissionName, NULL, &dwType, NULL, &cbSize);

		if ((dwReturnValue != ERROR_SUCCESS)&&(dwReturnValue != ERROR_INSUFFICIENT_BUFFER))
			break;

		*ppSecurityDesc = (SECURITY_DESCRIPTOR *)malloc(cbSize);
		if (*ppSecurityDesc == NULL)
		{
			dwReturnValue = ERROR_OUTOFMEMORY;
			break;
		}

		dwReturnValue = ::RegQueryValueEx(hkeyReg, tszPermissionName, NULL,
										  &dwType, (LPBYTE)*ppSecurityDesc, &cbSize);
	} while (false);


	if (dwReturnValue != ERROR_SUCCESS)
	{
		if (*ppSecurityDesc)
			free(*ppSecurityDesc);
		*ppSecurityDesc = NULL;

		if (pbNew)
		{
			dwReturnValue = CreateNewSecurityDescriptor(ppSecurityDesc);
			if (dwReturnValue == ERROR_SUCCESS)
				*pbNew = TRUE;
		}
	}

	if (hkeyReg != NULL)
		::RegCloseKey(hkeyReg);

	return dwReturnValue;
}

DWORD COxtSecurityHelper::SetSecurityDescriptorByName(LPCTSTR tszPermissionName,
													  SECURITY_DESCRIPTOR *pSecurityDesc)
{
	DWORD dwReturnValue = ERROR_SUCCESS;
	DWORD dwDisposition = 0;
	DWORD dwLength;
	HKEY  hkeyReg = NULL;

	// Create new key or open existing key
	dwReturnValue = ::RegCreateKeyEx(HKEY_CLASSES_ROOT, m_tszAppIdKey, 0, _T(""), 0,
									 KEY_ALL_ACCESS, NULL, &hkeyReg, &dwDisposition);
	if (dwReturnValue != ERROR_SUCCESS)
		return dwReturnValue;

	// Write the security descriptor
	dwLength = ::GetSecurityDescriptorLength(pSecurityDesc);
	dwReturnValue = ::RegSetValueEx(hkeyReg, tszPermissionName, 0, REG_BINARY,
									(LPBYTE)pSecurityDesc, dwLength);
	::RegCloseKey(hkeyReg);

	return dwReturnValue;
}

DWORD COxtSecurityHelper::CanonicalizeSecurityDescriptor(PSECURITY_DESCRIPTOR pSD)
{
	BOOL bACLPresent = FALSE;
	BOOL bDefaulted  = FALSE;
	ACL* pACL		 = NULL;

	if (!::GetSecurityDescriptorDacl(pSD, &bACLPresent, &pACL, &bDefaulted))
		return ::GetLastError();

	ACCESS_MASK dwOtherRights = COM_RIGHTS_EXECUTE_LOCAL |
								COM_RIGHTS_EXECUTE_REMOTE |
								COM_RIGHTS_ACTIVATE_LOCAL |
								COM_RIGHTS_ACTIVATE_REMOTE;

	DWORD dwSizeOfACL = sizeof(ACL);
	ULONG_PTR ulptrACL = (ULONG_PTR)pACL;
	PACE_HEADER pAceHeader = (PACE_HEADER)(ulptrACL + dwSizeOfACL);
	PACCESS_MASK pAccessMask = (PACCESS_MASK)((ULONG_PTR)pAceHeader+sizeof(ACE_HEADER));

	// Iterate through the ACE's in the ACL and canonicalize the representation
	// Each ACE has a header and Mask Field as a minimum.
	if (pACL != NULL)
	{
		for (int i = 0; i < pACL->AceCount; i++)
		{
			DWORD dwError = NULL;
			void* pNewAcl = NULL;

			// Protect against bad ACL structure
			if (((ULONG_PTR)pAceHeader-(ULONG_PTR)pACL) >= (pACL->AclSize - sizeof(ACCESS_MASK)))
				return ERROR_INVALID_PARAMETER;

			DWORD dwAceSize = pAceHeader->AceSize;

			// Ensure minimum size ACE
			if (dwAceSize < (sizeof(ACE_HEADER)+sizeof(ACCESS_MASK)))
				return ERROR_INVALID_PARAMETER;

			// Canonicalize AccessMask
			if (*pAccessMask & COM_RIGHTS_EXECUTE)
			{
				// When COM_RIGHTS_EXECUTE is set but no other RIGHTS
				// This means grant all other RIGHTS
				if ((*pAccessMask & dwOtherRights) == 0)
					*pAccessMask |= dwOtherRights;
			}
			else
			{
				// COM_RIGHTS_EXECUTE Not Set so clear all other RIGHTS bits
				*pAccessMask &= ~dwOtherRights;
			}

			ulptrACL = (ULONG_PTR)pAceHeader;
			pAceHeader = (PACE_HEADER)(ulptrACL + dwAceSize);
			pAccessMask = (PACCESS_MASK)((ULONG_PTR)pAceHeader + sizeof(ACE_HEADER));
		}
	}

	return ERROR_SUCCESS;
}

DWORD COxtSecurityHelper::RemovePrincipalFromACL(PACL paclOrig, LPCTSTR tszPrincipal)
{
	ACL_SIZE_INFORMATION  aclSizeInfo	   = {0};
	LONG				  i;
	LPVOID				  pvAce			   = NULL;
	ACCESS_DENIED_ACE	 *pAccessDeniedAce = NULL;
	PSID				  psidPrincipal	   = NULL;
	DWORD				  dwReturnValue	   = ERROR_SUCCESS;
	ACE_HEADER		     *pAceHeader	   = NULL;
	DWORD				  dwFoundValue	   = ERROR_FILE_NOT_FOUND;

	do {
		dwReturnValue = GetPrincipalSID(tszPrincipal, &psidPrincipal);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		if (!::GetAclInformation(paclOrig, (LPVOID)&aclSizeInfo,
								 sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		for (i = aclSizeInfo.AceCount - 1; i >= 0; i--)
		{
			if (!::GetAce(paclOrig, i, &pvAce))
			{
				dwReturnValue = ::GetLastError();
				break; // inner loop
			}

			pAceHeader = (ACE_HEADER*)pvAce;

			// Searching for ACCESS_DENIED_ACE_TYPE types only
			if (pAceHeader->AceType == ACCESS_DENIED_ACE_TYPE)
			{
				pAccessDeniedAce = (ACCESS_DENIED_ACE*)pvAce;

				if (::EqualSid(psidPrincipal, (PSID)&pAccessDeniedAce->SidStart))
				{
					if (pAccessDeniedAce->Mask & SPECIFIC_RIGHTS_ALL)
						::DeleteAce(paclOrig, i);

					dwFoundValue = ERROR_SUCCESS;
				}
			}
		}
	} while (false);

	if (psidPrincipal != NULL)
		::LocalFree(psidPrincipal);

	if (dwReturnValue == ERROR_SUCCESS)
		dwReturnValue = dwFoundValue;

	return dwReturnValue;
}

DWORD COxtSecurityHelper::UpdatePrincipalInACL(PACL paclOrig, LPCTSTR tszPrincipal, DWORD dwAccessMask)
{
	ACL_SIZE_INFORMATION aclSizeInfo	   = {0};
	LONG				 i;
	LPVOID				 pvAce			   = NULL;
	ACCESS_ALLOWED_ACE  *pAccessAllowedAce = NULL;
	ACCESS_DENIED_ACE   *pAccessDeniedAce  = NULL;
	SYSTEM_AUDIT_ACE	*pSystemAuditAce   = NULL;
	PSID				 psidPrincipal	   = NULL;
	DWORD				 dwReturnValue	   = ERROR_SUCCESS;
	ACE_HEADER		    *pAceHeader		   = NULL;
	DWORD				 dwFoundValue	   = ERROR_FILE_NOT_FOUND;

	do {
		// Construct a SID for this principal
		dwReturnValue = GetPrincipalSID(tszPrincipal, &psidPrincipal);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		if (!::GetAclInformation(paclOrig, (LPVOID)&aclSizeInfo,
								 sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		// Iterate through all of the ACEs in this ACL looking for a SID that corresponds
		// to the principal.
		for (i = aclSizeInfo.AceCount - 1; i >= 0; i--)
		{
			if (!::GetAce(paclOrig, i, &pvAce))
			{
				dwReturnValue = ::GetLastError();
				break; // inner loop
			}

			pAceHeader = (ACE_HEADER*)pvAce;

			// Searching for ACCESS_DENIED_ACE_TYPE types only
			if (pAceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
			{
				pAccessAllowedAce = (ACCESS_ALLOWED_ACE*)pvAce;

				if (::EqualSid(psidPrincipal, (PSID)&pAccessAllowedAce->SidStart))
				{
					// Found an ACE, modify the mask bits
					if (pAccessAllowedAce->Mask & SPECIFIC_RIGHTS_ALL)
					{
						pAccessAllowedAce->Mask &= ~dwAccessMask;
						// If there are any COM rights reamining we must ensure
						// COM_RIGHTS_EXECUTE is set before leaving.
						if (pAccessAllowedAce->Mask & (COM_RIGHTS_ACTIVATE_LOCAL  |
													   COM_RIGHTS_ACTIVATE_REMOTE |
													   COM_RIGHTS_EXECUTE_LOCAL   |
													   COM_RIGHTS_EXECUTE_REMOTE))
						{
							pAccessAllowedAce->Mask |= COM_RIGHTS_EXECUTE;
						}
						else if((pAccessAllowedAce->Mask & SPECIFIC_RIGHTS_ALL) == 0)
						{
							// If there are no more specific rights on this ACE, delete it.
							::DeleteAce(paclOrig, i);
						}
					}
					else
					{
						pAccessAllowedAce->Mask |= dwAccessMask;
					}
					dwFoundValue = ERROR_SUCCESS;
				}
			}
		}
	} while (false);

	if (psidPrincipal != NULL)
		::LocalFree(psidPrincipal);

	if (dwReturnValue == ERROR_SUCCESS)
		dwReturnValue = dwFoundValue;

	return dwReturnValue;
}

DWORD COxtSecurityHelper::MakeAbsoluteSecurityDescriptor(PSECURITY_DESCRIPTOR psidOld,
														 PSECURITY_DESCRIPTOR *psidNew)
{
	PSECURITY_DESCRIPTOR  pSid		   = NULL;
	DWORD				  cbDescriptor   = 0;
	DWORD				  cbDacl		 = 0;
	DWORD				  cbSacl		 = 0;
	DWORD				  cbOwnerSID	 = 0;
	DWORD				  cbGroupSID	 = 0;
	PACL				  pDacl		  = NULL;
	PACL				  pSacl		  = NULL;
	PSID				  psidOwner	  = NULL;
	PSID				  psidGroup	  = NULL;
	BOOL				  bPresent	     = FALSE;
	BOOL				  bSystemDefault = FALSE;
	DWORD				  dwReturnValue  = ERROR_SUCCESS;

	do {
		if (!::GetSecurityDescriptorSacl(psidOld, &bPresent, &pSacl, &bSystemDefault))
		{
			dwReturnValue = GetLastError();
			break;
		}

		if ((pSacl != NULL)&&(bPresent))
			cbSacl = pSacl->AclSize;

		if (!::GetSecurityDescriptorDacl(psidOld, &bPresent, &pDacl, &bSystemDefault))
		{
			dwReturnValue = GetLastError();
			break;
		}

		if ((pDacl != NULL)&&(bPresent))
			cbDacl = pDacl->AclSize;

		if (!::GetSecurityDescriptorOwner(psidOld, &psidOwner, &bSystemDefault))
		{
			dwReturnValue = GetLastError();
			break;
		}

		cbOwnerSID = GetLengthSid(psidOwner);

		if (!::GetSecurityDescriptorGroup(psidOld, &psidGroup, &bSystemDefault))
		{
			dwReturnValue = GetLastError();
			break;
		}

		cbGroupSID = GetLengthSid(psidGroup);

		// Do the conversion
		cbDescriptor = 0;

		::MakeAbsoluteSD(psidOld, pSid, &cbDescriptor, pDacl, &cbDacl, pSacl,
						 &cbSacl, psidOwner, &cbOwnerSID, psidGroup, &cbGroupSID);

		pSid = (PSECURITY_DESCRIPTOR)malloc(cbDescriptor);
		if (pSid == NULL)
		{
			dwReturnValue = ERROR_OUTOFMEMORY;
			break;
		}

		::ZeroMemory(pSid, cbDescriptor);

		if (!::InitializeSecurityDescriptor(pSid, SECURITY_DESCRIPTOR_REVISION))
		{
			dwReturnValue = GetLastError();
			break;
		}

		if (!::MakeAbsoluteSD(psidOld, pSid, &cbDescriptor, pDacl, &cbDacl, pSacl,
							  &cbSacl, psidOwner, &cbOwnerSID, psidGroup, &cbGroupSID))
		{
			dwReturnValue = GetLastError();
			break;
		}

	} while (false);

	if ((dwReturnValue != ERROR_SUCCESS)&&(pSid != NULL))
	{
		free(pSid);
		pSid = NULL;
	}

	*psidNew = pSid;

	return dwReturnValue;
}

DWORD COxtSecurityHelper::RemovePrincipalFromSecurityDescriptor(LPCTSTR tszPermissionName,
																LPCTSTR tszPrincipal)
{
	DWORD				 dwReturnValue   = ERROR_SUCCESS;
	SECURITY_DESCRIPTOR *pSD			 = NULL;
	SECURITY_DESCRIPTOR *psdSelfRelative = NULL;
	SECURITY_DESCRIPTOR *psdAbsolute	 = NULL;
	DWORD				 cbSecurityDesc  = 0;
	BOOL				 bPresent		 = FALSE;
	BOOL				 bDefaultDACL	 = FALSE;
	PACL				 pDacl			 = NULL;

	do {
		// Get security descriptor from registry, if it is not there then
		// just return - nothing to do.
		dwReturnValue = GetSecurityDescripterByName(tszPermissionName, &pSD, NULL);
		if (dwReturnValue != ERROR_SUCCESS)
		{
			if (dwReturnValue == ERROR_FILE_NOT_FOUND)
				dwReturnValue = ERROR_SUCCESS;
			break;
		}

		if (!::GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefaultDACL))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		// Remove the Principal that the caller wants removed
		dwReturnValue = RemovePrincipalFromACL(pDacl, tszPrincipal);
		if (dwReturnValue == ERROR_FILE_NOT_FOUND)
		{
			dwReturnValue = ERROR_SUCCESS;
			break;
		}
		else if (dwReturnValue != ERROR_SUCCESS)
			break;

		// Make the security descriptor absolute if it isn't new
		dwReturnValue = MakeAbsoluteSecurityDescriptor((PSECURITY_DESCRIPTOR)pSD, (PSECURITY_DESCRIPTOR *)&psdAbsolute);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		// Set the discretionary ACL on the security descriptor
		if (!::SetSecurityDescriptorDacl(psdAbsolute, TRUE, pDacl, FALSE))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		// Make the security descriptor self-relative so that we can
		// store it in the registry
		cbSecurityDesc = 0;
		::MakeSelfRelativeSD(psdAbsolute, psdSelfRelative, &cbSecurityDesc);

		psdSelfRelative = (SECURITY_DESCRIPTOR *)malloc(cbSecurityDesc);
		if (psdSelfRelative == NULL)
		{
			dwReturnValue = ERROR_OUTOFMEMORY;
			break;
		}

		if (!::MakeSelfRelativeSD(psdAbsolute, psdSelfRelative, &cbSecurityDesc))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		// Store the security descriptor in the registry
		dwReturnValue = SetSecurityDescriptorByName(tszPermissionName, psdSelfRelative);
	} while (false);

	if (pSD != NULL)
		free(pSD);
	if (psdSelfRelative != NULL)
		free(psdSelfRelative);
	if (psdAbsolute != NULL)
		free(psdAbsolute);

	return dwReturnValue;
}

DWORD COxtSecurityHelper::UpdatePrincipalInNamedSecurityDescriptor(LPCTSTR tszPermissionName,
																   LPCTSTR tszPrincipal,
																   DWORD dwAccessMask)
{
	DWORD				 dwReturnValue	 = ERROR_SUCCESS;
	SECURITY_DESCRIPTOR *pSD			 = NULL;
	SECURITY_DESCRIPTOR *psdSelfRelative = NULL;
	SECURITY_DESCRIPTOR *psdAbsolute	 = NULL;
	DWORD				 cbSecurityDesc  = 0;
	BOOL				 bPresent		 = FALSE;
	BOOL				 bDefaultDACL	 = FALSE;
	PACL				 pDacl			 = NULL;

	do {
		// Get security descriptor from registry
		dwReturnValue = GetSecurityDescripterByName(tszPermissionName, &pSD, NULL);
		if (dwReturnValue != ERROR_SUCCESS)
		{
			if (dwReturnValue == ERROR_FILE_NOT_FOUND)
				dwReturnValue = ERROR_SUCCESS;
			break;
		}

		if (!::GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefaultDACL))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		// Update the tszPrincipal that the caller wants to change
		dwReturnValue = UpdatePrincipalInACL(pDacl, tszPrincipal, dwAccessMask);
		if(dwReturnValue == ERROR_FILE_NOT_FOUND)
		{
			dwReturnValue = ERROR_SUCCESS;
			break;
		}
		else if (dwReturnValue != ERROR_SUCCESS)
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		// Make the security descriptor absolute
		dwReturnValue = MakeAbsoluteSecurityDescriptor((PSECURITY_DESCRIPTOR)pSD,
													   (PSECURITY_DESCRIPTOR *)&psdAbsolute);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		// Set the discretionary ACL on the security descriptor
		if (!::SetSecurityDescriptorDacl(psdAbsolute, TRUE, pDacl, FALSE))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		// Now ensure consistency of the SD
		dwReturnValue = CanonicalizeSecurityDescriptor(psdAbsolute);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		// Make the security descriptor self-relative so that we can
		// store it in the registry
		cbSecurityDesc = 0;
		::MakeSelfRelativeSD(psdAbsolute, psdSelfRelative, &cbSecurityDesc);

		psdSelfRelative = (SECURITY_DESCRIPTOR *)malloc(cbSecurityDesc);
		if (psdSelfRelative == NULL)
		{
			dwReturnValue = ERROR_OUTOFMEMORY;
			break;
		}

		if (!::MakeSelfRelativeSD(psdAbsolute, psdSelfRelative, &cbSecurityDesc))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		// Store the security descriptor in the registry
		dwReturnValue = SetSecurityDescriptorByName(tszPermissionName, psdSelfRelative);
	} while (false);

	if (pSD != NULL)
		free(pSD);
	if (psdSelfRelative != NULL)
		free(psdSelfRelative);
	if (psdAbsolute != NULL)
		free(psdAbsolute);

	return dwReturnValue;
}

DWORD COxtSecurityHelper::AddPrincipalToNamedSecurityDescriptor(LPCTSTR tszPermissionName,
																LPCTSTR tszPrincipal,
																DWORD dwAccessMask,
																DWORD dwSDType)
{
	DWORD				 dwReturnValue	 = ERROR_SUCCESS;
	SECURITY_DESCRIPTOR *pSD			 = NULL;
	SECURITY_DESCRIPTOR *psdSelfRelative = NULL;
	SECURITY_DESCRIPTOR *psdAbsolute	 = NULL;
	DWORD				 cbSecurityDesc  = 0;
	BOOL				 bPresent		 = FALSE;
	BOOL				 bDefaultDACL	 = FALSE;
	PACL				 pDacl			 = NULL;
	BOOL				 bNewSD		     = FALSE;

	do {
		// Get security descriptor from registry or create a new one
		dwReturnValue = GetSecurityDescripterByName(tszPermissionName, &pSD, &bNewSD);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		if (!::GetSecurityDescriptorDacl(pSD, &bPresent, &pDacl, &bDefaultDACL))
		{
			dwReturnValue = ::GetLastError();
			break;
		}

		if (bNewSD)
		{
			dwReturnValue = SetACLDefaults(&pDacl, dwSDType);
			if (dwReturnValue != ERROR_SUCCESS)
				break;
		}

		// Add the Principal that the caller wants added
		dwReturnValue = AddAccessDeniedACEToACL(&pDacl, dwAccessMask, tszPrincipal);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		// Make the security descriptor absolute if it isn't new
		if (!bNewSD)
		{
			dwReturnValue = MakeAbsoluteSecurityDescriptor((PSECURITY_DESCRIPTOR)pSD,
														   (PSECURITY_DESCRIPTOR *)&psdAbsolute);
			if (dwReturnValue != ERROR_SUCCESS)
				break;
		}
		else
			psdAbsolute = pSD;

		// Set the discretionary ACL on the security descriptor
		if (!::SetSecurityDescriptorDacl(psdAbsolute, TRUE, pDacl, FALSE))
		{
			dwReturnValue = ::GetLastError();
			break;
		 }

		// Now ensure consistency of the SD
		dwReturnValue = CanonicalizeSecurityDescriptor(psdAbsolute);
		if (dwReturnValue != ERROR_SUCCESS)
			break;

		// Make the security descriptor self-relative so that we can
		// store it in the registry
		cbSecurityDesc = 0;

		::MakeSelfRelativeSD(psdAbsolute, psdSelfRelative, &cbSecurityDesc);

		psdSelfRelative = (SECURITY_DESCRIPTOR *)malloc(cbSecurityDesc);

		if (psdSelfRelative == NULL)
		{
			dwReturnValue = ERROR_OUTOFMEMORY;
			break;
		}

		if (!::MakeSelfRelativeSD(psdAbsolute, psdSelfRelative, &cbSecurityDesc))
		{
			dwReturnValue = GetLastError();
			break;
		}

		// Store the security descriptor in the registry
		dwReturnValue = SetSecurityDescriptorByName(tszPermissionName, psdSelfRelative);
	} while (false);


	if (pSD != NULL)
		free(pSD);
	if (psdSelfRelative != NULL)
		free(psdSelfRelative);
	if ((psdAbsolute != NULL)&&(pSD != psdAbsolute))
		free(psdAbsolute);

	return dwReturnValue;
}

void COxtSecurityHelper::DenyRemoteAccess()
{
	DWORD dwRet = ERROR_SUCCESS;
	int   i;

	for (i = 0; i < XSH_PRINCIPAL_COUNT; i++)
	{
		// Loop and update each of the 3 Principals with deny remote
		// access SDs.
		dwRet = RemovePrincipalFromSecurityDescriptor(_T("AccessPermission"),
													  g_ptszPrincipals[i]);
		if (dwRet != ERROR_SUCCESS)
		{
			LogSecuritySetupFailure(g_ptszPrincipals[i],
									_T("AccessPermission"),
									_T("RemovePrincipalFromSecurityDescriptor"),
									dwRet);
			break;
		}

		dwRet = UpdatePrincipalInNamedSecurityDescriptor(_T("AccessPermission"),
														 g_ptszPrincipals[i],
														 g_dwAccessAccessMask);
		if (dwRet != ERROR_SUCCESS)
		{
			LogSecuritySetupFailure(g_ptszPrincipals[i],
									_T("AccessPermission"),
									_T("UpdatePrincipalInNamedSecurityDescriptor"),
									dwRet);
			break;
		}

		dwRet = AddPrincipalToNamedSecurityDescriptor(_T("AccessPermission"),
													  g_ptszPrincipals[i],
													  g_dwAccessAccessMask,
													  SDTYPE_APPLICATION_ACCESS);
		if (dwRet != ERROR_SUCCESS)
		{
			LogSecuritySetupFailure(g_ptszPrincipals[i],
									_T("AccessPermission"),
									_T("AddPrincipalToNamedSecurityDescriptor"),
									dwRet);
			break;
		}
	}
}

void COxtSecurityHelper::DenyRemoteLaunchAndActivate()
{
	DWORD dwRet = ERROR_SUCCESS;
	int   i;

	for (i = 0; i < XSH_PRINCIPAL_COUNT; i++)
	{
		// Loop and update each of the 3 Principals with deny remote
		// access SDs.
		dwRet = RemovePrincipalFromSecurityDescriptor(_T("LaunchPermission"),
													  g_ptszPrincipals[i]);
		if (dwRet != ERROR_SUCCESS)
		{
			LogSecuritySetupFailure(g_ptszPrincipals[i],
									_T("LaunchPermission"),
									_T("RemovePrincipalFromSecurityDescriptor"),
									dwRet);
			break;
		}

		dwRet = UpdatePrincipalInNamedSecurityDescriptor(_T("LaunchPermission"),
														 g_ptszPrincipals[i],
														 g_dwLaunchActivateMask);
		if (dwRet != ERROR_SUCCESS)
		{
			LogSecuritySetupFailure(g_ptszPrincipals[i],
									_T("LaunchPermission"),
									_T("UpdatePrincipalInNamedSecurityDescriptor"),
									dwRet);
			break;
		}

		dwRet = AddPrincipalToNamedSecurityDescriptor(_T("LaunchPermission"),
													  g_ptszPrincipals[i],
													  g_dwLaunchActivateMask,
													  SDTYPE_APPLICATION_LAUNCH);
		if (dwRet != ERROR_SUCCESS)
		{
			LogSecuritySetupFailure(g_ptszPrincipals[i],
									_T("LaunchPermission"),
									_T("AddPrincipalToNamedSecurityDescriptor"),
									dwRet);
			break;
		}
	}
}

void COxtSecurityHelper::LogDenyCheckFailure(LPCTSTR tszPermissionName,
											 LPCTSTR tszOp)
{
	m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_DENY_CHECK_FAILURE___PERMISSION__OXTSECURITYHELPER_1244),
							 EVENTLOG_ERROR_TYPE,
							 EVMSG_SECURITY_FAILURE,
							 tszPermissionName,
							 tszOp,
							 ::GetLastError());
}

bool COxtSecurityHelper::DenyCheckUser(DWORD dwAccessMask,
									   DWORD dwSDType,
									   LPCTSTR tszUser,
									   LPCTSTR tszDomain,
									   BOOL bPermit)
{

	if (IsLegacySecurityModel())
	{
		// We don't really support anything lower than XPSP3 so we will just
		// drop out on the legacy check.
		// NOTE: removed check for WarnIfGlobalPolicySet()
		return true;
	}

	// All local access is fine and this check is not concerned with whether
	// everything has been denied. So the only case that is bad is permitting
	// remote access.

	if (dwSDType & SDTYPE_APPLICATION_ACCESS)
	{
		BOOL bRemoteAccess = (dwAccessMask & COM_RIGHTS_EXECUTE_REMOTE  ) ||
							 ((dwAccessMask & COM_RIGHTS_EXECUTE) &&
							  !(dwAccessMask & COM_RIGHTS_EXECUTE_LOCAL));

		if ((bPermit)&&(bRemoteAccess))
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_DENY_REMOTE_CHECK_FOR_zS_DETECTE_OXTSECURITYHELPER_1279),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE,
									 _T("AccessPermission"));
			return false;
		}
	}

	if (dwSDType & SDTYPE_APPLICATION_LAUNCH)
	{
		BOOL bRemoteLaunchAccess = (dwAccessMask & COM_RIGHTS_EXECUTE_REMOTE  ) ||
							 ((dwAccessMask & COM_RIGHTS_EXECUTE) &&
							 !(dwAccessMask & (COM_RIGHTS_EXECUTE_LOCAL   |
											   COM_RIGHTS_ACTIVATE_REMOTE |
											   COM_RIGHTS_ACTIVATE_LOCAL)));

		BOOL bRemoteActivateAccess = (dwAccessMask & COM_RIGHTS_ACTIVATE_REMOTE) ||
							 ((dwAccessMask & COM_RIGHTS_EXECUTE) &&
							 !(dwAccessMask & (COM_RIGHTS_EXECUTE_LOCAL  |
											   COM_RIGHTS_EXECUTE_REMOTE |
											   COM_RIGHTS_ACTIVATE_LOCAL)));
		if ((bPermit)&&(bRemoteLaunchAccess))
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_DENY_REMOTE_CHECK_FOR_zS_DETECTE_OXTSECURITYHELPER_1301),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE,
									 _T("LaunchPermission-Launch"));
			return false;
		}

		if ((bPermit)&&(bRemoteActivateAccess))
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_DENY_REMOTE_CHECK_FOR_zS_DETECTE_OXTSECURITYHELPER_1309),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE,
									 _T("LaunchPermission-Activate"));
			return false;
		}
	}

	return true;
}

bool COxtSecurityHelper::DenyCheckACL(PACL pACL, LPCTSTR tszPermissionName, DWORD dwSDType)
{
	ACL_SIZE_INFORMATION	  aclSizeInfo					  = {0};
	ACL_REVISION_INFORMATION  aclRevInfo					  = {0};
	ULONG					  i;
	LPVOID					  pvAce						      = NULL;
	ACE_HEADER			     *pAceHeader					  = NULL;
	ACCESS_ALLOWED_ACE	     *pAccessAllowedAce			      = NULL;
	ACCESS_DENIED_ACE		 *pAccessDeniedAce				  = NULL;
	TCHAR					  tszDomainName[XSH_NAME_LEN + 1] = {0};
	TCHAR					  tszUserName[XSH_NAME_LEN + 1]   = {0};
	DWORD					  cchName						  = 0;
	SID_NAME_USE			  snu;
	BOOL					  rc;
	BOOL					  bPermit;
	PSID					  pSID;
	ACCESS_MASK			      dwMask;

	if (!::GetAclInformation(pACL, &aclSizeInfo, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation))
	{
		LogDenyCheckFailure(tszPermissionName, _T("GET AclSizeInformation"));
		return false;
	}

	if (!::GetAclInformation(pACL, &aclRevInfo, sizeof(ACL_REVISION_INFORMATION), AclRevisionInformation))
	{
		LogDenyCheckFailure(tszPermissionName, _T("GET AclRevisionInformation"));
		return false;
	}

	for (i = 0; i < aclSizeInfo.AceCount; i++)
	{
		rc = ::GetAce(pACL, i, &pvAce);
		if (!rc)
		{
			LogDenyCheckFailure(tszPermissionName, _T("GetAce"));
			return false;
		}

		pAceHeader = (ACE_HEADER*)pvAce;

		if (pAceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			pAccessAllowedAce = (ACCESS_ALLOWED_ACE*)pvAce;
			pSID = (PSID)&pAccessAllowedAce->SidStart;
			dwMask = pAccessAllowedAce->Mask;
			bPermit = TRUE;
		}
		else if (pAceHeader->AceType == ACCESS_DENIED_ACE_TYPE)
		{
			pAccessDeniedAce = (ACCESS_DENIED_ACE*)pvAce;
			pSID = (PSID)&pAccessDeniedAce->SidStart;
			dwMask = pAccessDeniedAce->Mask;
			bPermit = FALSE;
		}

		cchName = XSH_NAME_LEN;
		rc = ::LookupAccountSid(NULL,
								pSID,
								tszUserName,
								&cchName,
								tszDomainName,
								&cchName,
								&snu);

		if (!rc)
		{
			LogDenyCheckFailure(tszPermissionName, _T("LookupAccountSid"));
			return false;
		}

		rc = DenyCheckUser(dwMask,
						   dwSDType,
						   tszUserName,
						   tszDomainName,
						   bPermit);
		if (!rc)
			return false;
	}

	return true;
}

bool COxtSecurityHelper::CheckDenyRemoteAccess()
{
	DWORD				 dwReturnValue = ERROR_SUCCESS;
	SECURITY_DESCRIPTOR *pSD		   = NULL;
	BOOL				 bPresent	   = FALSE;
	BOOL				 bDefaultDACL  = FALSE;
	PACL				 pDACL		   = NULL;
	bool				 rc = true;

	// First test AccessPermission for denied remote access
	do {
		dwReturnValue = GetSecurityDescripterByName(_T("AccessPermission"), &pSD, NULL);
		if (dwReturnValue != ERROR_SUCCESS)
		{
			// using default, no SD for this permission
			LogDenyCheckFailure(_T("AccessPermission"), _T("NO SD (using defaults)"));
			rc = false;
			break;
		}

		if (!::GetSecurityDescriptorDacl(pSD, &bPresent, &pDACL, &bDefaultDACL))
		{
			LogDenyCheckFailure(_T("AccessPermission"), _T("GET SD DACL"));
			rc = false;
			break;
		}

		if (!bPresent)
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_DENY_CHECK_FOUND_NO_SD_DACL_FOR__OXTSECURITYHELPER_1431),
									 EVENTLOG_WARNING_TYPE, EVMSG_SECURITY_WARNING,
									 _T("AccessPermission"));
			// go on with other checks for launch access below
			break;
		}

		rc = DenyCheckACL(pDACL, _T("AccessPermission"), SDTYPE_APPLICATION_ACCESS);
		// Specific issues logged in call
	} while (false);

	if (pSD != NULL)
	{
		free(pSD);
		pSD = NULL;
	}

	if (!rc)
		return false; // first check failed

	dwReturnValue = ERROR_SUCCESS;
	bPresent	  = FALSE;
	bDefaultDACL  = FALSE;
	pDACL		  = NULL;

	// Now test LaunchPermission for denied remote access
	do {
		dwReturnValue = GetSecurityDescripterByName(_T("LaunchPermission"), &pSD, NULL);
		if (dwReturnValue != ERROR_SUCCESS)
		{
			// using default, no SD for this permission
			LogDenyCheckFailure(_T("AccessPermission"), _T("NO SD (using defaults)"));
			rc = false;
			break;
		}

		if (!::GetSecurityDescriptorDacl(pSD, &bPresent, &pDACL, &bDefaultDACL))
		{
			LogDenyCheckFailure(_T("LaunchPermission"), _T("GET SD DACL"));
			rc = false;
			break;
		}

		if (!bPresent)
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_DENY_CHECK_FOUND_NO_SD_DACL_FOR__OXTSECURITYHELPER_1476),
									 EVENTLOG_WARNING_TYPE, EVMSG_SECURITY_WARNING,
									 _T("LaunchPermission"));
			// go on with other checks for launch access below
			break;
		}

		rc = DenyCheckACL(pDACL, _T("LaunchPermission"), SDTYPE_APPLICATION_LAUNCH);
		// Specific issues logged in call
	} while (false);

	if (pSD != NULL)
	{
		free(pSD);
		pSD = NULL;
	}

	return rc;
}

// DACL to allow interactive users access to named events and objects
static const WCHAR g_XgsEventDACL[] =
{
	SDDL_DACL SDDL_DELIMINATOR SDDL_PROTECTED

	// Local system - full access
	SDDL_ACE_BEGIN
	SDDL_ACCESS_ALLOWED
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_GENERIC_ALL
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_LOCAL_SYSTEM
	SDDL_ACE_END

	// Creator/Owner - full access
	SDDL_ACE_BEGIN
	SDDL_ACCESS_ALLOWED
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_GENERIC_ALL
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_CREATOR_OWNER
	SDDL_ACE_END

	// LocalService - All access.
	SDDL_ACE_BEGIN
	SDDL_ACCESS_ALLOWED
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_GENERIC_ALL
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_LOCAL_SERVICE
	SDDL_ACE_END

	// Interactive - All access.
	SDDL_ACE_BEGIN
	SDDL_ACCESS_ALLOWED
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_GENERIC_ALL
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_SEPERATOR
	SDDL_INTERACTIVE
	SDDL_ACE_END
};

SECURITY_ATTRIBUTES* COxtSecurityHelper::CreateXgaSecurityAttributes()
{
	SECURITY_ATTRIBUTES  *pSA   = NULL;
	PSECURITY_DESCRIPTOR  pSD = NULL;
	BOOL				  rc;

	pSA = (SECURITY_ATTRIBUTES*)::LocalAlloc(LMEM_FIXED, sizeof(SECURITY_ATTRIBUTES));
	if (pSA == NULL)
	{
		m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_TO_ALLOCATE_SECURITY_ATTR_OXTSECURITYHELPER_1559),
								 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE);
		return NULL;
	}
	pSA->nLength = sizeof(SECURITY_ATTRIBUTES);
	pSA->bInheritHandle = FALSE;

	rc = ::ConvertStringSecurityDescriptorToSecurityDescriptor(g_XgsEventDACL, SDDL_REVISION_1, &pSD, NULL);
	if ((!rc)||(pSD == NULL))
	{
		m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_TO_CREATE_SECURITY_DESCRI_OXTSECURITYHELPER_1569),
								 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE,
								 (pSD == NULL) ? ERROR_OUTOFMEMORY : ::GetLastError());
		::LocalFree(pSA);
		return NULL;
	}
	pSA->lpSecurityDescriptor = pSD;

	return pSA;
}

SECURITY_ATTRIBUTES* COxtSecurityHelper::CreateXgaSecurityAttributesAbsolute()
{
	DWORD				 dwRet		 = ERROR_SUCCESS;
	PSECURITY_DESCRIPTOR pSD		 = NULL;
	PSECURITY_ATTRIBUTES pSA;
	ULONG				 ulSdSize	 = 0;
	ULONG				 ulDaclSize	 = 0;
	ULONG				 ulSaclSize	 = 0;
	ULONG				 ulOwnerSize = 0;
	ULONG				 ulGroupSize = 0;
	ULONG				 ulNewSdSize = 0;
	PACL				 pDACL;
	PACL				 pSACL;
	PSID				 pOwner;
	PSID				 pGroup;

	// First create our relate descriptor
	pSA = CreateXgaSecurityAttributes();
	if (pSA == NULL)
		return NULL;

	// Determine buffer size needed to convert self-relative SD to absolute.
	if (!::MakeAbsoluteSD(pSA->lpSecurityDescriptor,
						  NULL, &ulSdSize,
						  NULL, &ulDaclSize,
						  NULL, &ulSaclSize,
						  NULL, &ulOwnerSize,
						  NULL, &ulGroupSize))
	{
	   dwRet = GetLastError();
	}

	if (dwRet != ERROR_INSUFFICIENT_BUFFER)
	{
		m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_TO_GET_SIZES_FROM_MAKEABS_OXTSECURITYHELPER_1614),
								 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE, dwRet);
		FreeXgaSecurityAttributes(pSA);
		return NULL;
	}

	// Allocate memory for the absolute SD and setup various pointers
	ulNewSdSize = ulSdSize + ulDaclSize + ulSaclSize + ulOwnerSize + ulGroupSize;
	pSD = (SECURITY_DESCRIPTOR*)::LocalAlloc(LMEM_FIXED, ulNewSdSize);
	if (pSD == NULL)
	{
		m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_TO_ALLOCATE_SECURITY_DESC_OXTSECURITYHELPER_1625),
								 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE);
		FreeXgaSecurityAttributes(pSA);
		return NULL;
	}

	pDACL  = (PACL)((PCHAR)pSD	+ ulSdSize);
	pSACL  = (PACL)((PCHAR)pDACL  + ulDaclSize);
	pOwner = (PSID)((PCHAR)pSACL  + ulSaclSize);
	pGroup = (PSID)((PCHAR)pOwner + ulOwnerSize);

	// Now convert self-relative SD to absolute format.
	if (!::MakeAbsoluteSD(pSA->lpSecurityDescriptor,
						  pSD, &ulSdSize,
						  pDACL, &ulDaclSize,
						  pSACL, &ulSaclSize,
						  pOwner, &ulOwnerSize,
						  pGroup, &ulGroupSize))
	{
		m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_CREATE_SD_IN_MAKEABSOLUTE_OXTSECURITYHELPER_1644),
								 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE, ::GetLastError());
		::LocalFree(pSD);
		FreeXgaSecurityAttributes(pSA);
		return NULL;
	}

	// Free the original SD and set the new one.
	::LocalFree(pSA->lpSecurityDescriptor);
	pSA->lpSecurityDescriptor = pSD;

	return pSA;
}

void COxtSecurityHelper::FreeXgaSecurityAttributes(SECURITY_ATTRIBUTES *pSA)
{
	if (pSA != NULL)
	{
		if (pSA->lpSecurityDescriptor != NULL)
			::LocalFree(pSA->lpSecurityDescriptor);
		::LocalFree(pSA);
	}
}

WINADVAPI
BOOL
WINAPI
CreateWellKnownSid(
	__in	 WELL_KNOWN_SID_TYPE WellKnownSidType,
	__in_opt PSID DomainSid,
	__out_bcount_part_opt(*cbSid, *cbSid) PSID pSid,
	__inout  DWORD *cbSid
	);

XSH_DESCRIPTOR* COxtSecurityHelper::CreateXgaComSecurityDescriptor()
{
	DWORD dwRet;
	DWORD dwSidSize;
	BOOL  bRet;
	XSH_DESCRIPTOR *pXD = NULL;
	EXPLICIT_ACCESS ea = {0};

	pXD = (XSH_DESCRIPTOR*)::LocalAlloc(LMEM_FIXED, sizeof(XSH_DESCRIPTOR));
	if (pXD == NULL)
	{
		m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_TO_ALLOCATE_XSH_DESCRIPTO_OXTSECURITYHELPER_1689),
								 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE);
		return NULL;
	}
	::ZeroMemory(pXD, sizeof(XSH_DESCRIPTOR));

	do {
		bRet = ::InitializeSecurityDescriptor(&pXD->stSD, SECURITY_DESCRIPTOR_REVISION);
		if (!bRet)
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_TO_INITIALIZE_COM_SID___E_OXTSECURITYHELPER_1699),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE, ::GetLastError());
			break;
		}

		// Create some SIDs
		dwSidSize = SECURITY_MAX_SID_SIZE;
		pXD->pInteractivSID = (PSID*)::LocalAlloc(LMEM_FIXED, dwSidSize);
		if (pXD->pInteractivSID == NULL)
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_TO_ALLOCATE_PINTERACTIVSI_OXTSECURITYHELPER_1709),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE);
			bRet = FALSE;
			break;
		}

		pXD->pAdminsSID = (PSID*)::LocalAlloc(LMEM_FIXED, dwSidSize);
		if (pXD->pAdminsSID == NULL)
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_TO_ALLOCATE_ADMINS_SID_OXTSECURITYHELPER_1718),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE);
			bRet = FALSE;
			break;
		}

		bRet = ::CreateWellKnownSid(WinInteractiveSid, NULL, pXD->pInteractivSID, &dwSidSize);
		if (!bRet)
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_CREATEWELLKNOWNSID_PINTER_OXTSECURITYHELPER_1727),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE, ::GetLastError());
			break;
		}

		dwSidSize = SECURITY_MAX_SID_SIZE;
		bRet = ::CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, pXD->pAdminsSID, &dwSidSize);
		if (!bRet)
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_CREATEWELLKNOWNSID_PADMIN_OXTSECURITYHELPER_1736),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE, ::GetLastError());
			break;
		}

		// Setup AuthenticatedUsers for COM access.
		ea.grfAccessPermissions = COM_RIGHTS_EXECUTE;
		ea.grfAccessMode = SET_ACCESS;
		ea.grfInheritance = NO_INHERITANCE;
		ea.Trustee.pMultipleTrustee = NULL;
		ea.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
		ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		ea.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
		ea.Trustee.ptstrName = (LPTSTR)pXD->pInteractivSID;

		// Create the Interactive user ACL with this new ACE
		dwRet = ::SetEntriesInAcl(1, &ea, NULL, &pXD->pACL);
		if (dwRet != ERROR_SUCCESS)
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_SETENTRIESINACL_PINTERACT_OXTSECURITYHELPER_1755),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE, dwRet);
			bRet = FALSE;
			break;
		}

		// Setup Administrator as owner and group for SD
		bRet = ::SetSecurityDescriptorOwner(&pXD->stSD, pXD->pAdminsSID, FALSE);
		if (!bRet)
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_TO_SET_ADMINS_SID_AS_OWNE_OXTSECURITYHELPER_1765),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE, ::GetLastError());
			break;
		}

		bRet = ::SetSecurityDescriptorGroup(&pXD->stSD, pXD->pAdminsSID, FALSE);
		if (!bRet)
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_TO_SET_ADMINS_SID_AS_GROU_OXTSECURITYHELPER_1773),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE, ::GetLastError());
			break;
		}

		// Set ACL on descriptor
		bRet = ::SetSecurityDescriptorDacl(&pXD->stSD, TRUE, pXD->pACL, FALSE);
		if (!bRet)
		{
			m_pclOxtSvc->LogEventTypeId(ctxLS(IDS_FAILED_TO_SET_DACL_FOR_SD___ERRO_OXTSECURITYHELPER_1782),
									 EVENTLOG_ERROR_TYPE, EVMSG_SECURITY_FAILURE, ::GetLastError());
			break;
		}

	} while (false);

	if (!bRet)
	{
		FreeXgaComSecurityDescriptor(pXD);
		pXD = NULL;
	}

	return pXD;
}

void COxtSecurityHelper::FreeXgaComSecurityDescriptor(XSH_DESCRIPTOR* pXD)
{
	if (pXD != NULL)
	{
		if (pXD->pACL != NULL)
			::LocalFree(pXD->pACL);
		if (pXD->pAdminsSID != NULL)
			::LocalFree(pXD->pAdminsSID);
		if (pXD->pInteractivSID != NULL)
			::LocalFree(pXD->pInteractivSID);
		::LocalFree(pXD);
	}
}

