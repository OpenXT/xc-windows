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


#pragma once
#include "resource.h"	   // main symbols
#include "OxtService.h"

#define XSH_APPID_LEN 45

typedef struct _XSH_DESCRIPTOR
{
	SECURITY_DESCRIPTOR stSD;
	PACL				pACL;
	PSID				pAdminsSID;
	PSID				pInteractivSID;
} XSH_DESCRIPTOR, *PXSH_DESCRIPTOR;

class COxtSecurityHelper
{
private:
	COxtService *m_pclOxtSvc;
	TCHAR		m_tszAppIdKey[XSH_APPID_LEN + 1];

public:
	COxtSecurityHelper(COxtService *pclOxtSvc)
	{
		m_pclOxtSvc = pclOxtSvc;
		_sntprintf_s(m_tszAppIdKey, XSH_APPID_LEN, _TRUNCATE, _T("APPID\\%s"), CA2T(APPID_OxtService));
		m_tszAppIdKey[XSH_APPID_LEN] = _T('\0');
	}

	~COxtSecurityHelper()
	{
	}

	void DenyRemoteAccess();
	void DenyRemoteLaunchAndActivate();
	bool CheckDenyRemoteAccess();

	SECURITY_ATTRIBUTES* CreateXgaSecurityAttributes();
	SECURITY_ATTRIBUTES* CreateXgaSecurityAttributesAbsolute();
	void FreeXgaSecurityAttributes(SECURITY_ATTRIBUTES *pSA);

	XSH_DESCRIPTOR* CreateXgaComSecurityDescriptor();
	void FreeXgaComSecurityDescriptor(XSH_DESCRIPTOR* pXD);

private:
	void LogSecuritySetupFailure(LPCTSTR tszPrincipal,
								 LPCTSTR tszPermissionName,
								 LPCTSTR tszOp,
								 DWORD dwError);
	bool IsLegacySecurityModel();
	DWORD CopyACL(PACL paclOld, PACL paclNew);
	DWORD AddAccessAllowedACEToACL(PACL *paclOrig,
								   DWORD dwAccessMask,
								   LPCTSTR tszPrincipal);
	DWORD AddAccessDeniedACEToACL(PACL *paclOrig,
								  DWORD dwAccessMask,
								  LPCTSTR tszPrincipal);
	DWORD SetLegacyACLDefaults(PACL *ppDacl, DWORD dwSDType);
	DWORD SetACLDefaults(PACL *ppDacl, DWORD dwSDType);
	DWORD CreateNewSecurityDescriptor(SECURITY_DESCRIPTOR **ppSecurityDesc);
	DWORD GetPrincipalSIDByName(LPCTSTR tszPrincipal, PSID *ppSid);
	DWORD GetPrincipalSID(LPCTSTR tszPrincipal, PSID *ppSid);
	DWORD GetSecurityDescripterByName(LPCTSTR tszPermissionName,
									  SECURITY_DESCRIPTOR **ppSecurityDesc,
									  BOOL *pbNew);
	DWORD SetSecurityDescriptorByName(LPCTSTR tszPermissionName,
									  SECURITY_DESCRIPTOR *pSecurityDesc);
	DWORD CanonicalizeSecurityDescriptor(PSECURITY_DESCRIPTOR pSD);
	DWORD RemovePrincipalFromACL(PACL paclOrig, LPCTSTR tszPrincipal);
	DWORD UpdatePrincipalInACL(PACL paclOrig,
							   LPCTSTR tszPrincipal,
							   DWORD dwAccessMask);
	DWORD MakeAbsoluteSecurityDescriptor(PSECURITY_DESCRIPTOR psidOld,
										 PSECURITY_DESCRIPTOR *psidNew);
	DWORD RemovePrincipalFromSecurityDescriptor(LPCTSTR tszPermissionName,
												LPCTSTR tszPrincipal);
	DWORD UpdatePrincipalInNamedSecurityDescriptor(LPCTSTR tszPermissionName,
												   LPCTSTR tszPrincipal,
												   DWORD dwAccessMask);
	DWORD AddPrincipalToNamedSecurityDescriptor(LPCTSTR tszPermissionName,
												LPCTSTR tszPrincipal,
												DWORD dwAccessMask,
												DWORD dwSDType);
	void LogDenyCheckFailure(LPCTSTR tszPermissionName,
							 LPCTSTR tszOp);
	bool DenyCheckUser(DWORD dwAccessMask,
					   DWORD dwSDType,
					   LPCTSTR tszUser,
					   LPCTSTR tszDomain,
					   BOOL bPermit);
	bool DenyCheckACL(PACL pACL, LPCTSTR tszPermissionName, DWORD dwSDType);
};
