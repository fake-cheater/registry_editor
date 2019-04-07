#pragma once
#include <accctrl.h>
#include <aclapi.h>
#include <string_view>
#include "raii.hpp"

namespace privilege {
	bool set_privilege( ) {
		LUID luid{ };

		if ( !LookupPrivilegeValueA( NULL, SE_TAKE_OWNERSHIP_NAME, &luid ) )
			return false;

		HANDLE h_token = INVALID_HANDLE_VALUE;

		if ( !OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES, &h_token ) )
			return false;

		raii::handle raii_token( h_token );

		TOKEN_PRIVILEGES token_attributes{};

		token_attributes.PrivilegeCount = 1;
		token_attributes.Privileges[ 0 ].Luid = luid;
		token_attributes.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

		if ( !AdjustTokenPrivileges( raii_token.get( ), FALSE, &token_attributes, sizeof( TOKEN_PRIVILEGES ), nullptr, nullptr ) )
			return false;

		return true;
	}
	bool take_ownership( const LPSTR file_path ) {
		PSID sid_everyone = nullptr;
		SID_IDENTIFIER_AUTHORITY sid_world = SECURITY_WORLD_SID_AUTHORITY;

		if ( !AllocateAndInitializeSid( &sid_world, 1, SECURITY_WORLD_RID, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &sid_everyone ) )
			return false;

		EXPLICIT_ACCESS explicity{ };

		RtlZeroMemory( &explicity, sizeof( EXPLICIT_ACCESS_A ) );

		explicity.grfAccessPermissions = GENERIC_ALL;
		explicity.grfAccessMode = SET_ACCESS;
		explicity.grfInheritance = NO_INHERITANCE;
		explicity.Trustee.TrusteeForm = TRUSTEE_IS_SID;
		explicity.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
		explicity.Trustee.ptstrName = ( LPTSTR )sid_everyone;

		ACL* acl_entry = nullptr;

		if ( SetEntriesInAclA( 1, &explicity, NULL, &acl_entry ) != ERROR_SUCCESS )
			return false;

		privilege::set_privilege( );

		if ( SetNamedSecurityInfoA( file_path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, acl_entry, NULL ) != ERROR_SUCCESS )
			return false;

		return true;
	}
}