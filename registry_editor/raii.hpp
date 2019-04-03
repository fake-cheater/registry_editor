#pragma once
#include <windows.h>
#include <memory>

namespace raii {
	struct registry_deleter {
		const void operator( )( const HKEY key ) noexcept {
			RegCloseKey( key );
		}
	};

	using hkey = std::unique_ptr< std::remove_pointer_t<HKEY> >;
}