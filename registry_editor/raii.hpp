#pragma once
#include <windows.h>
#include <memory>
#include <cstdio>

namespace raii {
	struct registry_deleter {
		const void operator( )( const HKEY key ) noexcept {
			RegCloseKey( key );
		}
	};
	
	struct handle_deleter {
		const void operator( )( const HANDLE key ) noexcept {
			CloseHandle( key );
		}
	};

	using hkey = std::unique_ptr<std::remove_pointer_t<HKEY>, registry_deleter>;
	using handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, handle_deleter>;
}
