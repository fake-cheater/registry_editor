#include <chrono>
#include <thread>
#include <random>
#include <algorithm>
#include <array>
#include "raii.hpp"

// this is one of the worst applications I have ever written in my life, atleast it's modern.

#define out( text, ... ) std::printf( text, ##__VA_ARGS__ )

#pragma warning( disable : 4312 )

char random_char( ) {
	std::random_device random_device;
	std::mt19937 mersenne_generator( random_device( ) );
	std::uniform_int_distribution<> distribution( 97, 122 );

	return static_cast< unsigned char >( distribution( mersenne_generator ) );
}

int main( ) {
	out( "[+] registry spoofer by paracord initiated\n" );

	static constexpr std::size_t string_length = 16;
	static const auto start_time = std::chrono::system_clock::now( ).time_since_epoch( );

	HKEY output = nullptr;
	auto open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control", NULL, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to System\\CurrentControlSet\\Control\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey control_key( output ); {
		std::string randomized_string;
		randomized_string.resize( string_length );
		std::generate_n( randomized_string.begin( ), string_length, random_char );

		std::array< const char*, 2 > sub_keys = { "SystemInformation", "ComputerHardwareId" };

		auto set_status = ERROR_SUCCESS;

		for ( auto idx = 0; idx < sub_keys.size( ); idx++ ) {
			set_status = RegSetValueExA( control_key.get( ), sub_keys[ idx ], NULL, REG_SZ, ( std::uint8_t* )randomized_string.c_str( ), string_length );

			if ( set_status == ERROR_SUCCESS )
				out( "[+] set %s to: %s\n", sub_keys[ idx ], randomized_string.c_str( ) );
			else
				out( "[-] failed to set %s\n", sub_keys[ idx ] );
		}
	}

	output = nullptr;
	open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "Hardware\\Description\\System\\BIOS", NULL, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to Hardware\\Description\\System\\BIOS\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey bios_key( output ); {
		std::string randomized_string;
		randomized_string.resize( string_length );
		std::generate_n( randomized_string.begin( ), string_length, random_char );

		std::array< const char*, 4 > sub_keys = { "BIOSVendor", "BIOSReleaseDate", "SystemManufacturer", "SystemProductName" };

		auto set_status = ERROR_SUCCESS;

		for ( auto idx = 0; idx < sub_keys.size( ); idx++ ) {
			set_status = RegSetValueExA( bios_key.get( ), sub_keys[ idx ], NULL, REG_SZ, ( std::uint8_t* )randomized_string.c_str( ), string_length );

			if ( set_status == ERROR_SUCCESS )
				out( "[+] set %s to: %s\n", sub_keys[ idx ], randomized_string.c_str( ) );
			else
				out( "[-] failed to set %s\n", sub_keys[ idx ] );
		}
	}

	output = nullptr;
	open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "Hardware\\DeviceMap\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", NULL, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to Hardware\\DeviceMap\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey scsi_key( output ); {
		std::string randomized_string;
		randomized_string.resize( string_length );
		std::generate_n( randomized_string.begin( ), string_length, random_char );

		std::array< const char*, 2 > sub_keys = { "Identifier", "SerialNumber" };

		auto set_status = ERROR_SUCCESS;

		for ( auto idx = 0; idx < sub_keys.size( ); idx++ ) {
			set_status = RegSetValueExA( scsi_key.get( ), sub_keys[ idx ], NULL, REG_SZ, ( std::uint8_t* )randomized_string.c_str( ), string_length );

			if ( set_status == ERROR_SUCCESS )
				out( "[+] set %s to: %s\n", sub_keys[ idx ], randomized_string.c_str( ) );
			else
				out( "[-] failed to set %s\n", sub_keys[ idx ] );
		}
	}

	output = nullptr;
	open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "Hardware\\Description\\System\\CentralProcessor\\0", NULL, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to Hardware\\Description\\System\\CentralProcessor\\0\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey cpu_key( output ); {
		std::string randomized_string;
		randomized_string.resize( string_length );
		std::generate_n( randomized_string.begin( ), string_length, random_char );

		auto set_status = RegSetValueExA( cpu_key.get( ), "ProcessorNameString", NULL, REG_SZ, ( std::uint8_t* )randomized_string.c_str( ), string_length );

		if ( set_status == ERROR_SUCCESS )
			out( "[+] set ProcessorNameString to: %s\n", randomized_string.c_str( ) );
		else
			out( "[-] failed to set ProcessorNameString\n" );
	}

	output = nullptr;
	open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", NULL, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to System\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey desc_key( output ); {
		std::random_device random_device;
		std::mt19937 mersenne_generator( random_device( ) );
		std::uniform_int_distribution<> distribution( 0, MAXUINT32 );

		DWORD randomized_nr = static_cast< DWORD >( distribution( mersenne_generator ) );

		auto set_status = RegSetValueExA( desc_key.get( ), "DriverDesc", NULL, REG_DWORD, ( std::uint8_t* )&randomized_nr, sizeof( DWORD ) );

		if ( set_status == ERROR_SUCCESS )
			out( "[+] set DriverDesc to: %i\n", desc_random );
		else
			out( "[-] failed to set DriverDesc\n" );
	}

	output = nullptr;
	open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", NULL, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to Software\\Microsoft\\Windows NT\\CurrentVersion\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey nt_key( output ); {
		std::random_device random_device;
		std::mt19937 mersenne_generator( random_device( ) );
		std::uniform_int_distribution<> distribution( 0, MAXUINT32 );

		DWORD randomized_nr = static_cast< DWORD >( distribution( mersenne_generator ) );
		
		std::array< const char*, 4 > sub_keys = { "InstallDate", "InstallTime", "BuildGUID", "ProductID" };

		auto set_status = ERROR_SUCCESS;

		for ( auto idx = 0; idx < sub_keys.size( ); idx++ ) {
			set_status = RegSetValueExA( nt_key.get( ), sub_keys[ idx ], NULL, REG_DWORD, ( std::uint8_t* )&randomized_nr, sizeof( DWORD ) );

			if ( set_status == ERROR_SUCCESS )
				out( "[+] set %s to: %i\n", sub_keys[idx], randomized_nr );
			else
				out( "[-] failed to set %s\n", sub_keys[idx] );
		}
	}

	auto elapsed_time = std::chrono::duration_cast< std::chrono::milliseconds >( std::chrono::system_clock::now( ).time_since_epoch( ) - start_time ).count( );

	out( "[+] done in %llums\n", elapsed_time );

	std::this_thread::sleep_for( std::chrono::seconds( 10 ) );

	return EXIT_SUCCESS;
}
