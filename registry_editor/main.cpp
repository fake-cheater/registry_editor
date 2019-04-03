#include <chrono>
#include <thread>
#include <random>
#include <algorithm>
#include <array>
#include "raii.hpp"

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

	auto spoof_key = [ & ] ( HKEY current_key, std::vector<const char*> sub_keys, std::uint8_t data_type ) {
		DWORD randomized_dword = 0;
		std::string randomized_string;

		if ( data_type == 1 ) {
			randomized_string.reserve( string_length );
			std::generate_n( std::back_inserter( randomized_string ), string_length, random_char );
		} else if ( data_type == 2 ) {
			std::random_device random_device;
			std::mt19937 mersenne_generator( random_device( ) );
			std::uniform_int_distribution<> distribution( 0, MAXUINT32 );
			randomized_dword = static_cast< DWORD >( distribution( mersenne_generator ) );
		}

		auto set_status = ERROR_SUCCESS;

		for ( const auto current : sub_keys ) {
			( data_type == 1 ) ? set_status = RegSetValueExA( current_key, current, 0, REG_SZ, ( std::uint8_t* )randomized_string.c_str( ), string_length ) : set_status = RegSetValueExA( current_key, current, 0, REG_DWORD, ( std::uint8_t* )&randomized_dword, sizeof( DWORD ) );

			if ( set_status == ERROR_SUCCESS )
				( data_type == 1 ) ? out( "[+] set %s to: %s\n", current, randomized_string.c_str( ) ) : out( "[+] set %s to: %i\n", current, randomized_dword );
			else
				out( "[-] failed to set %s\n", current );
		}
	};

	HKEY output = nullptr;
	auto open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control", 0, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to System\\CurrentControlSet\\Control\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey control_key( output ); 
	{
		std::vector<const char*> sub_keys{ "SystemInformation", "ComputerHardwareId" };
		spoof_key( control_key.get( ), sub_keys, 1 );
	}

	output = nullptr;
	open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "Hardware\\Description\\System\\BIOS", 0, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to Hardware\\Description\\System\\BIOS\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey bios_key( output ); 
	{
		std::vector<const char*> sub_keys{ "BIOSVendor", "BIOSReleaseDate", "SystemManufacturer", "SystemProductName" };
		spoof_key( bios_key.get( ), sub_keys, 1 );
	}

	output = nullptr;
	open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "Hardware\\DeviceMap\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", 0, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to Hardware\\DeviceMap\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey scsi_key( output ); 
	{
		std::vector<const char*> sub_keys{ "Identifier", "SerialNumber" };
		spoof_key( scsi_key.get( ), sub_keys, 1 );
	}

	output = nullptr;
	open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "Hardware\\Description\\System\\CentralProcessor\\0", 0, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to Hardware\\Description\\System\\CentralProcessor\\0\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey cpu_key( output ); 
	{
		spoof_key( scsi_key.get( ), std::vector<const char*>{ "ProcessorNameString" }, 1 );
	}

	output = nullptr;
	open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", 0, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to System\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey desc_key( output ); 
	{
		spoof_key( desc_key.get( ), std::vector<const char*>{ "DriverDesc" }, 2 );
	}

	output = nullptr;
	open_status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_ALL_ACCESS, &output );

	if ( open_status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to Software\\Microsoft\\Windows NT\\CurrentVersion\n" );

		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return EXIT_FAILURE;
	}

	raii::hkey nt_key( output );
	{
		std::vector<const char*> sub_keys{ "InstallDate", "InstallTime", "BuildGUID", "ProductID" };
		spoof_key( nt_key.get( ), sub_keys, 2 );
	}

	auto elapsed_time = std::chrono::duration_cast< std::chrono::milliseconds >( std::chrono::system_clock::now( ).time_since_epoch( ) - start_time ).count( );

	out( "[+] done in %llums\n", elapsed_time );

	std::this_thread::sleep_for( std::chrono::seconds( 10 ) );

	return EXIT_SUCCESS;
}
