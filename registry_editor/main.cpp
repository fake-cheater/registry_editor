#include <chrono>
#include <thread>
#include <random>
#include <algorithm>
#include <array>
#include <filesystem>
#include "utilities.hpp"
#include "raii.hpp"
#include "privilege_editor.hpp"

#define out( text, ... ) std::printf( text, ##__VA_ARGS__ )
#define EAC_FINGERPRINT "C:\\Windows\\System32\\restore\\MachineGuid.txt"
#pragma warning( disable : 4312 )

raii::hkey registry_hkey( const std::string_view& key ) {
	HKEY output = nullptr;
	LSTATUS status = RegOpenKeyExA( HKEY_LOCAL_MACHINE, key.data( ), 0, KEY_ALL_ACCESS, &output );

	if ( status != ERROR_SUCCESS ) {
		out( "[-] failed to open handle to %s\n", key.data( ) );
		std::this_thread::sleep_for( std::chrono::seconds( 7 ) );
		return nullptr;
	}

	return raii::hkey( output );
}

int main( ) {
	out( "[+] registry spoofer by paracord initiated\n" );

	static constexpr std::size_t string_length = 16;
	const auto start_time = std::chrono::steady_clock::now( ).time_since_epoch( );

	auto spoof_key = [ ]( HKEY current_key, auto sub_keys, std::uint8_t data_type ) {
		DWORD randomized_dword = 0u;
		std::string randomized_string;

		if ( data_type == 1 ) {
			randomized_string.reserve( string_length );
			std::generate_n( std::back_inserter( randomized_string ), string_length, [ & ] ( ) {
				thread_local std::mt19937_64 mersenne_generator( std::random_device{}( ) );
				thread_local std::uniform_int_distribution<> distribution( 97, 122 );
				return static_cast< unsigned char >( distribution( mersenne_generator ) );
			} );
		} else if ( data_type == 2 ) {
			thread_local std::mt19937_64 mersenne_generator( std::random_device{}( ) );
			thread_local std::uniform_int_distribution<DWORD> distribution( 0, MAXUINT32 );
			randomized_dword = distribution( mersenne_generator );
		}

		auto set_status = ERROR_SUCCESS;

		for ( const auto current : sub_keys ) {
			( data_type == 1 ) ? set_status = RegSetValueExA( current_key, current, 0, REG_SZ, ( std::uint8_t* )randomized_string.c_str( ), string_length ) : set_status = RegSetValueExA( current_key, current, 0, REG_DWORD, ( std::uint8_t* )&randomized_dword, sizeof( DWORD ) );
			( set_status == ERROR_SUCCESS ) ? ( ( data_type == 1 ) ? out( "[+] set %s to: %s\n", current, randomized_string.c_str( ) ) : out( "[+] set %s to: %i\n", current, randomized_dword ) ) : out( "[-] failed to set %s\n", current );
		}
	};

	auto control_key = registry_hkey( "System\\CurrentControlSet\\Control" );
	{
		std::array sub_keys{ "SystemInformation", "ComputerHardwareId" };
		spoof_key( control_key.get( ), sub_keys, 1 );
	}

	auto bios_key = registry_hkey( "Hardware\\Description\\System\\BIOS" );
	{
		std::array sub_keys{ "BaseBoardManufacturer", "BaseBoardProduct", "BIOSVendor", "BIOSReleaseDate", "SystemManufacturer", "SystemProductName" };
		spoof_key( bios_key.get( ), sub_keys, 1 );
	}

	auto scsi_key = registry_hkey( "Hardware\\DeviceMap\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" );
	{
		std::array sub_keys{ "Identifier", "SerialNumber" };
		spoof_key( scsi_key.get( ), sub_keys, 1 );
	}

	auto cpu_key = registry_hkey( "Hardware\\Description\\System\\CentralProcessor\\0" );
	{
		spoof_key( scsi_key.get( ), std::array{ "ProcessorNameString" }, 1 );
	}

	auto desc_key = registry_hkey( "System\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" );
	{
		spoof_key( desc_key.get( ), std::array{ "DriverDesc" }, 2 );
	}

	auto nt_key = registry_hkey( "Software\\Microsoft\\Windows NT\\CurrentVersion" );
	{
		std::array sub_keys{ "InstallDate", "InstallTime", "BuildGUID", "ProductID" };
		spoof_key( nt_key.get( ), sub_keys, 2 );
	}
	
	HKEY raw_hkey = nullptr;
	RegCreateKeyExA( HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Control\\WMI\\Restrictions", NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &raw_hkey, NULL );

	raii::hkey unique_hkey( raw_hkey ); 
	{
		const auto value = 1;
		const auto status = RegSetValueExA( unique_hkey.get( ), "HideMachine", NULL, REG_DWORD, ( std::uint8_t* )&value, sizeof( DWORD ) );
		status ? out( "[+] successfully set HideMachine flag to prevent SMBIOS queries!\n" ) : out( "[-] failed to set HideMachine flag\n" );
	}

	raii::handle wmi_handle( OpenProcess( PROCESS_ALL_ACCESS, FALSE, utilities::process_id( "WmiPrvSE.exe" ) ) );
	{
		if ( wmi_handle.get( ) != INVALID_HANDLE_VALUE )
			TerminateProcess( wmi_handle.get( ), EXIT_SUCCESS );
	}

	if ( std::filesystem::exists( EAC_FINGERPRINT ) ) 
	{
		privilege::take_ownership( const_cast< char* >( EAC_FINGERPRINT ) );
		std::filesystem::remove( EAC_FINGERPRINT );
		out( "[+] deleted MachineGUID.txt\n" );
	}

	auto elapsed_time = std::chrono::duration_cast< std::chrono::milliseconds >( std::chrono::steady_clock::now( ).time_since_epoch( ) - start_time ).count( );

	out( "[+] done in %llums\n", elapsed_time );

	std::this_thread::sleep_for( std::chrono::seconds( 10 ) );

	return EXIT_SUCCESS;
}