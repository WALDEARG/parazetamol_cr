#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include "xorstr.hpp"
#include "bytes.hpp"
#include <vector>
#include <array>



void write_file(const char* file_name, const std::uint8_t buffer[], DWORD size)
{
	auto file_handle = CreateFileA(file_name, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!file_handle)
	{
		CloseHandle(file_handle);
		return;
	}

	if (!WriteFile(file_handle, buffer, size, NULL, NULL))
	{
		CloseHandle(file_handle);
		return;
	}

	CloseHandle(file_handle);
}

int main()
{

	HWND window_handle = {};
	DWORD process_index = {};
	LPCSTR file_path = xorstr_("C:\\Windows\\system32\\nvmld.dll");

	std::vector<std::string> directory_paths =
	{
		xorstr_("C:\\parazetamol\\"),
		xorstr_("C:\\parazetamol\\dumps\\"),
		xorstr_("C:\\parazetamol\\temp\\"),
		xorstr_("C:\\parazetamol\\menus\\")
	};

	std::vector<std::pair<std::string, LPCVOID>> startups =
	{
		{ xorstr_("scheduler.lua"),  scheduler },
		{ xorstr_("natives_universal.lua"),  natives_universal },
		{ xorstr_("deferred.lua"),  deferred },
		{ xorstr_("MessagePack.lua"),  message_pack },
		{ xorstr_("json.lua"),  json }
	};

	std::vector<std::pair<std::string, LPCVOID>> menus =
	{
		{ xorstr_("absolute.lua"),  absolute },
		{ xorstr_("absolute_new.lua"),  absolute_new },
		{ xorstr_("cock.lua"),  cock },
		{ xorstr_("extrude.lua"),  extrude },
		{ xorstr_("fivesense.lua"),  fivesense },
		{ xorstr_("lumia.lua"),  lumia },
		{ xorstr_("synapse.lua"),  synapse }
	};

	SetConsoleTitle("Parazetamol suck my dick");

	std::cout << R"(
				
  _____                              _                            _  
 |  __ \                            | |                          | | 
 | |__) |__ _  _ __  __ _  ____ ___ | |_  __ _  _ __ ___    ___  | | 
 |  ___// _` || '__|/ _` ||_  // _ \| __|/ _` || '_ ` _ \  / _ \ | | 
 | |   | (_| || |  | (_| | / /|  __/| |_| (_| || | | | | || (_) || | 
 |_|    \__,_||_|   \__,_|/___|\___| \__|\__,_||_| |_| |_| \___/ |_| 
                    _                             _  _        _      
                   | |                           | |(_)      | |     
  ___  _   _   ___ | | __  _ __ ___   _   _    __| | _   ___ | | __  
 / __|| | | | / __|| |/ / | '_ ` _ \ | | | |  / _` || | / __|| |/ /  
 \__ \| |_| || (__ |   <  | | | | | || |_| | | (_| || || (__ |   <   
 |___/ \__,_| \___||_|\_\ |_| |_| |_| \__, |  \__,_||_| \___||_|\_\  
                                       __/ |                         
                                      |___/                          
	)" << '\n';


	std::cout << xorstr_("Imagine getting cracked by nt#1078, speedy#5418") << std::endl;

	std::cout << xorstr_("Checking for paths!..") << std::endl;

	for (int i = 0; i < directory_paths.size(); i++)
	{
		auto paths = directory_paths[i];

		if (!CreateDirectory(paths.data(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
		{
			continue;
		}

		switch (i)
		{
			case 2: 
			{
				for (int i = 0; i < startups.size(); i++)
				{
					auto temps = startups[i];
					auto path = paths + temps.first;

					write_file(path.data(), (std::uint8_t*)temps.second, strlen((const char*)temps.second));
				}
			}
			break;
			case 3: 
			{
				for (int i = 0; i < menus.size(); i++)
				{
					auto temps = menus[i];
					auto path = paths + temps.first;

					write_file(path.data(), (std::uint8_t*)temps.second, strlen((const char*)temps.second));
				}
			}
			break;
		}
	}

	write_file(file_path, (std::uint8_t*)dll, sizeof(dll));

	std::cout << xorstr_("Waiting for game!..") << std::endl;

	while (!(window_handle = FindWindow(xorstr_("grcWindow"), nullptr)))
	{
		Sleep(3000);
	}

	if (GetWindowThreadProcessId(window_handle, &process_index) && process_index)
	{
		std::cout << xorstr_("Game found with pid: ") << process_index << std::endl;
	}

	auto process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_index);
	if (!process_handle)
	{
		return false;
	}
	
	auto memory_allocated = VirtualAllocEx(process_handle, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!memory_allocated)
	{

		return false;
	}

	if (!WriteProcessMemory(process_handle, memory_allocated, file_path, MAX_PATH, nullptr))
	{
		return false;
	}
		
	auto thread_handle = CreateRemoteThread(process_handle, nullptr, NULL, LPTHREAD_START_ROUTINE(LoadLibraryA), memory_allocated, NULL, nullptr);
	if (!thread_handle)
	{
		return false;
	}

	CloseHandle(thread_handle);
	VirtualFreeEx(process_handle, LPVOID(memory_allocated), 0, MEM_RELEASE);
	CloseHandle(process_handle);
	
	std::cout << xorstr_("Executed!") << std::endl;

	Sleep(3000);

	return EXIT_SUCCESS;
}
