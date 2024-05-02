#include <iostream>
#include <cassert>
#include <cstdlib>
#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h>

#define MAX_STR_SIZE 192
#define MAX_MODULE_AMOUNT 128
#define MAX_MEM_AMOUNT 10000

#define MAX_MODULE_AMOUNT_IN_BYTES MAX_MODULE_AMOUNT * sizeof(HMODULE)

#undef min
#undef Process32First
#undef Process32Next
#undef PROCESSENTRY32

UCHAR strcmp_leastchar(const char* a, const char* b, const char* la = nullptr)
{
	const char* lb = b;

	if (la == nullptr)
	{
		la = a;
		while (*la) la++;
	}

	while (*lb) lb++;

	int min_size = -std::min(la - a, lb - b);
	UCHAR c = 0;

	for (int i = -1; i >= min_size; i--)
		c += (la[i] == lb[i]);

	return c;
}

std::string GetLastErrorAsString()
{
	//Get the error message ID, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0) {
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	//Copy the error message into a std::string.
	std::string message(messageBuffer, size);

	//Free the Win32's string's buffer.
	LocalFree(messageBuffer);

	return message;
}

struct mem_info_s
{
	void* BaseAddress;
	SIZE_T RegionSize;
	bool is_priorited;
};

size_t app_mem_size = 0;

struct info_s
{
	bool alive;

	DWORD pId, module_amount, error_code;
	HMODULE* modules;
	MODULEINFO* module_infos;

	size_t buck_mem_size;

	HMODULE main_module;
	void* module_base;
	MODULEINFO main_module_info;
	LPSTR main_module_file_name;

	mem_info_s* mem_addresses;
	DWORD mem_amount;

	HANDLE proc;

	info_s(DWORD pId_In) : pId(pId_In)
	{
		module_infos = nullptr;
		mem_addresses = nullptr;
		mem_amount = 0;
		alive = false;
		main_module = 0;
		main_module_info = { nullptr, 0, nullptr };
		module_amount = error_code = 0;
		modules = nullptr;
		proc = nullptr;

		main_module_file_name = (LPSTR)malloc(MAX_STR_SIZE);
		LPSTR cache_file_name = (LPSTR)malloc(MAX_STR_SIZE);

		if (main_module_file_name == nullptr || cache_file_name == nullptr) {
			error_code = 1;
			return;
		}

		main_module_file_name[MAX_STR_SIZE - 1] = '\0';
		cache_file_name[MAX_STR_SIZE - 1] = '\0';

		modules = (HMODULE*)malloc(MAX_MODULE_AMOUNT_IN_BYTES);
		module_infos = (MODULEINFO*)malloc(MAX_MODULE_AMOUNT * sizeof(MODULEINFO));

		if (modules == nullptr || module_infos == nullptr) {
			error_code = 2;
			return;
		}

		proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId_In);

		GetProcessImageFileNameA(proc, main_module_file_name, MAX_STR_SIZE);

		EnumProcessModules(proc, modules, MAX_MODULE_AMOUNT_IN_BYTES, &module_amount);

		if (module_amount > MAX_MODULE_AMOUNT_IN_BYTES) {
			error_code = 3;
			return;
		}

		module_amount /= sizeof(HMODULE);

		const char* least_char_on_main = main_module_file_name;
		while (*least_char_on_main) least_char_on_main++;

		MODULEINFO module_info;

		for (DWORD i = 0; i < module_amount; i++)
		{
			DWORD err = GetModuleFileNameA(modules[i], cache_file_name, MAX_STR_SIZE);
			GetModuleInformation(proc, modules[i], &module_info, sizeof(MODULEINFO));
			module_infos[i] = module_info;

			if (err == 0)
			{
				cache_file_name[0] = '?';
				cache_file_name[1] = '\0';
			}

			std::cout << i << ":\t" << module_info.lpBaseOfDll << ": " << cache_file_name << '\n';
		}

		main_module_info = module_infos[0];
		main_module = modules[0];

		module_base = (void*)main_module;

		free(cache_file_name);

		std::cout << "\nModule Name:\t" << main_module_file_name
			<< "\nModule Base:\t0x" << module_base
			<< "\nCum Base:\t0x" << main_module_info.EntryPoint
			<< "\nModule Size:\t" << main_module_info.SizeOfImage
			<< "\nModule Amount:\t" << module_amount
			<< "\npId:\t\t" << pId
			<< std::endl;

		alive = true;
	}

	void get_memory_infos()
	{
		if (alive == false)
			return;

		if (mem_addresses == nullptr)
			mem_addresses = (mem_info_s*)malloc(MAX_MEM_AMOUNT * sizeof(mem_info_s));

		buck_mem_size = 0;
		mem_amount = 0;

		MEMORY_BASIC_INFORMATION mem_info;
		void* next_scan_start = nullptr;

		while (VirtualQueryEx(proc, next_scan_start, &mem_info, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			next_scan_start = (char*)mem_info.BaseAddress + mem_info.RegionSize;

			if (mem_info.State == MEM_COMMIT && next_scan_start < (void*)0x00007FF000000000)
			{
				if (mem_info.RegionSize > app_mem_size)
					buck_mem_size++;
				else
				{
					mem_addresses[mem_amount].is_priorited = (mem_info.BaseAddress == mem_info.AllocationBase);
					mem_addresses[mem_amount].BaseAddress = mem_info.BaseAddress;
					mem_addresses[mem_amount].RegionSize = mem_info.RegionSize;
					mem_amount++;
				}
			}
		}
	}

	void print_memory_infos()
	{
		std::cout << '\n';

		for (int i = 0; i < mem_amount; i++)
		{
			if (mem_addresses[i].is_priorited)
				std::cout << "\033[33m" << mem_addresses[i].BaseAddress << "\033[0m (" << mem_addresses[i].RegionSize << ")\n";
			else
				std::cout << mem_addresses[i].BaseAddress << " (" << mem_addresses[i].RegionSize << ")\n";
		}

		std::cout << "Total: " << buck_mem_size << '/' << (mem_amount + buck_mem_size) << std::endl;
	}

	void clean_up()
	{
		alive = false;

		CloseHandle(proc);
		proc = nullptr;
		free(main_module_file_name);
		main_module_file_name = nullptr;
		free(modules);
		modules = nullptr;

		if (mem_addresses) {
			free(mem_addresses);
			mem_addresses = nullptr;
		}
	}
};

DWORD find_pId(const char* name)
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(snapshot, &entry) == TRUE)
		while (Process32Next(snapshot, &entry) == TRUE)
			if (strcmp(entry.szExeFile, name) == 0)
			{
				CloseHandle(snapshot);
				return entry.th32ProcessID;
			}

	CloseHandle(snapshot);

	return 0;
}

void EnablePriv()
{
	HANDLE hToken;
	DWORD dwLen;
	bool bRes;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	// obtain dwLen
	bRes = GetTokenInformation(
		hToken,
		TokenPrivileges,
		NULL,
		0,
		&dwLen
	);

	BYTE* pBuffer = new BYTE[dwLen];

	bRes = GetTokenInformation(
		hToken,
		TokenPrivileges,
		pBuffer,
		dwLen,
		&dwLen
	);

	// Iterate through all the privileges and enable them all
	// ======================================================
	TOKEN_PRIVILEGES* pPrivs = (TOKEN_PRIVILEGES*)pBuffer;
	for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++)
	{
		pPrivs->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;
	}
	// Store the information back in the token
	// =========================================
	bRes = AdjustTokenPrivileges(
		hToken,
		FALSE,
		pPrivs,
		0, NULL, NULL
	);

	delete[] pBuffer;
	CloseHandle(hToken);
}

#define MAX_SCAN_SIZE 591632

typedef UCHAR byte_t;

size_t* scan_result;
size_t* scan_sub_result;
size_t last_scan_size = 0;
int last_scan_module_index = 0;
size_t last_condition_value = 0;
UCHAR last_scan_bit_size = 0;
size_t scan_number_of_bytes_read = 0;
size_t scan_step = 0;

char* module_name_buffer = nullptr;

void* app_mem;
void* extra;
// module_index = 0 for main module
void scan_static(UCHAR size_in_bits, info_s* info, size_t condition_value, int module_index = 0)
{
	last_scan_module_index = module_index;
	scan_step = 1;
	last_scan_bit_size = size_in_bits;
	last_condition_value = condition_value;
	size_t next_index = 0;
	size_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - size_in_bits);

	ReadProcessMemory(info->proc, info->module_infos[module_index].lpBaseOfDll, app_mem, app_mem_size, &scan_number_of_bytes_read);
	GetModuleFileNameA(info->modules[module_index], module_name_buffer, 128);

	size_t cache = scan_number_of_bytes_read - 16;
	for (size_t i = 0; i < cache; i++)
	{
		size_t value = *((size_t*)((byte_t*)app_mem + i));

		if (condition_value == (value & mask))
		{
			scan_result[next_index] = i;
			next_index++;

			if (next_index >= MAX_SCAN_SIZE)
				return;
		}
	}

	last_scan_size = next_index;
}

void scan_dynamic(UCHAR size_in_bits, info_s* info, size_t condition_value)
{
	last_scan_module_index = -1;
	scan_step = 1;
	last_scan_bit_size = size_in_bits;
	last_condition_value = condition_value;
	size_t next_index = 0;
	size_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - size_in_bits);
	scan_number_of_bytes_read = 0;
	size_t scan_number_of_bytes_read_foronce = 0;

	last_scan_size = 0;

	for (int k = 0; k < info->mem_amount; k++)
	{
		size_t cache2 = (size_t)info->mem_addresses[k].BaseAddress;
		ReadProcessMemory(info->proc, info->mem_addresses[k].BaseAddress, app_mem, info->mem_addresses[k].RegionSize, &scan_number_of_bytes_read_foronce);
		scan_number_of_bytes_read += scan_number_of_bytes_read_foronce;

		std::cout << (void*)cache2 << "    " << scan_number_of_bytes_read_foronce << '/' << info->mem_addresses[k].RegionSize << '\n';

		for (size_t i = 0; i < scan_number_of_bytes_read_foronce; i++)
		{
			size_t value = *((size_t*)((byte_t*)app_mem + i));

			if (condition_value == (value & mask))
			{
				if (next_index >= MAX_SCAN_SIZE)
					return;

				scan_result[next_index] = cache2 + i;

				next_index++;
			}
		}
	}

	for (int i = 0; i < next_index; i++)
		((size_t*)app_mem)[i] = condition_value;

	last_scan_size = next_index;
}

void big_scan(UCHAR size_in_bits, info_s* info, void* start, size_t size)
{
	last_scan_module_index = -1;
	scan_step = 1;
	last_scan_bit_size = size_in_bits;
	size_t next_index = 0;
	size_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - size_in_bits);

	ReadProcessMemory(info->proc, start, extra, size, &scan_number_of_bytes_read);

	for (int i = 0; i < size; i++)
	{
		scan_result[i] = (size_t)((byte*)start + i);
		((size_t*)app_mem)[i] = *(size_t*)((byte*)extra + i) & mask;
	}

	std::cout << '\n' << start << '\t' << scan_number_of_bytes_read << '/' << size << '\n';

	last_scan_size = scan_number_of_bytes_read;
}

void next_scan_dynamic(info_s* info, size_t condition_value, UCHAR type = 4)
{
	last_condition_value = condition_value;
	size_t next_index = 0;
	size_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - last_scan_bit_size);
	size_t byte_size = last_scan_bit_size >> 3;

	for (int i = 0; i < last_scan_size; i++)
	{
		size_t old_value = ((size_t*)app_mem)[i];

		ReadProcessMemory(info->proc, (void*)scan_result[i], extra, byte_size, nullptr);

		size_t value = (*((size_t*)extra)) & mask;

		bool dodo = false;

		switch (type)
		{
		case 0:
			dodo = (old_value > value);
			break;
		case 1:
			dodo = (old_value == value);
			break;
		case 2:
			dodo = (old_value < value);
			break;
		case 3:
			dodo = (condition_value > value);
			break;
		case 4:
			dodo = (condition_value == value);
			break;
		case 5:
			dodo = (condition_value < value);
			break;
		}

		if (dodo)
		{
			scan_result[next_index] = scan_result[i];
			((size_t*)app_mem)[next_index] = value;
			next_index++;
		}
	}

	last_scan_size = next_index;
	scan_step++;
}

void next_scan_static(info_s* info, size_t condition_value)
{
	scan_sub_result = (size_t*)malloc(sizeof(size_t) * last_scan_size);

	if (scan_sub_result == nullptr)
		return;

	last_condition_value = condition_value;
	size_t next_index = 0;
	size_t mask = 0xFFFFFFFFFFFFFFFF >> (64 - last_scan_bit_size);

	ReadProcessMemory(info->proc, info->module_infos[last_scan_module_index].lpBaseOfDll, app_mem, app_mem_size, &scan_number_of_bytes_read);

	for (size_t i = 0; i < last_scan_size; i++)
	{
		size_t value = *((size_t*)((byte_t*)app_mem + scan_result[i]));

		if (condition_value == (value & mask))
		{
			scan_sub_result[next_index] = scan_result[i];
			next_index++;
		}
	}

	last_scan_size = next_index;

	memcpy(scan_result, scan_sub_result, last_scan_size * sizeof(size_t));

	free(scan_sub_result);

	scan_step++;
}

void initalize_scan_mem(info_s* info)
{
	module_name_buffer = (char*)malloc(128);
	module_name_buffer[127] = 0;
	scan_result = (size_t*)malloc(MAX_SCAN_SIZE * sizeof(size_t) + 64);
	app_mem_size = 0x10000000;
	app_mem = malloc(app_mem_size);
	extra = (char*)app_mem + 0xA000000;
}

void clean_scan_mem()
{
	free(module_name_buffer);
	module_name_buffer = nullptr;
	free(scan_result);
	scan_result = nullptr;
	free(app_mem);
	app_mem = nullptr;
}

void print_scan_basic()
{
	if (last_scan_module_index == -1)
		std::cout << "Scan Type:\tDynamic";
	else
		std::cout << "Scan Module:\t" << module_name_buffer;

	std::cout << "\nScan Step:\t" << scan_step
		<< "\nFound:\t\t" << last_scan_size
		<< "\nScan Condition:\t" << last_condition_value
		<< "\nReaded Bytes:\t" << scan_number_of_bytes_read << '/' << app_mem_size
		<< "\nScan Bit Size:\t" << +last_scan_bit_size << '\n';
}

void print_scan_result(info_s* info)
{
	if (last_scan_size == 0)
	{
		std::cout << "Please Scan first ':scan'.\n";
		return;
	}

	if (last_scan_module_index == -1)
	{
		for (size_t i = 0; i < last_scan_size; i++)
			std::cout << i << ":\t  0x" << (void*)scan_result[i] << '\n';
		return;
	}

	std::cout << "Index\t| Base Addr\t\t | Offset\n";

	for (size_t i = 0; i < last_scan_size; i++)
		std::cout << i << ":\t  0x" << info->module_infos[last_scan_module_index].lpBaseOfDll << "\t + " << scan_result[i] << "\t= "
		<< (void*)(reinterpret_cast<size_t>(info->module_infos[last_scan_module_index].lpBaseOfDll) + scan_result[i]) << '\n';
}

char* general_use_str = nullptr;

char* exe_name;

// C:\Users\luicc\source\repos\"Ceting Engin"\x64\Release\"Ceting Engin".exe

int main()
{
	EnablePriv();

	exe_name = (char*)malloc(64);

	puts(R"(                          --.:--.
                        =***++*++*+-
                       **:       :=*:
                      =+           #-
                      -=          =#
                       .-         #:
                        +.        #
                      -=*:       :=
                   :**+*=        ..+***:
                 .+*=              ---=#*.
                :=                      -#=
              .+=                         #*
             -*.                           --
             *:   -+*+.             . ==:   -
            =+   :=: ==         #   .. -:   =:
            *    -=  +-  |    | |      +=   -#
           -+     *- +   |#   | |  +   *     +.
           .*     ++ *   | #  | |  *   =    .-
            =+    =.:+   |  # | |  #   .    =
             +:   ::+    |   #| |  = .     +=
              -.   .                .     +=
               =:        |####    |     .=:
                ==       |        |    :+
                 :-      |       | |   =+
                 +*      |  ##|  |#|   .#
                 #=      |    | |   |   *-
                 #       |####| |   |   +=
                -*                      -=
                #:                       +
                =:          -+-        . .:
                :+.      -+***##        . -
                -#      +=-    *#      =. =
                #.     :+       +*        +.
                                                                     )");

	std::cout << "\nHuman Check write answer of this question: 0.1 + 0.2 (only whole intagers)\n";

	{
		getchar();

		std::cout << "\nHello, World!\n";
	}

	std::cout << "Proccess exe name (moneys baba gril ['.' for own]): ";

	std::cin >> exe_name;

	std::cout << "\nBig BLACK Mans Around You!!! (Naber cet -Egemen Yalin)\n\n";

	DWORD fpId = (exe_name[0] == '.') ? GetCurrentProcessId() : find_pId(exe_name);

	if (fpId == 0)
	{
		std::cout << "Didn't found '" << exe_name << "'. . .";
		getchar();
		return 0;
	}

	info_s current(fpId);

	assert(current.error_code == 0);

	initalize_scan_mem(&current);

	current.get_memory_infos();

	current.print_memory_infos();

	general_use_str = (char*)malloc(64);

	if (general_use_str != nullptr)
	{
		general_use_str[63] = '\0';

		std::cout << "\nWrite help for commands.\n" << std::endl;

		while (true)
		{
			std::cout << "\n:";

			std::cin >> general_use_str;

			std::cout << std::endl;

			if (strcmp(general_use_str, "help") == 0)
				std::cout << "   help  | shows here\n   toF | IEE 745 to float\n   toI | float to IEE 745\n   blowjob | blowjob my c*ck (copy memory start -> start + size to checking area) \n   refm  | refresh memory info\n   ndscan| next dscan.\n   dscan | scans values in dynamic mem.\n   scan  | scans value you will enter next command\n   dget\n   dset  | set nigga set set (dynamic & static)!\n   nexts | scans but only stored indexez!\n   chnge | change??? by index dont forget your index :) (static)\n   show  | show scan results (damn)\n   showb | show scan basic info (damn)\n   clear\n   quit\n";
			else if (strcmp(general_use_str, "quit") == 0)
				break;
			else if (general_use_str[0] == 's')
			{
				if (strcmp(general_use_str, "show") == 0)
					print_scan_result(&current);
				else if (strcmp(general_use_str, "showb") == 0)
					print_scan_basic();
				else if (strcmp(general_use_str, "scan") == 0)
				{
					size_t bit_size;
					size_t condutionlul;
					int moduleI;

					std::cout << "bit size: ";
					std::cin >> bit_size;
					std::cout << "value (unsigned): ";
					std::cin >> condutionlul;
					std::cout << "module index: ";
					std::cin >> moduleI;

					scan_static(bit_size, &current, condutionlul, moduleI);

					std::cout << '\n';

					print_scan_basic();
				}
				else if (strcmp(general_use_str, "seta") == 0)
				{
					uint32_t val;

					std::cout << "value: ";
					std::cin >> val;

					for (int i = 0; i < last_scan_size; i++)
						WriteProcessMemory(current.proc, (void*)(scan_result[i]), &val, 4, nullptr);
				}
			}
			else if (strcmp(general_use_str, "nexts") == 0)
			{
				size_t condutionlul;

				std::cout << "value (unsigned): ";
				std::cin >> condutionlul;

				next_scan_static(&current, condutionlul);

				std::cout << '\n';

				print_scan_basic();
			}
			else if (strcmp(general_use_str, "chnge") == 0)
			{
				size_t index;

				std::cout << "index (255 for exit): ";
				std::cin >> index;

				if (index != 255 && index < last_scan_size)
				{
					size_t value;

					std::cout << "value (unsigned): ";
					std::cin >> value;

					WriteProcessMemory(current.proc, (char*)current.module_infos[last_scan_module_index].lpBaseOfDll + scan_result[index], &value,
						last_scan_bit_size >> 3, nullptr);
				}
			}
			else if (strcmp(general_use_str, "clear") == 0)
				system("cls");
			else if (strcmp(general_use_str, "refm") == 0)
			{
				current.get_memory_infos();
				current.print_memory_infos();
			}
			else if (strcmp(general_use_str, "dscan") == 0)
			{
				size_t bit_size;
				size_t condutionlul;

				std::cout << "bit size: ";
				std::cin >> bit_size;
				std::cout << "value (unsigned): ";
				std::cin >> condutionlul;

				scan_dynamic(bit_size, &current, condutionlul);

				std::cout << '\n';

				print_scan_basic();
			}
			else if (strcmp(general_use_str, "dset") == 0)
			{
				size_t bit_size;
				void* index;
				size_t val;

				std::cout << "bit size: ";
				std::cin >> bit_size;
				std::cout << "address: ";
				std::cin >> index;
				std::cout << "value (unsigned): ";
				std::cin >> val;

				WriteProcessMemory(current.proc, index, &val, bit_size >> 3, nullptr);
			}
			else if (strcmp(general_use_str, "ndscan") == 0)
			{
				size_t condutionlul = 0;
				size_t type;

				std::cout << "type (4): ";
				std::cin >> type;

				if (type >= 3 && type <= 5)
				{
					std::cout << "value (unsigned): ";
					std::cin >> condutionlul;
				}

				next_scan_dynamic(&current, condutionlul, type);

				std::cout << '\n';

				print_scan_basic();
			}
			else if (strcmp(general_use_str, "dget") == 0)
			{
				size_t bit_size;
				void* index;

				std::cout << "bit size: ";
				std::cin >> bit_size;
				std::cout << "address: ";
				std::cin >> index;

				*(size_t*)app_mem = 0;
				ReadProcessMemory(current.proc, index, app_mem, bit_size >> 3, nullptr);

				std::cout << *(size_t*)app_mem;
			}
			else if (strcmp(general_use_str, "blowjob") == 0)
			{
				size_t bit_size;
				void* start;
				size_t size;

				std::cout << "bit size: ";
				std::cin >> bit_size;
				std::cout << "start addr: ";
				std::cin >> start;
				std::cout << "size: ";
				std::cin >> size;

				big_scan(bit_size, &current, start, size);
			}
			else if (strcmp(general_use_str, "toI") == 0)
			{
				float val;

				std::cout << "value: ";
				std::cin >> val;

				std::cout << *reinterpret_cast<uint32_t*>(&val) << '\n';
			}
			else if (strcmp(general_use_str, "toF") == 0)
			{
				uint32_t val;

				std::cout << "value: ";
				std::cin >> val;

				std::cout << *reinterpret_cast<float*>(&val) << '\n';
			}
		}

		free(general_use_str);
	}

	current.clean_up();

	clean_scan_mem();

	return 0;
}