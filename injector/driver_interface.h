#pragma once
#pragma once

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <tlhelp32.h>

enum actions
{
	write_virtual_memory_action = 32837473,
	read_virtual_memory_action = 88523453,
	get_process_base_adderss_action = 73758392,
	get_module_base_address_action = 53453455,
	allocate_virtual_memory_action = 82342341,
	get_driver_running_status_action = 28998498
};

typedef struct _read_virtual_memory_request
{

	void* address;
	void* buffer;
	HANDLE process_id;
	size_t size;

} read_virtual_memory_request, * pread_virtual_memory_request;

typedef struct _write_virtual_memory_request
{

	void* address;
	void* buffer;
	HANDLE process_id;
	size_t size;

} write_virtual_memory_request, * pwrite_virtual_memory_request;

typedef struct _get_process_base_address_request
{

	void* buffer;
	HANDLE process_id;

} get_process_base_address_request, * pget_process_base_address_request;

typedef struct _get_module_base_address_request
{

	HANDLE process_id;
	const char* module_name;
	void* buffer;
	bool is32bit;

} get_module_base_address_request, * pget_module_base_address_request;

typedef struct _allocate_virtual_memory_request
{

	void* buffer;
	HANDLE process_id;
	DWORD protect;
	size_t size;
	DWORD type;

} allocate_virtual_memory_request, * pallocate_virtual_memory_request;

typedef struct _is_driver_running_request
{

	void* is_running;

} is_driver_running_request, * pis_driver_running_request;

namespace driver_interface
{
	static HANDLE process_id = 0;
	static NTSTATUS(__stdcall* NtUserUpdateLayeredWindow)(__int64, void*, __int64, __int64, __int64, __int64, int, __int64, __int64, __int64) = nullptr;

	inline void init_interface(std::string name)
	{
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(PROCESSENTRY32);

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (Process32First(snapshot, &entry) == TRUE)
		{
			while (Process32Next(snapshot, &entry) == TRUE)
			{
				if (name.compare(entry.szExeFile) == 0)
				{
					driver_interface::process_id = (HANDLE)entry.th32ProcessID;
					break;
				}
			}
		}

		CloseHandle(snapshot);

		LoadLibraryA("user32.dll");
		HMODULE h_module = LoadLibraryA("win32u.dll");

		*(void**)&NtUserUpdateLayeredWindow = GetProcAddress(h_module, "NtUserUpdateLayeredWindow");
	}

	inline bool is_driver_running()
	{
		void* buff;
		is_driver_running_request request{};
		request.is_running = &buff;

		NtUserUpdateLayeredWindow(actions::get_driver_running_status_action, &request, 0, 0, 0, 0, 0, 0, 0, 0);

		return request.is_running;
	}

	inline void* get_process_base_address()
	{
		if (!driver_interface::process_id)
			return nullptr;

		void* base;
		get_process_base_address_request request{};
		request.buffer = &base;
		request.process_id = process_id;

		NtUserUpdateLayeredWindow(actions::get_process_base_adderss_action, &request, 0, 0, 0, 0, 0, 0, 0, 0);

		return request.buffer;
	}

	inline void* get_module_base_address(const char* module_name, bool is32bit = false)
	{
		if (!driver_interface::process_id)
			return nullptr;

		void* base;
		get_module_base_address_request request{};
		request.buffer = &base;
		request.process_id = process_id;
		request.module_name = module_name;
		request.is32bit = is32bit;

		NtUserUpdateLayeredWindow(actions::get_module_base_address_action, &request, 0, 0, 0, 0, 0, 0, 0, 0);

		return request.buffer;
	}

	inline void* allocate_virtual_memory(size_t size, DWORD protect, DWORD type)
	{
		if (!driver_interface::process_id)
			return nullptr;

		void* buffer;

		allocate_virtual_memory_request request{};
		request.process_id = process_id;
		request.buffer = &buffer;
		request.size = size;
		request.protect = protect;
		request.type = type;

		NtUserUpdateLayeredWindow(actions::allocate_virtual_memory_action, &request, 0, 0, 0, 0, 0, 0, 0, 0);

		return request.buffer;
	}

	template<typename T>
	T read_virtual_memory(DWORD64 address)
	{
		if (!driver_interface::process_id)
			return T{ 0 };

		T buffer;

		read_virtual_memory_request request{};
		request.process_id = process_id;
		request.address = reinterpret_cast<void*>(address);
		request.buffer = &buffer;
		request.size = sizeof(T);

		NtUserUpdateLayeredWindow(actions::read_virtual_memory_action, &request, 0, 0, 0, 0, 0, 0, 0, 0);

		return buffer;
	}

	inline bool write_virtual_memory(DWORD64 address, void* buffer, size_t size)
	{
		if (!driver_interface::process_id)
			return false;

		write_virtual_memory_request request{};
		request.process_id = process_id;
		request.address = reinterpret_cast<void*>(address);
		request.buffer = buffer;
		request.size = size;

		NtUserUpdateLayeredWindow(actions::write_virtual_memory_action, &request, 0, 0, 0, 0, 0, 0, 0, 0);

		return true;
	}

	inline void* get_process_module_export(LPCSTR module_name, LPCSTR export_name)
	{
		HMODULE h_module = LoadLibraryA(module_name);
		void* local_module_base = GetModuleHandleA(module_name);

		if (h_module && local_module_base)
		{
			void* local_export_address = GetProcAddress(h_module, export_name);

			if (local_export_address)
			{
				void* extern_module_base = driver_interface::get_module_base_address(module_name);

				if (extern_module_base)
				{
					return (void*)((uintptr_t)extern_module_base + ((uintptr_t)local_export_address - (uintptr_t)local_module_base));
				}
			}
		}
	}
}