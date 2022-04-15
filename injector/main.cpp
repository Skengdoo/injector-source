#include <stdio.h>
#include <Windows.h>

#include "driver_interface.h"
#include "cPEFile.h"

typedef struct _handle_data
{

    int process_id;
    HWND window_handle;

} handle_data, * phandle_data;

bool enum_window_proc(HWND hwnd, LPARAM lParam)
{
    DWORD process_id = 0;
    GetWindowThreadProcessId(hwnd, &process_id);

    if (process_id == ((phandle_data)lParam)->process_id && (GetWindowLong(hwnd, GWL_STYLE) & WS_VISIBLE))
        ((phandle_data)lParam)->window_handle = hwnd;

    return false;
};

HWND find_corrosponding_main_window(int pid)
{
    handle_data data;
    data.process_id = pid;
    data.window_handle = 0;

    EnumWindows((WNDENUMPROC)&enum_window_proc, (LPARAM)&data);

    return data.window_handle;
}

BYTE shellcode[]
{
            0x4C, 0x89, 0x44, 0x24, 0x18, // mov    QWORD PTR [rsp+0x18],r8
            0x48, 0x89, 0x54, 0x24, 0x10, // mov    QWORD PTR [rsp+0x10],rdx
            0x89, 0x4C, 0x24, 0x08, //  mov    DWORD PTR [rsp+0x8],ecx
            0x48, 0x83, 0xEC, 0x28, // sub    rsp,0x28
            0x48, 0x8b, 0x44, 0x24, 0x40, //  mov    rax,QWORD PTR [rsp + 64]
            0x83, 0x78, 0x08, 0x00, // cmp    DWORD PTR [rax+0x8],0x0
            0x75, 0x25, // jne 41
            0x49, 0xB8, 0xBE, 0xBA, 0xFE, 0xCA, 0xBE, 0xBA, 0xFE, 0xCA, // movabs r8,0xcafebabecafebabe argument
            0xBA, 0x01, 0x00, 0x00, 0x00, // mov edx, 0x1 // reason
            0x48, 0xB9, 0xBE, 0xBA, 0xFE, 0xCA, 0xBE, 0xBA, 0xFE, 0xCA, //  movabs rcx,0xcafebabecafebabe module base
            0x48, 0xB8, 0xBE, 0xBA, 0xFE, 0xCA, 0xBE, 0xBA, 0xFE, 0xCA, // movabs rax,0xcafebabecafebabe function
            0xFF, 0xD0, // call   rax
            0x31, 0xC0,  // xor    eax,eax
            0x48, 0x83, 0xC4, 0x28, // add    rsp,0x28
            0xC2, 0x00, 0x00 // ret 0x0
};

void relocate_base(cPEFile* pe_file_, DWORD64 base_address)
{

    ptrdiff_t diff = 
            DWORD64(base_address) - pe_file_->GetImageBase();

    size_t RelocationSize = pe_file_->GetDirectorySize(IMAGE_DIRECTORY_ENTRY_BASERELOC);

    if (diff) {

        IMAGE_BASE_RELOCATION* Relocation = pe_file_->GetBaseRelocation();

        size_t nRelocatedBytes = 0;

        while (nRelocatedBytes < RelocationSize) {

            unsigned long* LocationBase = pe_file_->GetPointerFromRVA< unsigned long >(Relocation->VirtualAddress);

            size_t nRelocs = (Relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(unsigned short);

            unsigned short* Location = MakePointer< unsigned short >(Relocation, sizeof(IMAGE_BASE_RELOCATION));

            for (size_t i = 0; i < nRelocs; i++) {

                int LocType = *Location >> 12;

                if (LocType == IMAGE_REL_BASED_DIR64) {

                    DWORD_PTR UNALIGNED* Address =
                        MakePointer<DWORD_PTR UNALIGNED>(LocationBase, *Location & 0xFFF);

                    *Address += diff;
                }

                if (LocType == IMAGE_REL_BASED_HIGHLOW) {

                    unsigned long* Address =
                        MakePointer< unsigned long >(LocationBase, *Location & 0xFFF);

                    *Address += diff;

                }

                Location++;
            }

            nRelocatedBytes += Relocation->SizeOfBlock;
            Relocation = reinterpret_cast<IMAGE_BASE_RELOCATION*>(Location);
        }
    }
}

int main()
{
    driver_interface::init_interface("Rust.exe");

	HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, (DWORD)driver_interface::process_id);

	if (h_process == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

    HANDLE hFile = CreateFileW(L"C:\\payload.dll", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    DWORD FileSize = GetFileSize(hFile, NULL);
    void* buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!buffer)
    {
        return 0;
    }

    DWORD read;
    if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
    {
        return 0;
    }

    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)buffer;

    if (dos_header->e_magic != 0x5a4d)
    {
        return 0;
    }


    PIMAGE_NT_HEADERS nt_headers = PIMAGE_NT_HEADERS((uintptr_t)buffer + dos_header->e_lfanew);

    PIMAGE_OPTIONAL_HEADER optional_header = &nt_headers->OptionalHeader;
    PIMAGE_FILE_HEADER file_header = &nt_headers->FileHeader;
    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);

    void* allocation = driver_interface::allocate_virtual_memory(optional_header->SizeOfImage, PAGE_EXECUTE_READWRITE, MEM_COMMIT | MEM_RESERVE);

    if (allocation == nullptr)
    {
        return 0;
    }

    cPEFile pe_file_ = cPEFile((char*)buffer);
    relocate_base(&pe_file_, (DWORD64)allocation);

    for (auto Descriptor = pe_file_.GetImportDescriptor();
        auto ModuleName = pe_file_.GetPointerFromRVA< char >(Descriptor->Name);
        Descriptor++) 
    {

        for (auto thunk_data = pe_file_.GetPointerFromRVA< IMAGE_THUNK_DATA >(Descriptor->FirstThunk); thunk_data->u1.AddressOfData; thunk_data++) {

            IMAGE_IMPORT_BY_NAME* ImportByName =
                pe_file_.GetPointerFromRVA< IMAGE_IMPORT_BY_NAME >(thunk_data->u1.AddressOfData);

            if (thunk_data->u1.AddressOfData < IMAGE_ORDINAL_FLAG32 && ImportByName->Name) {

                thunk_data->u1.Function = (DWORD_PTR)GetProcAddress(GetModuleHandleA(ModuleName), ImportByName->Name);

            }
            else {
                thunk_data->u1.Function = (DWORD_PTR)GetProcAddress(GetModuleHandleA(ModuleName), MAKEINTRESOURCEA(thunk_data->u1.AddressOfData & 0xFFF));

                ImportByName->Hint = 0;
            }
        }
    }

    for (size_t i = 0; i != file_header->NumberOfSections; i++, section_header++)
    {
        if (section_header->SizeOfRawData)
        {
            printf_s("section[%i] -> %p\n", i, (uintptr_t)allocation + section_header->VirtualAddress);
            driver_interface::write_virtual_memory(((uintptr_t)allocation + section_header->VirtualAddress), (void*)((uintptr_t)pe_file_.GetRawImage() + section_header->PointerToRawData), section_header->SizeOfRawData);
        }
    }

    printf_s("wrote section\n");

    void* shellcode_alloc = driver_interface::allocate_virtual_memory(sizeof(shellcode), PAGE_EXECUTE_READWRITE, MEM_COMMIT | MEM_RESERVE);

    if (shellcode_alloc == nullptr)
    {
        return 0;
    }
    
    printf_s("dll entry point -> %p\n", pe_file_.GetEntryPointAddress());

    void* entry = (void*)((uintptr_t)allocation + pe_file_.GetEntryPointAddress());
    void* base = (void*)pe_file_.GetImageBase();

    memcpy(&shellcode[46], &base, sizeof(void*));
    memcpy(&shellcode[56], &entry, sizeof(void*));

    driver_interface::write_virtual_memory((DWORD64)shellcode_alloc, shellcode, sizeof(shellcode));

    printf_s("shellcode allocation -> %p\n", shellcode_alloc);
    
    HWND hwnd = find_corrosponding_main_window((int)driver_interface::process_id);
    DWORD tid = GetWindowThreadProcessId(hwnd, (LPDWORD)&driver_interface::process_id);
    HMODULE ntdll = LoadLibraryW(L"ntdll.dll");

    HHOOK handle = SetWindowsHookExA(WH_GETMESSAGE, (HOOKPROC)shellcode_alloc, (HINSTANCE)ntdll, tid);

    if (handle) {
        PostThreadMessage(tid, WM_NULL, NULL, NULL);

        Sleep(500);

        UnhookWindowsHookEx(handle);
    }

    while (1);
}