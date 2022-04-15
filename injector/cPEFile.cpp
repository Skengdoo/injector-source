/**
 * @file    cPEFile.cpp.
 *
 * Implements the pe file class.
**/

#include "cPEFile.h"
#include <bitset>

/**
 * Constructor.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @param [in,out]  pImage  If non-null, the image.
 * @param           Size    The size.
**/

cPEFile::cPEFile(
    char* pImage,
    size_t  Size)
{
    nSize = Size;
    pBaseAddress = pImage;

    Parse();
}
cPEFile::cPEFile(
    char* pImage)
{
    pBaseAddress = pImage;

    Parse();
}
/**
 * Gets the size.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  The size.
**/

size_t cPEFile::GetSize() const
{
    return nSize;
}

/**
 * Gets raw image.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  Null if it fails, else the raw image.
**/

char* cPEFile::GetRawImage() const
{
    return pBaseAddress;
}

/**
 * Query if this object is 64 bit
 *
 * @author skeng#9524
 * @date 31.01.2021
 *
 * @returns True if 64 bit, false if not.
 */

bool cPEFile::Is64Bit() {
    return ((IMAGE_NT_HEADERS*)(pNtHeaders))->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
}


/**
 * Parses this object.
 *
 * @author  skeng#9524
 * @date    04.04.2017
**/

void cPEFile::Parse()
{
    pDosHeader = (PIMAGE_DOS_HEADER)pBaseAddress;

    if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {

        pNtHeaders = (PIMAGE_NT_HEADERS)(pBaseAddress + pDosHeader->e_lfanew);

        if (((IMAGE_NT_HEADERS*)(pNtHeaders))->Signature == IMAGE_NT_SIGNATURE) {

            if (((IMAGE_NT_HEADERS*)(pNtHeaders))->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {

                for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
                    DirectoryPointers[i] = reinterpret_cast<DWORD64>(
                        GetPointerFromRVA< DWORD64 >(((IMAGE_NT_HEADERS32*)(pNtHeaders))->OptionalHeader.DataDirectory[i].VirtualAddress));

                }

            }
            else if (((IMAGE_NT_HEADERS*)(pNtHeaders))->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {

                for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++) {
                    DirectoryPointers[i] = reinterpret_cast<DWORD64>(
                        GetPointerFromRVA< DWORD64 >(((IMAGE_NT_HEADERS*)(pNtHeaders))->OptionalHeader.DataDirectory[i].VirtualAddress));

                }
            }



            bValidPE = true;
        }
    }
}

/**
 * Query if this object is valid pe.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  True if valid pe, false if not.
**/

bool cPEFile::IsValidPE() const
{
    return bValidPE;
}

/**
 * Gets directory size.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @param   Directory   Pathname of the directory.
 *
 * @return  The directory size.
**/

size_t cPEFile::GetDirectorySize(
    const int Directory) const
{
    if (((IMAGE_NT_HEADERS*)(pNtHeaders))->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {

        return ((IMAGE_NT_HEADERS32*)(pNtHeaders))->OptionalHeader.DataDirectory[Directory].Size;
    }

    return ((IMAGE_NT_HEADERS*)(pNtHeaders))->OptionalHeader.DataDirectory[Directory].Size;
}


/**
 * Gets NT headers.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  Null if it fails, else the NT headers.
**/

void* cPEFile::GetNtHeaders() const
{
    return pNtHeaders;
}

/**
 * Gets dos header.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  Null if it fails, else the dos header.
**/

IMAGE_DOS_HEADER* cPEFile::GetDosHeader() const
{
    return pDosHeader;
}

/**
 * Gets optional header.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  The optional header.
**/

IMAGE_OPTIONAL_HEADER cPEFile::GetOptionalHeader64() const
{
    return ((IMAGE_NT_HEADERS*)(pNtHeaders))->OptionalHeader;
}

/**
 * Gets optional header.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  The optional header.
**/

IMAGE_OPTIONAL_HEADER32 cPEFile::GetOptionalHeader32() const
{
    return ((IMAGE_NT_HEADERS32*)(pNtHeaders))->OptionalHeader;
}

/**
 * Gets the first section header.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  Null if it fails, else the first section header.
**/

IMAGE_SECTION_HEADER* cPEFile::GetFirstSectionHeader() const
{
    return IMAGE_FIRST_SECTION(((IMAGE_NT_HEADERS*)pNtHeaders));
}

/**
 * Gets import descriptor.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  Null if it fails, else the import descriptor.
**/

IMAGE_IMPORT_DESCRIPTOR* cPEFile::GetImportDescriptor()
{
    return GetDirectoryPointer< IMAGE_IMPORT_DESCRIPTOR >(IMAGE_DIRECTORY_ENTRY_IMPORT);
}

/**
 * Gets base relocation.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  Null if it fails, else the base relocation.
**/

IMAGE_BASE_RELOCATION* cPEFile::GetBaseRelocation()
{
    return GetDirectoryPointer< IMAGE_BASE_RELOCATION >(IMAGE_DIRECTORY_ENTRY_BASERELOC);
}

/**
 * Gets image size.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  The image size.
**/

size_t cPEFile::GetImageSize() const
{
    if (((IMAGE_NT_HEADERS*)(pNtHeaders))->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {

        return ((IMAGE_NT_HEADERS32*)(pNtHeaders))->OptionalHeader.SizeOfImage;
    }

    return ((IMAGE_NT_HEADERS*)(pNtHeaders))->OptionalHeader.SizeOfImage;
}

/**
 * Gets entry point address.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  The entry point address.
**/

DWORD64 cPEFile::GetEntryPointAddress() const
{
    if (((IMAGE_NT_HEADERS*)(pNtHeaders))->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {

        return ((IMAGE_NT_HEADERS32*)(pNtHeaders))->OptionalHeader.AddressOfEntryPoint;
    }

    return ((IMAGE_NT_HEADERS*)(pNtHeaders))->OptionalHeader.AddressOfEntryPoint;

}

/**
 * Gets image base.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  The image base.
**/

DWORD64 cPEFile::GetImageBase() const
{
    if (((IMAGE_NT_HEADERS*)(pNtHeaders))->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {

        return ((IMAGE_NT_HEADERS32*)(pNtHeaders))->OptionalHeader.ImageBase;
    }

    return ((IMAGE_NT_HEADERS*)(pNtHeaders))->OptionalHeader.ImageBase;
}

/**
 * Gets section for rva.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @param   RelativeAddress The relative address.
 *
 * @return  Null if it fails, else the section for rva.
**/

IMAGE_SECTION_HEADER* cPEFile::GetSectionForRVA(
    const unsigned long RelativeAddress) const
{
    IMAGE_SECTION_HEADER* pSection = IMAGE_FIRST_SECTION(
        ((IMAGE_NT_HEADERS*)pNtHeaders));

    for (size_t i = 0; i < ((IMAGE_NT_HEADERS*)(pNtHeaders))->FileHeader.NumberOfSections; i++, pSection++) {

        unsigned long SectionStart = pSection->VirtualAddress;
        unsigned long SectionEnd = SectionStart;

        if (pSection->Misc.VirtualSize == 0)
            SectionEnd += pSection->SizeOfRawData;
        else
            SectionEnd += pSection->Misc.VirtualSize;

        if (RelativeAddress >= SectionStart && RelativeAddress < SectionEnd) {
            return pSection;
        }
    }

    return nullptr;
}

/**
 * Gets section count.
 *
 * @author  skeng#9524
 * @date    04.04.2017
 *
 * @return  The section count.
**/

size_t cPEFile::GetSectionCount() const
{
    return ((IMAGE_NT_HEADERS*)(pNtHeaders))->FileHeader.NumberOfSections;
}