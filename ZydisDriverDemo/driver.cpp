#include <wdm.h>
#include <ntimage.h>
#include <stdio.h>
#include <stdarg.h>
#include "Zydis/Zydis.h"



extern "C"
{
    NTKERNELAPI
        PVOID
        NTAPI
        RtlPcToFileHeader(
            _In_ PVOID PcValue,
            _Out_ PVOID* BaseOfImage
        );

    NTKERNELAPI
        PIMAGE_NT_HEADERS
        NTAPI
        RtlImageNtHeader(
            _In_ PVOID ImageBase
        );

    DRIVER_INITIALIZE DriverEntry;
    DRIVER_UNLOAD DriverUnload;
}

VOID
Print(
    _In_ PCCH Format,
    _In_ ...
)
{
    CHAR message[512];
    va_list argList;
    va_start(argList, Format);
    const int n = _vsnprintf_s(message, sizeof(message), sizeof(message) - 1, Format, argList);
    message[n] = '\0';
    vDbgPrintExWithPrefix("[ZYDIS] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, message, argList);
    va_end(argList);
}


_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    if (ZydisGetVersion() != ZYDIS_VERSION) {
        Print("Invalid zydis version\n");
        return STATUS_UNKNOWN_REVISION;
    }

    PVOID imageBase;
    RtlPcToFileHeader((PVOID)DriverObject->DriverInit, &imageBase);
    if (imageBase == nullptr)
        return STATUS_INVALID_IMAGE_FORMAT;

    const PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(imageBase);
    if (ntHeaders == NULL)
        return STATUS_INVALID_IMAGE_FORMAT;

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    PIMAGE_SECTION_HEADER initSection = nullptr;
    for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        if (memcmp(section->Name, "INIT", sizeof("INIT") - 1) == 0)
        {
            initSection = section;
            break;
        }
        section++;
    }
    if (initSection == nullptr)
        return STATUS_NOT_FOUND;

    const ULONG entryPointRva = (ULONG)((ULONG_PTR)DriverObject->DriverInit - (ULONG_PTR)imageBase);
    const ULONG importDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    SIZE_T length = initSection->VirtualAddress + initSection->SizeOfRawData - entryPointRva;
    if (importDirRva > entryPointRva && importDirRva > initSection->VirtualAddress &&
        importDirRva < initSection->VirtualAddress + initSection->SizeOfRawData)
        length = importDirRva - entryPointRva;

    Print("Driver image base: 0x%p, size: 0x%X\n", (PVOID)imageBase, ntHeaders->OptionalHeader.SizeOfImage);
    Print("Entry point RVA: 0x%X (0x%p)\n", entryPointRva, DriverObject->DriverInit);

    // Initialize Zydis decoder and formatter
    ZydisDecoder decoder;
#ifdef _M_AMD64
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
#else
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32)))
#endif
        return STATUS_DRIVER_INTERNAL_ERROR;

    ZydisFormatter formatter;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
        return STATUS_DRIVER_INTERNAL_ERROR;

    SIZE_T readOffset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    ZyanStatus status;
    CHAR printBuffer[128];

    // Start the decode loop
    while ((status = ZydisDecoderDecodeFull(&decoder,
        (PVOID)((ULONG_PTR)imageBase + entryPointRva + readOffset),
        length - readOffset, &instruction,
        operands)) != ZYDIS_STATUS_NO_MORE_DATA)
    {
        NT_ASSERT(ZYAN_SUCCESS(status));
        if (!ZYAN_SUCCESS(status))
        {
            readOffset++;
            continue;
        }

        // Format and print the instruction
        const ZyanU64 instrAddress = (ZyanU64)((ULONG_PTR)imageBase + entryPointRva + readOffset);
        ZydisFormatterFormatInstruction(
            &formatter, &instruction, operands, instruction.operand_count_visible, printBuffer,
            sizeof(printBuffer), instrAddress, NULL);

        readOffset += instruction.length;

        if (instruction.machine_mode != ZYDIS_MACHINE_MODE_LONG_64) {
            continue;
        }
        if (instruction.mnemonic != ZYDIS_MNEMONIC_JMP) {
            continue;
        }
        if (instruction.operand_count != 2) {
            continue;
        }
        if (operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            continue;
        }
        if (operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER) {
            continue;
        }

        if (operands[1].reg.value != ZYDIS_REGISTER_RIP) {
            continue;
        }

        Print("Target Address: 0x%-16llX\n", instrAddress + instruction.length
            + operands[0].imm.value.u);

        Print("+%-4X 0x%-16llX\t\t%hs\n", (ULONG)readOffset, instrAddress, printBuffer);
    }

    // Return an error status so that the driver does not have to be unloaded after running.
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
void DriverUnload(
    PDRIVER_OBJECT DriverObject
) {
    UNREFERENCED_PARAMETER(DriverObject);
}