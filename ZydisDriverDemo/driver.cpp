#include <ntifs.h>
#include <ntimage.h>
#include <stdio.h>
#include <stdarg.h>
#include "Zydis/Zydis.h"



extern "C"
{
	typedef enum _SYSTEM_INFORMATION_CLASS {
		SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
		SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
		SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
		SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
		SystemPathInformation, // not implemented
		SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
		SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
		SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
		SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
		SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
		SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
		SystemModuleInformation, // q: RTL_PROCESS_MODULES
		SystemLocksInformation, // q: RTL_PROCESS_LOCKS
		SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
		SystemPagedPoolInformation, // not implemented
		SystemNonPagedPoolInformation, // not implemented
		SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
		SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
		SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
		SystemVdmInstemulInformation, // q
		SystemVdmBopInformation, // not implemented // 20
		SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
		SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
		SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
		SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
		SystemFullMemoryInformation, // not implemented
		SystemLoadGdiDriverInformation, // s (kernel-mode only)
		SystemUnloadGdiDriverInformation, // s (kernel-mode only)
		SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
		SystemSummaryMemoryInformation, // not implemented
		SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
		SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
		SystemObsolete0, // not implemented
		SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
		SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
		SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
		SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
		SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
		SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
		SystemPrioritySeperation, // s (requires SeTcbPrivilege)
		SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
		SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
		SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
		SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
		SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
		SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
		SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
		SystemSessionCreate, // not implemented
		SystemSessionDetach, // not implemented
		SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
		SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
		SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
		SystemVerifierThunkExtend, // s (kernel-mode only)
		SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
		SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
		SystemNumaProcessorMap, // q
		SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
		SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
		SystemRecommendedSharedDataAlignment, // q
		SystemComPlusPackage, // q; s
		SystemNumaAvailableMemory, // 60
		SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
		SystemEmulationBasicInformation, // q
		SystemEmulationProcessorInformation,
		SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
		SystemLostDelayedWriteInformation, // q: ULONG
		SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
		SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
		SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
		SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
		SystemObjectSecurityMode, // q: ULONG // 70
		SystemWatchdogTimerHandler, // s (kernel-mode only)
		SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
		SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
		SystemWow64SharedInformationObsolete, // not implemented
		SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
		SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
		SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
		SystemVerifierTriageInformation, // not implemented
		SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
		SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
		SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
		SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
		SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
		SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
		SystemProcessorPowerInformationEx, // not implemented
		SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
		SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
		SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
		SystemErrorPortInformation, // s (requires SeTcbPrivilege)
		SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
		SystemHypervisorInformation, // q; s (kernel-mode only)
		SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
		SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
		SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
		SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
		SystemPrefetchPatchInformation, // not implemented
		SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
		SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
		SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
		SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
		SystemNumaProximityNodeInformation, // q
		SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
		SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
		SystemProcessorMicrocodeUpdateInformation, // s
		SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
		SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
		SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
		SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
		SystemStoreInformation, // q; s // SmQueryStoreInformation
		SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
		SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
		SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
		SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
		SystemNativeBasicInformation, // not implemented
		SystemSpare1, // not implemented
		SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
		SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
		SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
		SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
		SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
		SystemNodeDistanceInformation, // q
		SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
		SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
		SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
		SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
		SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
		SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
		SystemBadPageInformation,
		SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
		SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
		SystemEntropyInterruptTimingCallback,
		SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
		SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION
		SystemThrottleNotificationInformation,
		SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
		SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
		SystemDeviceDataEnumerationInformation,
		SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
		SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
		SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
		SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
		SystemSpare0,
		SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
		SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
		SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
		SystemEntropyInterruptTimingRawInformation,
		SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
		SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
		SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
		SystemBootMetadataInformation, // 150
		SystemSoftRebootInformation,
		SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
		SystemOfflineDumpConfigInformation,
		SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
		SystemRegistryReconciliationInformation,
		SystemEdidInformation,
		SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
		SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
		SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
		SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
		SystemVmGenerationCountInformation,
		SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
		SystemKernelDebuggerFlags,
		SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
		SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
		SystemHardwareSecurityTestInterfaceResultsInformation,
		SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
		SystemAllowedCpuSetsInformation,
		SystemDmaProtectionInformation, // q: SYSTEM_DMA_PROTECTION_INFORMATION
		SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
		SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
		SystemCodeIntegrityPolicyFullInformation,
		SystemAffinitizedInterruptProcessorInformation,
		SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
		SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
		SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
		SystemWin32WerStartCallout,
		SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
		SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
		SystemInterruptSteeringInformation, // 180
		SystemSupportedProcessorArchitectures,
		SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
		SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
		SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
		SystemControlFlowTransition,
		SystemKernelDebuggingAllowed,
		SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
		SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
		SystemCodeIntegrityPoliciesFullInformation,
		SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
		SystemIntegrityQuotaInformation,
		SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
		SystemProcessorIdleMaskInformation, // since REDSTONE3
		SystemSecureDumpEncryptionInformation,
		SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
		MaxSystemInfoClass
	} SYSTEM_INFORMATION_CLASS;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION {
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES {
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	NTKERNELAPI
		PIMAGE_NT_HEADERS
		NTAPI
		RtlImageNtHeader(
			_In_ PVOID ImageBase
		);

	NTKERNELAPI
		NTSTATUS NTAPI ZwQuerySystemInformation(
			_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
			_Inout_   PVOID                    SystemInformation,
			_In_      ULONG                    SystemInformationLength,
			_Out_opt_ PULONG                   ReturnLength
		);

	DRIVER_INITIALIZE DriverEntry;
	DRIVER_UNLOAD DriverUnload;
}

NTSTATUS SearchPattern(PUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const VOID* base,
	ULONG_PTR size, PVOID* ppFound);

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

PVOID GetKernelBase() {
	void* buffer = nullptr;
	ULONG size = 1 << 18;

	buffer = ExAllocatePool(NonPagedPool, size);
	if (!buffer) {
		return nullptr;
	}

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation,
		buffer, size, nullptr);
	if (!NT_SUCCESS(status)) {
		ExFreePool(buffer);
		return nullptr;
	}

	auto info = (RTL_PROCESS_MODULES*)buffer;
	PVOID imageBase = info->Modules[0].ImageBase;

	ExFreePool(buffer);
	return imageBase;
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

	PVOID imageBase = GetKernelBase();
	if (imageBase == nullptr)
		return STATUS_INVALID_IMAGE_FORMAT;

	const PIMAGE_NT_HEADERS ntHeaders = RtlImageNtHeader(imageBase);
	if (ntHeaders == NULL)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(ntHeaders);
	PIMAGE_SECTION_HEADER initSection = nullptr;
	ULONG totalCount = 0;


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

	for (USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		if (pSec == nullptr) {
			continue;
		}

		if (pSec->Characteristics & IMAGE_SCN_MEM_READ &&
			pSec->Characteristics & IMAGE_SCN_CNT_CODE &&
			pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
			!(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
			(*(PULONG)pSec->Name != 'TINI')) {
			ULONG_PTR startAddr = (ULONG_PTR)((PUCHAR)imageBase + pSec->VirtualAddress);
			ULONG_PTR maxAddress = startAddr + pSec->Misc.VirtualSize;

#ifdef _WIN64
			UCHAR pattern1[] = "\x48\xb8\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xff\xe0";
			ULONG patternSize = sizeof(pattern1) - 1;
			Print("start address: %p max address: %p\n", startAddr, maxAddress);

			ULONG_PTR maxSearchAddr = maxAddress - patternSize;
			ULONG_PTR searchAddr = startAddr;
			while (searchAddr <= maxSearchAddr) {
				PVOID pFound = NULL;
				NTSTATUS status = SearchPattern(pattern1, 0xCC, patternSize, (void*)searchAddr, pSec->Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(status)) {
					searchAddr = (ULONG_PTR)pFound + patternSize;
					Print("Detect suspicious hook type 1 at %p\n", pFound);
					totalCount++;
				}
				else {
					break;
				}
			}

			UCHAR pattern2[] = "\x68\xcc\xcc\xcc\xcc\xc7\x44\x24\x04\xcc\xcc\xcc\xcc\xc3";
			patternSize = sizeof(pattern2) - 1;
			maxSearchAddr = maxAddress - patternSize;
			searchAddr = startAddr;
			while (searchAddr <= maxSearchAddr) {
				PVOID pFound = NULL;
				NTSTATUS status = SearchPattern(pattern2, 0xCC, patternSize, (void*)searchAddr, pSec->Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(status)) {
					Print("Detect suspicious hook type 2 at %p\n", pFound);
					searchAddr = (ULONG_PTR)pFound + patternSize;
					totalCount++;
				}
				else {
					break;
				}
			}

			UCHAR pattern3[] = "\xe9\xcc\xcc\xcc\xcc";
			patternSize = sizeof(pattern3) - 1;
			maxSearchAddr = maxAddress - patternSize;
			searchAddr = startAddr;
			while (searchAddr <= maxSearchAddr) {
				PVOID pFound = NULL;
				NTSTATUS status = SearchPattern(pattern3, 0xCC, patternSize, (void*)searchAddr, pSec->Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(status)) {

					SIZE_T length = sizeof(pattern3);
					// Start the decode loop
					while ((status = ZydisDecoderDecodeFull(&decoder,
						pFound,
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
						const ZyanU64 instrAddress = (ZyanU64)pFound;
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
						ULONG_PTR targetAddress = instrAddress + instruction.length
							+ operands[0].imm.value.u;
						if (targetAddress < maxAddress) {
							continue;
						}
						BOOLEAN isValid = MmIsAddressValid((PVOID)targetAddress);
						if (!isValid) {
							continue;
						}
						Print("Target Address: 0x%-16llX\n", targetAddress);

						totalCount++;
						Print("Detect suspicious hook type 3 at %p\n", pFound);
						Print("0x%-16llX\t\t%hs\n", instrAddress, printBuffer);
					}

					searchAddr = (ULONG_PTR)pFound + patternSize;
				}
				else {
					break;
				}
			}
#endif // _WIN64

		}
		else {
			ULONG_PTR sectionAddr = (ULONG_PTR)((PUCHAR)imageBase + pSec->VirtualAddress);
			ULONG_PTR maxAddress = sectionAddr + pSec->Misc.VirtualSize;
			Print("SectionAddress: %p, maxAddress: %p, characteristics %x\n", 
				sectionAddr,maxAddress,pSec->Characteristics);
		}
		pSec++;
	}
	Print("Total inline count: %d\n", totalCount);

	// Return an error status so that the driver does not have to be unloaded after running.
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
void DriverUnload(
	PDRIVER_OBJECT DriverObject
) {
	UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS SearchPattern(PUCHAR pattern, UCHAR wildcard, ULONG_PTR len, const VOID* base,
	ULONG_PTR size, PVOID* ppFound) {
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			PUCHAR pMem = (PUCHAR)base + i + j;
			BOOLEAN isValid = MmIsAddressValid(pMem);
			if (!isValid) {
				found = FALSE;
				break;
			}
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}