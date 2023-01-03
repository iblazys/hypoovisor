#include <ntddk.h>
#include <wdf.h>
#include "utils.h"
#include "vmx.h"
#include "hypervisor.h"

extern "C" void AsmEnableVmxOperation(void);

VOID Unload(IN WDFDRIVER Driver)
{
	UNREFERENCED_PARAMETER(Driver);
	DbgPrint("Unload Called");
}

// Lets try not to create a driver object so we can manually map this hypervisor.
NTSTATUS MyDriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DbgPrint("[+] Hypoovisor initializing...");

	if (!hypoovisor::Start()) 
	{
		DbgPrint("[-] Hypoovisor failed to start...");
		return STATUS_UNSUCCESSFUL;
	}

	// REMOVE ME ONCE UM COMMUNCATION IS COMPLETE
	hypoovisor::Stop();

	return STATUS_SUCCESS;
}