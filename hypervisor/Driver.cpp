#include <ntddk.h>
#include <wdf.h>
#include "utils.h"
#include "vmx.h"

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

	DbgPrint("[+] Checking for VMX support...");

	if (vmx::InitializeVmx()) 
	{
		DbgPrint("[*] VMX Initiated Successfully.");
	}

	return 0;
}