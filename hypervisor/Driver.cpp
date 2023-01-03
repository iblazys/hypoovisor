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

	DbgPrint("[+] Hypoovisor started");

	DbgPrint("[+] Checking for VMX support");

	if (!vmx::IsVMXSupported()) 
	{
		DbgPrint("[+] This device does not support VMX!");
		return 1;
	}

	DbgPrint("[+] Enabling VMX Operation...");

	AsmEnableVmxOperation(); // TODO: Move to C++

	DbgPrint("[+] VMX Operation Enabled");

	return 0;
}