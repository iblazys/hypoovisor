#include <ntddk.h>
#include <wdf.h>

#include "hypoovisor.h"

VOID Unload(IN WDFDRIVER Driver)
{
	UNREFERENCED_PARAMETER(Driver);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	// Start the hypervisor.
	if (InitializeHV()) 
	{
		DbgPrint("[hypoo] hypervisor initialized successfully.");
	}
	else
	{
		DbgPrint("[hypoo] hypervisor initialization failed.");
	}

	// remove me
	StopHV(); // remove, for testing purposes via manual mapping

	return STATUS_SUCCESS;

}
