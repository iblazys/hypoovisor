#include <ntddk.h>
#include <wdf.h>

#include "hypoovisor.h"
#include "hvroutines.h"

VOID Unload(IN PDRIVER_OBJECT Driver)
{
	UNICODE_STRING DosDeviceName;

	DbgPrint("DrvUnload Called !");

	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisor");

	IoDeleteSymbolicLink(&DosDeviceName);
	IoDeleteDevice(Driver->DeviceObject);
}

NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	// Start the hypervisor.
	if (HvVmxInitialize())
	{
		DbgPrint("[hypoo] hypervisor initialized successfully.");
	}
	else
	{
		DbgPrint("[hypoo] hypervisor initialization failed.");
	}

	//RunHV();

	// remove me
	// StopHV(); // remove, for testing purposes via manual mapping

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("[*] DrvClose Called !\n");

	// executing VMXOFF (From CPUID) on every logical processor
	StopHV();

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// WinDBG friendly entry, make a device
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS       NtStatus = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING DriverName, DosDeviceName;

	DbgPrint("DriverEntry Called.");

	RtlInitUnicodeString(&DriverName, L"\\Device\\MyHypervisor");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisor");

	NtStatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	if (NtStatus == STATUS_SUCCESS)
	{
		DbgPrint("[*] Setting Devices major functions.");

		DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;

		DriverObject->DriverUnload = Unload;

		IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	}

	return NtStatus;
}

/*
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

	RunHV();

	// remove me
	StopHV(); // remove, for testing purposes via manual mapping

	return STATUS_SUCCESS;

}
*/
