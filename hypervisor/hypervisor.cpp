#include "hypervisor.h"
#include "utils.h"
#include "vmx.h"
#include "ept.h"

namespace hypoovisor 
{
	bool Start()
	{
		DbgPrint("[+] Checking for VMX support...");

		if (!vmx::InitializeVmx())
		{
			DbgPrint("[-] Failed to initialize VMX.");
			return false;
		}

		DbgPrint("[+] VMX Initiated Successfully.");

		ept::InitializeEptp(); // remove me, testing purposes
		return true;
	}

	bool Stop()
	{
		DbgPrint("[-] Turning off VMX so we can load the driver again.");
		vmx::TerminateVmx();

		return true;
	}
}