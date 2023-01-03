#pragma once
#include <ntddk.h>

namespace ept {

	/// <summary>
	/// Extended-Page-Table Pointer 
	/// </summary>
	typedef union _EPTP
	{
		struct
		{
			/**
			 * [Bits 2:0] EPT paging-structure memory type:
			 * - 0 = Uncacheable (UC)
			 * - 6 = Write-back (WB)
			 * Other values are reserved.
			 *
			 * @see Vol3C[28.2.6(EPT and memory Typing)]
			 */
			UINT64 MemoryType : 3;

			/**
			 * [Bits 5:3] This value is 1 less than the EPT page-walk length.
			 *
			 * @see Vol3C[28.2.6(EPT and memory Typing)]
			 */
			UINT64 PageWalkLength : 3;

			/**
			 * [Bit 6] Setting this control to 1 enables accessed and dirty flags for EPT.
			 *
			 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
			 */
			UINT64 EnableAccessAndDirtyFlags : 1;
			UINT64 Reserved1 : 5;

			/**
			 * [Bits 47:12] Bits N-1:12 of the physical address of the 4-KByte aligned EPT PML4 table.
			 */
			UINT64 PageFrameNumber : 36;
			UINT64 Reserved2 : 16;
		};

		UINT64 Flags;
	} EPTP, * PEPTP;


	/// <summary>
	/// EPT PLM4 Entry
	/// </summary>
	typedef union _PEPT_PML4
	{
		struct
		{
			/**
			 * [Bit 0] Read access; indicates whether reads are allowed from the 512-GByte region controlled by this entry.
			 */
			UINT64 ReadAccess : 1;

			/**
			 * [Bit 1] Write access; indicates whether writes are allowed from the 512-GByte region controlled by this entry.
			 */
			UINT64 WriteAccess : 1;

			/**
			 * [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
			 * instruction fetches are allowed from the 512-GByte region controlled by this entry.
			 * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
			 * allowed from supervisor-mode linear addresses in the 512-GByte region controlled by this entry.
			 */
			UINT64 ExecuteAccess : 1;
			UINT64 Reserved1 : 5;

			/**
			 * [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 512-GByte region
			 * controlled by this entry. Ignored if bit 6 of EPTP is 0.
			 *
			 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
			 */
			UINT64 Accessed : 1;
			UINT64 Reserved2 : 1;

			/**
			 * [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
			 * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 512-GByte region
			 * controlled by this entry. If that control is 0, this bit is ignored.
			 */
			UINT64 UserModeExecute : 1;
			UINT64 Reserved3 : 1;

			/**
			 * [Bits 47:12] Physical address of 4-KByte aligned EPT page-directory-pointer table referenced by this entry.
			 */
			UINT64 PageFrameNumber : 36;
			UINT64 Reserved4 : 16;
		};

		UINT64 Flags;
	} EPT_PML4, * PEPT_PML4;


	/// <summary>
	/// EPT Page-Directory-Pointer-Table Entry
	/// </summary>
	typedef union _EPDPTE
	{
		struct
		{
			/**
			 * [Bit 0] Read access; indicates whether reads are allowed from the 1-GByte region controlled by this entry.
			 */
			UINT64 ReadAccess : 1;

			/**
			 * [Bit 1] Write access; indicates whether writes are allowed from the 1-GByte region controlled by this entry.
			 */
			UINT64 WriteAccess : 1;

			/**
			 * [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
			 * instruction fetches are allowed from the 1-GByte region controlled by this entry.
			 * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
			 * allowed from supervisor-mode linear addresses in the 1-GByte region controlled by this entry.
			 */
			UINT64 ExecuteAccess : 1;
			UINT64 Reserved1 : 5;

			/**
			 * [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 1-GByte region
			 * controlled by this entry. Ignored if bit 6 of EPTP is 0.
			 *
			 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
			 */
			UINT64 Accessed : 1;
			UINT64 Reserved2 : 1;

			/**
			 * [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
			 * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 1-GByte region controlled
			 * by this entry. If that control is 0, this bit is ignored.
			 */
			UINT64 UserModeExecute : 1;
			UINT64 Reserved3 : 1;

			/**
			 * [Bits 47:12] Physical address of 4-KByte aligned EPT page-directory-pointer table referenced by this entry.
			 */
			UINT64 PageFrameNumber : 36;
			UINT64 Reserved4 : 16;
		};

		UINT64 Flags;
	} EPDPTE, * PEPDPTE;


	/// <summary>
	/// EPT Page-Directory Entry
	/// </summary>
	typedef union _EPDE
	{
		struct
		{
			/**
			 * [Bit 0] Read access; indicates whether reads are allowed from the 2-MByte region controlled by this entry.
			 */
			UINT64 ReadAccess : 1;

			/**
			 * [Bit 1] Write access; indicates whether writes are allowed from the 2-MByte region controlled by this entry.
			 */
			UINT64 WriteAccess : 1;

			/**
			 * [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
			 * instruction fetches are allowed from the 2-MByte region controlled by this entry.
			 * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
			 * allowed from supervisor-mode linear addresses in the 2-MByte region controlled by this entry.
			 */
			UINT64 ExecuteAccess : 1;
			UINT64 Reserved1 : 5;

			/**
			 * [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 2-MByte region
			 * controlled by this entry. Ignored if bit 6 of EPTP is 0.
			 *
			 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
			 */
			UINT64 Accessed : 1;
			UINT64 Reserved2 : 1;

			/**
			 * [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
			 * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 2-MByte region controlled
			 * by this entry. If that control is 0, this bit is ignored.
			 */
			UINT64 UserModeExecute : 1;
			UINT64 Reserved3 : 1;

			/**
			 * [Bits 47:12] Physical address of 4-KByte aligned EPT page table referenced by this entry.
			 */
			UINT64 PageFrameNumber : 36;
			UINT64 Reserved4 : 16;
		};

		UINT64 Flags;
	} EPDE, * PEPDE;


	/// <summary>
	/// EPT Page-Table Entry
	/// </summary>
	typedef union _EPTE
	{
		struct
		{
			/**
			 * [Bit 0] Read access; indicates whether reads are allowed from the 4-KByte page referenced by this entry.
			 */
			UINT64 ReadAccess : 1;

			/**
			 * [Bit 1] Write access; indicates whether writes are allowed from the 4-KByte page referenced by this entry.
			 */
			UINT64 WriteAccess : 1;

			/**
			 * [Bit 2] If the "mode-based execute control for EPT" VM-execution control is 0, execute access; indicates whether
			 * instruction fetches are allowed from the 4-KByte page controlled by this entry.
			 * If that control is 1, execute access for supervisor-mode linear addresses; indicates whether instruction fetches are
			 * allowed from supervisor-mode linear addresses in the 4-KByte page controlled by this entry.
			 */
			UINT64 ExecuteAccess : 1;

			/**
			 * [Bits 5:3] EPT memory type for this 4-KByte page.
			 *
			 * @see Vol3C[28.2.6(EPT and memory Typing)]
			 */
			UINT64 MemoryType : 3;

			/**
			 * [Bit 6] Ignore PAT memory type for this 4-KByte page.
			 *
			 * @see Vol3C[28.2.6(EPT and memory Typing)]
			 */
			UINT64 IgnorePat : 1;
			UINT64 Reserved1 : 1;

			/**
			 * [Bit 8] If bit 6 of EPTP is 1, accessed flag for EPT; indicates whether software has accessed the 4-KByte page
			 * referenced by this entry. Ignored if bit 6 of EPTP is 0.
			 *
			 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
			 */
			UINT64 Accessed : 1;

			/**
			 * [Bit 9] If bit 6 of EPTP is 1, dirty flag for EPT; indicates whether software has written to the 4-KByte page referenced
			 * by this entry. Ignored if bit 6 of EPTP is 0.
			 *
			 * @see Vol3C[28.2.4(Accessed and Dirty Flags for EPT)]
			 */
			UINT64 Dirty : 1;

			/**
			 * [Bit 10] Execute access for user-mode linear addresses. If the "mode-based execute control for EPT" VM-execution control
			 * is 1, indicates whether instruction fetches are allowed from user-mode linear addresses in the 4-KByte page controlled
			 * by this entry. If that control is 0, this bit is ignored.
			 */
			UINT64 UserModeExecute : 1;
			UINT64 Reserved2 : 1;

			/**
			 * [Bits 47:12] Physical address of the 4-KByte page referenced by this entry.
			 */
			UINT64 PageFrameNumber : 36;
			UINT64 Reserved3 : 15;

			/**
			 * [Bit 63] Suppress \#VE. If the "EPT-violation \#VE" VM-execution control is 1, EPT violations caused by accesses to this
			 * page are convertible to virtualization exceptions only if this bit is 0. If "EPT-violation \#VE" VMexecution control is
			 * 0, this bit is ignored.
			 *
			 * @see Vol3C[25.5.6.1(Convertible EPT Violations)]
			 */
			UINT64 SuppressVe : 1;
		};

		UINT64 Flags;
	} EPTE, * PEPTE;

	///////////////////
	// Functions
	///////////////////

	UINT64 InitializeEptp();
}


