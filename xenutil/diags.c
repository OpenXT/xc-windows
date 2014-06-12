/*
 * Copyright (c) 2012 Citrix Systems, Inc.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* Various diagnostic functions */
#include <ntifs.h>
#include <ntstrsafe.h>
#include "xsapi.h"
#include "xs_ioctl.h"
#include "scsiboot.h"

#define XENDIAGS_TAG 'aidx'

#define ACPI_RSDP_SCAN_ADDR        0xE0000
#define ACPI_RSDP_SCAN_LENGTH      0x20000
#define ACPI_RSDP_SIGNATURE        "RSD PTR "
#define ACPI_RSDP_SIGNATURE_LENGTH 8
#define ACPI_RSDP_SIZE_V1          (20)
#define ACPI_RSDP_SIZE_V2          (ACPI_RSDP_SIZE_V1 + 16)

#define ACPI_SIGNATURE_LENGTH      4
#define ACPI_OEMID_LENGTH          6
#define ACPI_OEMTABLEID_LENGTH     8

#define ACPI_RSDT_SIGNATURE        "RSDT"
#define ACPI_XSDT_SIGNATURE        "XSDT"
#define ACPI_FADT_SIGNATURE        "FACP"
#define ACPI_FACS_SIGNATURE        "FACS"
#define ACPI_DSDT_SIGNATURE        "DSDT"

#pragma pack(push, 1)
typedef struct _ACPI_RSDP {
    CHAR Signature[ACPI_RSDP_SIGNATURE_LENGTH];
    UCHAR Checksum;
    CHAR OemId[ACPI_OEMID_LENGTH];
    UCHAR Revision;
    ULONG RsdtAddress;
    ULONG Length;
    ULARGE_INTEGER XsdtAddress;
    UCHAR ExtendedChecksum;
    CHAR Reserved[3];
} ACPI_RSDP;

typedef struct _ACPI_DESCRIPTOR {
    CHAR Signature[ACPI_SIGNATURE_LENGTH];
    ULONG Length;
    UCHAR Revision;
    UCHAR Checksum;
    CHAR OemId[ACPI_OEMID_LENGTH];
    CHAR OemTableId[ACPI_OEMTABLEID_LENGTH];
    ULONG OemRevision;
    ULONG CreatorId;
    ULONG CreatorRevision;
} ACPI_DESCRIPTOR;

typedef struct _ACPI_RSDT {
    ACPI_DESCRIPTOR Header;
    ULONG Entry[1];
} ACPI_RSDT;

typedef struct _ACPI_XSDT {
    ACPI_DESCRIPTOR Header;
    ULARGE_INTEGER Entry[1];
} ACPI_XSDT;

typedef struct _ACPI_FADT {
    ACPI_DESCRIPTOR Header;
    ULONG FacsAddress;
    ULONG DsdtAddress;
} ACPI_FADT;
#pragma pack(pop)

static ULONG
DiagsAcpiProcessTable(PHYSICAL_ADDRESS TablePhysAddr, UCHAR *pBuffer);

static ULONG
DiagsAcpiProcessFadt(ACPI_FADT *pFadt, UCHAR *pBuffer)
{
    PHYSICAL_ADDRESS PhysAddr = {0};
    ULONG TotalLength = 0, RetLength;

    if (pFadt->Header.Length < sizeof(ACPI_FADT)) {
        TraceError(("Invalid FADT length %d!\n", pFadt->Header.Length));
        return 0;
    }

    // Copy in the FADT
    if (pBuffer != NULL) {
        RtlMoveMemory(pBuffer, pFadt, pFadt->Header.Length);
        pBuffer += pFadt->Header.Length;
    }
    TotalLength += pFadt->Header.Length;

    PhysAddr.LowPart = pFadt->FacsAddress;
    RetLength = DiagsAcpiProcessTable(PhysAddr, pBuffer);
    if (pBuffer != NULL)
        pBuffer += RetLength;
    TotalLength += RetLength;

    PhysAddr.LowPart = pFadt->DsdtAddress;
    RetLength = DiagsAcpiProcessTable(PhysAddr, pBuffer);
    if (pBuffer != NULL)
        pBuffer += RetLength;
    TotalLength += RetLength;

    return TotalLength;
}

static ULONG
DiagsAcpiProcessTable(PHYSICAL_ADDRESS TablePhysAddr, UCHAR *pBuffer)
{
    ACPI_DESCRIPTOR *pTable;
    ULONG Length, TotalLength = 0, RetLength;
    SIZE_T Compare;

    pTable = (ACPI_DESCRIPTOR*)MmMapIoSpace(TablePhysAddr, sizeof(ACPI_DESCRIPTOR), MmNonCached);
    if (pTable == NULL) {
        TraceError(("Could not MAP table descriptor at addr: %x:%x!\n", TablePhysAddr.HighPart, TablePhysAddr.LowPart));
        return 0;
    }
    Length = pTable->Length;
    MmUnmapIoSpace(pTable, sizeof(ACPI_DESCRIPTOR));

    pTable = (ACPI_DESCRIPTOR*)MmMapIoSpace(TablePhysAddr, Length, MmNonCached);
    if (pTable == NULL) {
        TraceError(("Could not MAP table at addr: %x:%x!\n", TablePhysAddr.HighPart, TablePhysAddr.LowPart));
        return 0;
    }

    Compare = RtlCompareMemory(&pTable->Signature[0], ACPI_FADT_SIGNATURE, ACPI_SIGNATURE_LENGTH);
    if (Compare != ACPI_SIGNATURE_LENGTH) {
        // Copy the entire table in
        if (pBuffer != NULL)
            RtlMoveMemory(pBuffer, pTable, pTable->Length);
        TotalLength += pTable->Length;
    }
    else {
        RetLength = DiagsAcpiProcessFadt((ACPI_FADT*)pTable, pBuffer);
        TotalLength += RetLength;
    }

    MmUnmapIoSpace(pTable, Length);

    return TotalLength;
}

static ULONG
DiagsAcpiProcessRsdt(PHYSICAL_ADDRESS RsdtPhysAddr, UCHAR *pBuffer, BOOLEAN CopyTables)
{
    PHYSICAL_ADDRESS PhysAddr = {0};
    ACPI_DESCRIPTOR *pRsdt;
    ULONG Length, NumEntries, i, TotalLength = 0, RetLength;
    SIZE_T Compare;
    ULONG *pEntry;
    CHAR Signature[ACPI_SIGNATURE_LENGTH + 1];

    pRsdt = (ACPI_DESCRIPTOR*)MmMapIoSpace(RsdtPhysAddr, sizeof(ACPI_DESCRIPTOR), MmNonCached);
    if (pRsdt == NULL) {
        TraceError(("Could not MAP RSDP descriptor!\n"));
        return 0;
    }
    Length = pRsdt->Length;
    RtlZeroMemory(Signature, (ACPI_SIGNATURE_LENGTH + 1));
    RtlMoveMemory(Signature, pRsdt->Signature, ACPI_SIGNATURE_LENGTH);
    MmUnmapIoSpace(pRsdt, sizeof(ACPI_DESCRIPTOR));

    // Sanity check the descriptor
    Compare = RtlCompareMemory(Signature, ACPI_RSDT_SIGNATURE, ACPI_SIGNATURE_LENGTH);
    if (Compare != ACPI_SIGNATURE_LENGTH) {
        TraceError(("Invalid signature for RSDT table: %s\n", Signature));
        return 0;
    }
    if (Length > 0x200) {
        TraceError(("RSDT length if far too big: %d (0x%x)\n", Length, Length));
        return 0;
    }

    pRsdt = (ACPI_DESCRIPTOR*)MmMapIoSpace(RsdtPhysAddr, Length, MmNonCached);
    if (pRsdt == NULL) {
        TraceError(("Could not MAP RSDP table!\n"));
        return 0;
    }

    // Copy in the RSDT first
    if (pBuffer != NULL) {
        RtlMoveMemory(pBuffer, pRsdt, pRsdt->Length);
        pBuffer += pRsdt->Length;
    }
    TotalLength += pRsdt->Length;

    if (!CopyTables) {
        // Tables will be copied via the XSDT.
        MmUnmapIoSpace(pRsdt, Length);
        return TotalLength;
    }

    // Loop over entries
    NumEntries = (Length - sizeof(ACPI_DESCRIPTOR)) >> 2;
    pEntry = (ULONG*)((UCHAR*)pRsdt + sizeof(ACPI_DESCRIPTOR));
    for (i = 0; i < NumEntries; i++, pEntry++) {
        PhysAddr.LowPart = *pEntry;
        RetLength = DiagsAcpiProcessTable(PhysAddr, pBuffer);
        if (pBuffer != NULL)
            pBuffer += RetLength;
        TotalLength += RetLength;
    }

    MmUnmapIoSpace(pRsdt, Length);

    return TotalLength;
}

static ULONG
DiagsAcpiProcessXsdt(PHYSICAL_ADDRESS XsdtPhysAddr, UCHAR *pBuffer)
{
    ACPI_DESCRIPTOR *pXsdt;
    ULONG Length, NumEntries, i, TotalLength = 0, RetLength;
    SIZE_T Compare;
    PHYSICAL_ADDRESS *pEntry;
    CHAR Signature[ACPI_SIGNATURE_LENGTH + 1];

    pXsdt = (ACPI_DESCRIPTOR*)MmMapIoSpace(XsdtPhysAddr, sizeof(ACPI_DESCRIPTOR), MmNonCached);
    if (pXsdt == NULL) {
        TraceError(("Could not MAP XSDP descriptor!\n"));
        return 0;
    }
    Length = pXsdt->Length;
    RtlZeroMemory(Signature, (ACPI_SIGNATURE_LENGTH + 1));
    RtlMoveMemory(Signature, pXsdt->Signature, ACPI_SIGNATURE_LENGTH);
    MmUnmapIoSpace(pXsdt, sizeof(ACPI_DESCRIPTOR));

    // Sanity check the descriptor
    Compare = RtlCompareMemory(Signature, ACPI_XSDT_SIGNATURE, ACPI_SIGNATURE_LENGTH);
    if (Compare != ACPI_SIGNATURE_LENGTH) {
        TraceError(("Invalid signature for XSDT table: %s\n", Signature));
        return 0;
    }
    if (Length > 0x200) {
        TraceError(("XSDT length if far too big: %d (0x%x)\n", Length, Length));
        return 0;
    }

    pXsdt = (ACPI_DESCRIPTOR*)MmMapIoSpace(XsdtPhysAddr, Length, MmNonCached);
    if (pXsdt == NULL) {
        TraceError(("Could not MAP XSDP table!\n"));
        return 0;
    }

    // Copy in the XSDT first
    if (pBuffer != NULL) {
        RtlMoveMemory(pBuffer, pXsdt, pXsdt->Length);
        pBuffer += pXsdt->Length;
    }
    TotalLength += pXsdt->Length;

    // Loop over entries
    NumEntries = (Length - sizeof(ACPI_DESCRIPTOR)) >> 3;
    pEntry = (PHYSICAL_ADDRESS*)((UCHAR*)pXsdt + sizeof(ACPI_DESCRIPTOR));
    for (i = 0; i < NumEntries; i++, pEntry++) {
        RetLength = DiagsAcpiProcessTable(*pEntry, pBuffer);
        if (pBuffer != NULL)
            pBuffer += RetLength;
        TotalLength += RetLength;
    }

    MmUnmapIoSpace(pXsdt, Length);

    return TotalLength;
}

static ULONG
DiagsAcpiGetRsdp(ACPI_RSDP *pRsdp)
{
    PHYSICAL_ADDRESS PhysAddr = {0};
    UCHAR *pVirtAddr, *pPointer;
    ULONG Length = 0, i;
    SIZE_T Compare;
    ACPI_RSDP *pRsdpLoc;

    RtlZeroMemory(pRsdp, sizeof(ACPI_RSDP));

    PhysAddr.LowPart = ACPI_RSDP_SCAN_ADDR;
    pVirtAddr = (UCHAR*)MmMapIoSpace(PhysAddr, ACPI_RSDP_SCAN_LENGTH, MmNonCached);
    if (pVirtAddr == NULL) {
        TraceError(("Could not MAP in BIOS region to find RSDP table!\n"));
        return 0;
    }   

    // Loop and find the RSDP table, copy it to the buffer
    for (i = 0, pPointer = pVirtAddr;
         i < (ACPI_RSDP_SCAN_LENGTH - ACPI_RSDP_SIGNATURE_LENGTH);
         i++, pPointer++) {
        Compare = RtlCompareMemory(pPointer, ACPI_RSDP_SIGNATURE, ACPI_RSDP_SIGNATURE_LENGTH);
        if (Compare == ACPI_RSDP_SIGNATURE_LENGTH) {
            // Found it, sanity check
            if ((ACPI_RSDP_SCAN_LENGTH - i) < ACPI_RSDP_SIZE_V1) {
                TraceError(("RSDP signature located too near the end of ROM BIOS??\n"));
                break;
            }

            pRsdpLoc = (ACPI_RSDP*)pPointer;
            if (pRsdpLoc->Revision == 2) {
                // Another sanity check
                if ((ACPI_RSDP_SCAN_LENGTH - i) < ACPI_RSDP_SIZE_V2) {
                    TraceError(("RSDP V2 signature located too near the end of ROM BIOS??\n"));
                    break;
                }
                RtlMoveMemory(pRsdp, pRsdpLoc, ACPI_RSDP_SIZE_V2);
                Length = ACPI_RSDP_SIZE_V2;
                break;
            }
            else if (pRsdpLoc->Revision == 0) {
                RtlMoveMemory(pRsdp, pRsdpLoc, ACPI_RSDP_SIZE_V1);
                Length = ACPI_RSDP_SIZE_V1;
                break;
            }
            else {
                TraceError(("Unknown RSDP revision %d\n", pRsdpLoc->Revision));
                break;
            }
        }
    }

    MmUnmapIoSpace(pVirtAddr, ACPI_RSDP_SCAN_LENGTH);
    
    return Length;
}

static NTSTATUS
DiagsAcpiDumpWorker(UCHAR *pBuffer, ULONG *pLengthOut)
{
    ACPI_RSDP Rsdp;
    ULONG RsdpLength, TotalLength = 0, Length;
    UCHAR *pPointer = pBuffer;
    PHYSICAL_ADDRESS PhysAddr = {0};
    BOOLEAN IsV2;

    *pLengthOut = 0;

    // Get the RSDP, all starts there.
    RsdpLength = DiagsAcpiGetRsdp(&Rsdp);
    if (RsdpLength == 0)
        return STATUS_UNSUCCESSFUL;
    IsV2 = (RsdpLength == ACPI_RSDP_SIZE_V2) ? TRUE : FALSE;

    // Process RSDT first
    PhysAddr.LowPart = Rsdp.RsdtAddress;
    Length = DiagsAcpiProcessRsdt(PhysAddr, pPointer, (!IsV2));
    if (RsdpLength == 0)
        return STATUS_UNSUCCESSFUL; // SNO
    if (pPointer != NULL)
        pPointer += Length;
    TotalLength += Length;

    // Then the XSDT if there
    if (IsV2) {
        PhysAddr.QuadPart = Rsdp.XsdtAddress.QuadPart;
        Length = DiagsAcpiProcessXsdt(PhysAddr, pPointer);
        // (RsdpLength == 0) OK I guess
        if (pPointer != NULL)
            pPointer += Length;
        TotalLength += Length;
    }

    // Lastly copy in the RSDP at the end and set the length
    if (pPointer != NULL)
        RtlMoveMemory(pPointer, &Rsdp, RsdpLength);
    TotalLength += RsdpLength;

    *pLengthOut = TotalLength;
    
    return STATUS_SUCCESS;
}

NTSTATUS
DiagsAcpiDump(UCHAR *pBuffer, ULONG Length, ULONG *pLengthOut)
{
    NTSTATUS Status;

    if (pLengthOut == NULL)
        return STATUS_INVALID_PARAMETER;

    // User requesting a pBuffer size
    if (Length == 0) {
        Status = DiagsAcpiDumpWorker(NULL, pLengthOut);
        if (NT_SUCCESS(Status)) {
            return STATUS_BUFFER_OVERFLOW;
        }
        else {
            *pLengthOut = 0;
            return Status;
        }
    }

    if (pBuffer == NULL)
        return STATUS_INVALID_PARAMETER;

    Status = DiagsAcpiDumpWorker(NULL, pLengthOut);
    if (NT_SUCCESS(Status)) {
        if (*pLengthOut > Length)
            return STATUS_BUFFER_TOO_SMALL;
    }
    else {
        *pLengthOut = 0;
        return Status;
    }

    // Have enough room, fill it up
    return DiagsAcpiDumpWorker(pBuffer, pLengthOut);
}

#define E820_SIGNATURE        0x534D4150 // "SMAP"

#define E820_RAM              1
#define E820_RESERVED         2
#define E820_ACPI             3
#define E820_NVS              4

#define E820_PHYSICAL_ADDRESS 0x000EA100
#define E820_NR_OFFSET        0x0
#define E820_OFFSET           0x8
#define E820_MAX_COUNT        32

static NTSTATUS
DiagsGetE820Worker(UCHAR *pBuffer, ULONG *pLengthOut)
{
    PHYSICAL_ADDRESS PhysAddr = {0};
    UCHAR *pVirtAddr;
    USHORT Count, Size;
    XS_DIAGS_E820 *pE820;
    XS_DIAGS_E820_ENTRY *pE820Entry;

    *pLengthOut = 0;

    PhysAddr.LowPart = E820_PHYSICAL_ADDRESS;
    pVirtAddr = (UCHAR*)MmMapIoSpace(PhysAddr, PAGE_SIZE, MmNonCached);
    if (pVirtAddr == NULL) {
        TraceError(("Could not MAP in BIOS region to find E820 map!\n"));
        return 0;
    }
    Count = *((USHORT*)(pVirtAddr + E820_NR_OFFSET));
    if (Count > E820_MAX_COUNT) {
        TraceError(("Invalid E820 map entry count: %d!\n", Count));
        MmUnmapIoSpace(pVirtAddr, PAGE_SIZE);
        return STATUS_UNSUCCESSFUL;
    }

    Size = Count*sizeof(XS_DIAGS_E820_ENTRY);
    *pLengthOut = sizeof(XS_DIAGS_E820) + Size;
    if (pBuffer == NULL)
        return STATUS_SUCCESS;

    pE820 = (XS_DIAGS_E820*)pBuffer;
    pE820->signature = E820_SIGNATURE;
    pE820->entry_count = Count;
    pE820Entry = (XS_DIAGS_E820_ENTRY*)(pBuffer + FIELD_OFFSET(XS_DIAGS_E820, entries));

    // Copy in the entries
    RtlMoveMemory(pE820Entry, (pVirtAddr + E820_OFFSET), Size);

    MmUnmapIoSpace(pVirtAddr, PAGE_SIZE);

    return STATUS_SUCCESS;
}

NTSTATUS
DiagsGetE820(UCHAR *pBuffer, ULONG Length, ULONG *pLengthOut)
{
    NTSTATUS Status;

    if (pLengthOut == NULL)
        return STATUS_INVALID_PARAMETER;

    // User requesting a pBuffer size
    if (Length == 0) {
        Status = DiagsGetE820Worker(NULL, pLengthOut);
        if (NT_SUCCESS(Status)) {
            return STATUS_BUFFER_OVERFLOW;
        }
        else {
            *pLengthOut = 0;
            return Status;
        }
    }

    if (pBuffer == NULL)
        return STATUS_INVALID_PARAMETER;

    Status = DiagsGetE820Worker(NULL, pLengthOut);
    if (NT_SUCCESS(Status)) {
        if (*pLengthOut > Length)
            return STATUS_BUFFER_TOO_SMALL;
    }
    else {
        *pLengthOut = 0;
        return Status;
    }

    // Have enough room, fill it up
    return DiagsGetE820Worker(pBuffer, pLengthOut);
}

// PCI DWORD IO Ports
#define PCICONFIG_ADDRESS_PORT      0x0CF8
#define PCICONFIG_DATA_PORT         0x0CFC
#define PCICONFIG_MAX_BUS           0xFF
#define PCICONFIG_MAX_DEVICE        0x1F
#define PCICONFIG_MAX_FUNCTION      0x7
#define PCICONFIG_DWORDS            (XS_DIAGS_PCICONFIG_SIZE >> 2)
#define PCICONFIG_REGISTER_INVALID  0xFFFFFFFF
#define PCICONFIG_SHORTHDR_LIMIT    0x40
#define PCICONFIG_MAPPING_BIT       0x80000000
#define PCICONFIG_HDRTYPE_REGISTER  0xE

typedef struct _PCI_CONFIG {
    struct _PCI_CONFIG *pNext;
    ULONG Bus;
    ULONG Device;
    ULONG Function;
    UCHAR ConfigSpace[XS_DIAGS_PCICONFIG_SIZE];
} PCI_CONFIG;

static VOID
DiagsFreePciConfig(PCI_CONFIG *pConfigList)
{
    PCI_CONFIG *pConfigLast;

    if (pConfigList == NULL)
        return;

    while (pConfigList != NULL) {
        pConfigLast = pConfigList;
        pConfigList = pConfigList->pNext;
        ExFreePoolWithTag(pConfigLast, XENDIAGS_TAG);
    }
}

static DWORD
DiagsReadPciDword(ULONG Bus, ULONG Device, ULONG Function, ULONG Register)
{
    DWORD Address, Data;

    // Set address and endable access bit
    Address = (PCICONFIG_MAPPING_BIT)        | 
              ((Bus << 16)     & 0x00FF0000) |
              ((Device << 11)  & 0x0000F800) |
              ((Function << 8) & 0x00000700) |
              ((Register << 2) & 0x000000FC);

    // Access PCI configs space via ports
    WRITE_PORT_ULONG((ULONG*)PCICONFIG_ADDRESS_PORT, Address);
    Data = READ_PORT_ULONG((ULONG*)PCICONFIG_DATA_PORT);
    // Clear mapping bit, done accessing
    WRITE_PORT_ULONG((ULONG*)PCICONFIG_ADDRESS_PORT, 0);

    return Data;
}

static NTSTATUS
DiagsScanPciConfig(PCI_CONFIG **ppConfigList, ULONG *pCount)
{
    PCI_CONFIG *pConfigFirst = NULL, *pConfigLast = NULL, *pConfigCurr = NULL;
    ULONG Count = 0;
    ULONG Bus, Device, Function, Register, Index;
    DWORD Value;
    BOOLEAN Valid;

    *ppConfigList = NULL;
    *pCount = 0;

    for (Bus = 0; Bus <= PCICONFIG_MAX_BUS; Bus++) {

        for (Device = 0; Device <= PCICONFIG_MAX_DEVICE; Device++) {

            for (Function = 0; Function <= PCICONFIG_MAX_FUNCTION; Function++) {
                // Reset
                Index = 0;
                Valid = FALSE;

                // Inner most loop, read each DWORD PCI config register
                for (Register = 0; Register < PCICONFIG_DWORDS; Register++) {                    
                    Value = DiagsReadPciDword(Bus, Device, Function, Register);

                    // If there is a device, allocate block for storing its information, if
                    // not then don't try to read too far if the deviced is non-existant to avoid hangs.
                    if (Register == 0) {
                        if (Value == PCICONFIG_REGISTER_INVALID)
                            break;

                        Valid = TRUE;
                        pConfigCurr = (PCI_CONFIG*)ExAllocatePoolWithTag(NonPagedPool,
                                                                         sizeof(PCI_CONFIG),
                                                                         XENDIAGS_TAG);
                        if (pConfigCurr == NULL) {
                            DiagsFreePciConfig(pConfigFirst);
                            return STATUS_NO_MEMORY;
                        }
                        pConfigCurr->pNext = NULL;
                        pConfigCurr->Bus = Bus;
                        pConfigCurr->Device = Device;
                        pConfigCurr->Function = Function;
                        if (pConfigFirst == NULL) {
                            pConfigFirst = pConfigCurr;
                            pConfigLast = pConfigCurr;
                        }
                        else {
                            pConfigLast->pNext = pConfigCurr;
                            pConfigLast = pConfigCurr;
                        }
                        Count++;
                    }

                    // Write the current DWORD register value in swapping endian order
                    pConfigCurr->ConfigSpace[Index++] = (UCHAR)((Value) & 0xFF);
                    pConfigCurr->ConfigSpace[Index++] = (UCHAR)((Value >> 8) & 0xFF);
                    pConfigCurr->ConfigSpace[Index++] = (UCHAR)((Value >> 16) & 0xFF);
                    pConfigCurr->ConfigSpace[Index++] = (UCHAR)((Value >> 24) & 0xFF);

                    // Test to not go further than 0x40 bytes for config space header types
                    // that are other than type 1.
                    if (Index == PCICONFIG_SHORTHDR_LIMIT) {
                        if ((pConfigCurr->ConfigSpace[PCICONFIG_HDRTYPE_REGISTER] & 0x7F) != 0) {
                            // Fill the rest in from 0x40 ... 0xFF with 0xFF
                            RtlFillMemory(&pConfigCurr->ConfigSpace[Index],
                                          XS_DIAGS_PCICONFIG_SIZE - Index,
                                          0xFF);
                            break;
                        }
                    }

                } // Register loop

                // If function 0 is not value then none of the others will be so drop out
                if ((Function == 0)&&(!Valid))
                    break;

                // If this is function 0 and not a multifunction card then there should be no more functions
                if ((Function == 0)&&((pConfigCurr->ConfigSpace[PCICONFIG_HDRTYPE_REGISTER] & 0x80) == 0))
                    break;

            } // Function loop

        } // Device loop

    } // Bus loop

    *ppConfigList = pConfigFirst;
    *pCount = Count;
    return STATUS_SUCCESS;
}

NTSTATUS
DiagsPciConfig(UCHAR *pBuffer, ULONG Length, ULONG *pLengthOut)
{
    NTSTATUS Status;
    PCI_CONFIG *pConfigList;
    PCI_CONFIG *pConfigNext;
    ULONG Count, Size;
    XS_DIAGS_PCICONFIG *pPciConfig;
    XS_DIAGS_PCICONFIG_ENTRY *pPciConfigEntry;

    if (pLengthOut == NULL)
        return STATUS_INVALID_PARAMETER;
    *pLengthOut = 0;

    // First scan all PCI bdf's. Just as a reminder, the following !pci syntax
    // can be used to dump the config space:
    //          F B D F S E 
    // kd> !pci 3 0 1 0 0 ff
    // The above will dump device 00:1.0 from 0 -> FF (note segment is not used).
    Status = DiagsScanPciConfig(&pConfigList, &Count);
    if (!NT_SUCCESS(Status))
        return Status; // out of memory most likely

    // Check if the information will fit in the output buffer. This handles
    // the case where Length is zero requesting the size and the cases where
    // the PCI config could have changed.
    Size = sizeof(XS_DIAGS_PCICONFIG) + Count*sizeof(XS_DIAGS_PCICONFIG_ENTRY);
    if (Size > Length) {
        DiagsFreePciConfig(pConfigList);
        // Request larger buffer
        *pLengthOut = Size;
        return STATUS_BUFFER_OVERFLOW;
    }

    if (pBuffer == NULL)
        return STATUS_INVALID_PARAMETER;

    pPciConfig = (XS_DIAGS_PCICONFIG*)pBuffer;
    pPciConfigEntry = (XS_DIAGS_PCICONFIG_ENTRY*)(pBuffer + FIELD_OFFSET(XS_DIAGS_PCICONFIG, entries));
    pPciConfig->rev = XS_DIAGS_PCICONFIG_REV;
    pPciConfig->count = Count;

    // Else copy over all the PCI config information
    pConfigNext = pConfigList;

    while (pConfigNext != NULL) {
        pPciConfigEntry->bus = pConfigNext->Bus;
        pPciConfigEntry->device = pConfigNext->Device;
        pPciConfigEntry->function = pConfigNext->Function;
        RtlMoveMemory(&pPciConfigEntry->config_space[0], &pConfigNext->ConfigSpace[0], XS_DIAGS_PCICONFIG_SIZE);

        pPciConfigEntry++;
        pConfigNext = pConfigNext->pNext;
    }

    DiagsFreePciConfig(pConfigList);
    *pLengthOut = Size;

    return STATUS_SUCCESS;
}
