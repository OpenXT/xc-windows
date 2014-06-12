/*
 * Copyright (c) 2009 Citrix Systems, Inc.
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

/* Support for SCSI mode sense and mode select commands.  Mode select
   is pretty boring, given that we don't have any changeable
   parameters. */
#pragma warning (push, 3)
#include "xenvbd.h"
#include "xsapi.h"
#pragma warning (pop)

enum page_control_type {
    pc_current,
    pc_changeable,
    pc_default,
    pc_saved
};

/* Don't care that we're using char bitfields. */
#pragma warning(disable:4214)

struct mode_page_header {
    unsigned char page_code:6;
    unsigned char reserved:1;
    unsigned char ps:1;
    unsigned char length;
};

struct cache_mode_page {
    unsigned char rcd:1;
    unsigned char mf:1;
    unsigned char wce:1;
    unsigned char size:1;
    unsigned char disc:1;
    unsigned char cap:1;
    unsigned char abpf:1;
    unsigned char ic:1;
    unsigned char write_retention:4;
    unsigned char read_retention:4;
    unsigned char disable_prefetch_len[2];
    unsigned char minimum_prefetch[2];
    unsigned char maximum_prefetch[2];
    unsigned char maximum_prefetch_ceil[2];
    unsigned char nv_dis:1;
    unsigned char reserved:2;
    unsigned char vendor:2;
    unsigned char dra:1;
    unsigned char lbcss:1;
    unsigned char fsw:1;
    unsigned char nr_segments;
    unsigned char segment_size[2];
    unsigned char reserved2;
    unsigned char obsolete[2];
};

static void
InitialiseModeParameterHeader(PVOID DataBuffer, BOOLEAN WriteProtect)
{
    PMODE_PARAMETER_HEADER pMph = DataBuffer;

    pMph->ModeDataLength = sizeof (MODE_PARAMETER_HEADER) - 1;
    pMph->MediumType = 0;
    pMph->DeviceSpecificParameter = (WriteProtect) ? MODE_DSP_WRITE_PROTECT : 0;
    pMph->BlockDescriptorLength = 0;
}

static void
PushData(PSCSI_REQUEST_BLOCK srb, const void *data, size_t size,
         BOOLEAN force_to_zero, PVOID DataBuffer)
{
    PMODE_PARAMETER_HEADER pMph = DataBuffer;
    void *start;
    UCHAR allocation_length;

    allocation_length = ((PCDB)srb->Cdb)->MODE_SENSE.AllocationLength;

    start = (void *)((ULONG_PTR)pMph + 1 + pMph->ModeDataLength +
                     pMph->BlockDescriptorLength);

    if (pMph->ModeDataLength + 1 <= allocation_length) {
        if (force_to_zero) {
            memset(start, 0,
                   MIN(size, (size_t)(allocation_length - pMph->ModeDataLength - 1)));
        } else {
            memcpy(start, data,
                   MIN(size, (size_t)(allocation_length - pMph->ModeDataLength - 1)));
        }
    }

    pMph->ModeDataLength = pMph->ModeDataLength + (UCHAR)size;
}

static void
InitialiseModePage(PSCSI_REQUEST_BLOCK srb, UCHAR page, PVOID DataBuffer)
{
    struct mode_page_header ph;

    memset(&ph, 0, sizeof(ph));
    ph.page_code = page;
    PushData(srb, &ph, sizeof(ph), FALSE, DataBuffer);
}

static void
AddModePayload(PSCSI_REQUEST_BLOCK srb, const void *data, size_t size,
               BOOLEAN payload_all_zeroes, PVOID DataBuffer)
{
    PMODE_PARAMETER_HEADER pMph = DataBuffer;
    struct mode_page_header *ph;
    UCHAR allocation_length;
    unsigned offset;

    allocation_length = ((PCDB)srb->Cdb)->MODE_SENSE.AllocationLength;

    offset = sizeof(PMODE_PARAMETER_HEADER) + pMph->BlockDescriptorLength;

    ph = (struct mode_page_header *)((ULONG_PTR)DataBuffer + offset);
    if (offset + sizeof(*ph) <= allocation_length)
        ph->length = ph->length + (unsigned char)size;

    PushData(srb, data, size, payload_all_zeroes, DataBuffer);
}

static void
FinishModeSense(PSCSI_REQUEST_BLOCK srb, PVOID DataBuffer)
{
    PMODE_PARAMETER_HEADER pMph = DataBuffer;
    UCHAR allocation_length;

    allocation_length = ((PCDB)srb->Cdb)->MODE_SENSE.AllocationLength;

    srb->DataTransferLength =
        MIN(allocation_length,
            (ULONG)(pMph->ModeDataLength + 1 + pMph->BlockDescriptorLength));
}

static void
GeneratePage8(PSCSI_REQUEST_BLOCK srb, enum page_control_type t,
              PVOID DataBuffer)
{
    /* Caching information */
    struct cache_mode_page cmp;
    InitialiseModePage(srb, 0x08, DataBuffer);
    memset(&cmp, 0, sizeof(cmp));
    if (t == pc_changeable)
        AddModePayload(srb, &cmp, sizeof(cmp), TRUE, DataBuffer);
    else
        AddModePayload(srb, &cmp, sizeof(cmp), FALSE, DataBuffer);
}

/* The spec. says that if you implement this then you must also
 * implement MODE_SELECT. In practise we force any changeable value
 * mask to zero and thus any MODE_SELECT would fail, so we just allow
 * them to fall through to the default handler */
void
XenvbdModeSense(PXHBD_TARGET_INFO target, PSCSI_REQUEST_BLOCK srb,
                PVOID DataBuffer)
{
    PCDB cdb = (PCDB)srb->Cdb;
    enum page_control_type pct;

    UNREFERENCED_PARAMETER(target);

    srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;

    if (srb->DataTransferLength < sizeof (struct _MODE_SENSE)) {
        TraceWarning(("target %d: invalid MODE_SENSE SRB", srb->TargetId));
        return;
    }

    /* We can ignore the DBD bit, because we don't implement any block
       descriptors. */

    pct = cdb->MODE_SENSE.Pc;
    if (pct == pc_saved)
        return;

    /* Return the current values.  We don't support changing them, so
       current == default. */
    /* Format is a mode header, followed by some block descriptors,
       followed by some pages. */
    /* A mode header contains:

       -- One byte of mode data length, not including this field but
          including the rest of the header.
       -- One byte of medium type (0 for a block device)
       -- One byte of device-specific parameters (for a block device,
          bit 4 is ``DPO or FUA support'' and bit 7 is ``write
          protect'').

       -- One byte of block descriptor length. */
    /* A block descriptor contains:

       -- Four bytes of ``number of blocks'' (on the medium), or zero
          if the descriptor applies to the remainder of the disk
       -- One byte density code
       -- Three bytes of block length.
    */
    /* A mode page contains:

       -- Six bits of page code, one reserved bit, and one bit of
          parameter-saveable bit (least to most significant).
       -- One byte of page length, not including this header.
       -- Some bytes of parameters.
    */

    InitialiseModeParameterHeader(DataBuffer, (target->info & VDISK_READONLY) ? TRUE : FALSE);

    switch (cdb->MODE_SENSE.PageCode) {
    case 0x08:
        TraceInfo(("target %d: MODE_SENSE page 0x08\n", srb->TargetId));
        GeneratePage8(srb, pct, DataBuffer);
        srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    case 0x3f: /* List of all pages, in ascending order, except for
                  page 0, which is always last. */
        TraceInfo(("target %d: MODE_SENSE page 0x3f\n", srb->TargetId));
        GeneratePage8(srb, pct, DataBuffer);
        srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;
    default:
        TraceWarning(("target %d: unknown mode sense page 0x%02x\n",
                      srb->TargetId,
                      cdb->MODE_SENSE.PageCode));
    case 0x1c: /* Informational Exceptions Control Page. Believed safe
                * to just ignore this one */
    case 0: /* Vendor-specific information.  We don't have any, but
               Windows 2000 queries it anyway when you resize a disk.
               Ignore it, and suppress the warning. */
        break;
    }

    if (srb->SrbStatus == SRB_STATUS_SUCCESS)
        FinishModeSense(srb, DataBuffer);

    return;
}
