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

/* This file deals with requests which we've decided to send through
   the bypass.  If we get here then we'll either fail the request or
   bypass scsiport. */
#include "ntddk.h"
#pragma warning (push, 3)
#include "srb.h"
#include "scsi.h"
#pragma warning (pop)
#include "xsapi.h"
#include "scsiboot.h"
#include "scsifilt.h"

#include "scsifilt_wpp.h"
#include "datapath.tmh"

/* --------------- Bits for making requests of xenvbd ------------------ */
static struct scsifilt_irp_overlay *
get_irp_overlay(PIRP irp)
{
    return (struct scsifilt_irp_overlay *)irp->Tail.Overlay.DriverContext;
}

static struct scsifilt_request_internal *
allocate_request(struct scsifilt *sf)
{
    struct scsifilt_request_internal *sfri;
    LONG new_outstanding;

    sfri = ExAllocateFromNPagedLookasideList(&sf->sfri_lookaside_list);
    if (sfri != NULL) {
        memset(sfri, 0, sizeof(*sfri));
        sfri->scsifilt_request.state = SfrStateFresh;
        new_outstanding = InterlockedIncrement(&sf->cur_outstanding);
        if (new_outstanding > sf->max_outstanding)
            sf->max_outstanding = new_outstanding;
    }
    return sfri;
}

static void
release_request(struct scsifilt *sf, struct scsifilt_request_internal *sfri)
{
    if (sfri->bounce_buffer != NULL)
        XmFreeMemory(sfri->bounce_buffer);
    ExFreeToNPagedLookasideList(&sf->sfri_lookaside_list, sfri);
    InterlockedDecrement(&sf->cur_outstanding);
}

static void
release_requests(struct scsifilt *sf, PLIST_ENTRY requests)
{
    PLIST_ENTRY le, next_le;
    struct scsifilt_request_internal *sfri;

    for (le = requests->Flink; le != requests; le = next_le) {
        next_le = le->Flink;
        sfri = CONTAINING_RECORD(le, struct scsifilt_request_internal,
                                 scsifilt_request.list);
        release_request(sf, sfri);
    }
}

static NTSTATUS
allocate_requests(struct scsifilt *sf, unsigned nr_needed, PLIST_ENTRY list)
{
    struct scsifilt_request_internal *sfri;
    unsigned nr_allocated;

    InitializeListHead(list);
    for (nr_allocated = 0; nr_allocated < nr_needed; nr_allocated++) {
        sfri = allocate_request(sf);
        if (sfri == NULL) {
            release_requests(sf, list);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        InsertTailList(list, &sfri->scsifilt_request.list);
    }
    return STATUS_SUCCESS;
}

static MM_PAGE_PRIORITY
page_priority_for_irp(PIRP irp)
{
    if (irp->Flags & IRP_PAGING_IO)
        return HighPagePriority;
    else
        return NormalPagePriority;
}

static ULONG
get_big_endian_dword(const UCHAR src[4])
{
    return src[3] | ((ULONG)src[2] << 8) | ((ULONG)src[1] << 16) |
            ((ULONG)src[0] << 24);
}

static ULONG64
get_big_endian_qword(const UCHAR src[8])
{
    return src[7] | ((ULONG64)src[6] << 8) | ((ULONG64)src[5] << 16) |
        ((ULONG64)src[4] << 24) | ((ULONG64)src[3] << 32) |
        ((ULONG64)src[2] << 40) | ((ULONG64)src[1] << 48) |
        ((ULONG64)src[0] << 56);
}

/* Map from a virtual address to a page frame number, using the
   mapping given in @mdl. */
static PFN_NUMBER
mdl_va_to_pfn(PMDL mdl, ULONG_PTR va)
{
    unsigned offset;

    offset = (unsigned)(va - (ULONG_PTR)mdl->StartVa);
    return MmGetMdlPfnArray(mdl)[offset / PAGE_SIZE];
}

/* Look at an SRB and figure out how many sectors it's going to
 * transfer. */
static unsigned
get_nr_sectors_from_srb(PSCSI_REQUEST_BLOCK srb)
{
    CDB *const cdb = (CDB *)srb->Cdb;

    switch (srb->CdbLength) {
    case 6:
        return cdb->CDB6READWRITE.TransferBlocks;
    case 10:
        return cdb->CDB10.TransferBlocksLsb |
            ((ULONG)cdb->CDB10.TransferBlocksMsb << 8);
    case 12:
        return get_big_endian_dword(cdb->CDB12.TransferLength);
    case 16:
        return get_big_endian_dword(cdb->CDB16.TransferLength);
    default:
        TraceBugCheck(("Bad CDB length %d.\n", srb->CdbLength));
        return 0;
    }
}

void *
map_srb_data_buffer(PSCSI_REQUEST_BLOCK srb, PMDL mdl,
                    MM_PAGE_PRIORITY prio)
{
    ULONG_PTR DataOffset;

    if (MmGetSystemAddressForMdlSafe(mdl, prio) == NULL)
        return NULL;

    // StartVa and srb->DataBuffer should be in the same address space, so we can use these to calculate any offset
    DataOffset = (ULONG_PTR)srb->DataBuffer - ((ULONG_PTR)mdl->StartVa + mdl->ByteOffset);

    return (PVOID)((ULONG_PTR)mdl->MappedSystemVa + DataOffset);
}

/* Initialise @sfri to transfer @nr_sectors sectors at offset
   @sector_offset of the request described by @irp, @srb, and @mdl,
   assuming that everything is not properly aligned.  This always
   allocates a bounce buffer.  It can fail if no memory is available
   for the bounce buffer. */
/* This is responsible for setting srb->SrbStatus if an error
 * happens. */
static NTSTATUS
initialise_sfri_bounce(struct scsifilt_request_internal *sfri,
                       unsigned sector_offset,
                       unsigned nr_sectors,
                       unsigned sector_size,
                       PIRP irp,
                       PSCSI_REQUEST_BLOCK srb,
                       PMDL mdl)
{
    /* Request is unaligned in memory -> need to use a bounce
     * buffer. */
    const MM_PAGE_PRIORITY prio = page_priority_for_irp(irp);
    const unsigned sectors_per_page = PAGE_SIZE / sector_size;
    struct scsifilt_request *const sfr = &sfri->scsifilt_request;
    unsigned buffer_size;
    unsigned segment_idx;
    unsigned sectors_done;
    unsigned sectors_this_segment;

    /* Map the source.  We could defer this to the finish callback for
       READ operations, but it's easier to do it here. */
    sfri->mdl_va = map_srb_data_buffer(srb, mdl, prio);
    if (sfri->mdl_va == NULL) {
        srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* We might want this request to be at an offset in the IRP. */
    sfri->mdl_va = (PVOID)((ULONG_PTR)sfri->mdl_va +
                           sector_offset * sector_size);

    /* Allocate the buffer */
    buffer_size = sfri->byte_count;
    if (buffer_size < PAGE_SIZE) {
        /* Always use at least PAGE_SIZE so that we get page
         * alignment.  This is rare enough that we don't care about
         * the slightly higher overhead. */
        buffer_size = PAGE_SIZE;
    }
    sfri->bounce_buffer = XmAllocateMemory(buffer_size);
    if (sfri->bounce_buffer == NULL) {
        srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (sfr->operation == BLKIF_OP_WRITE) {
        /* Copy the data to be written into the bounce buffer. */
        memcpy(sfri->bounce_buffer, sfri->mdl_va, sfri->byte_count);
    }

    /* Build the request */
    segment_idx = 0;
    sectors_done = 0;
    while (sectors_done < nr_sectors) {
        PHYSICAL_ADDRESS pa;

        sectors_this_segment =
            MIN(nr_sectors - sectors_done, sectors_per_page);
        XM_ASSERT3U(segment_idx, <, BLKIF_MAX_SEGMENTS_PER_REQUEST);
        sfr->fragments[segment_idx].start_sect = 0;
        sfr->fragments[segment_idx].last_sect =
            (uint8_t)sectors_this_segment - 1;
        pa = MmGetPhysicalAddress((PVOID)((ULONG_PTR)sfri->bounce_buffer +
                                          sectors_done * sector_size));
        sfr->fragments[segment_idx].pfn =
            (PFN_NUMBER)(pa.QuadPart / PAGE_SIZE);

        sectors_done += sectors_this_segment;
        segment_idx++;
    }
    sfr->nr_segments = (uint8_t)segment_idx;

    return STATUS_SUCCESS;
}

/* Initialise @sfri to transfer @nr_sectors sectors at offset
   @sector_offset of the request described by @srb and @mdl, assuming
   that everything is properly aligned.  This always succeeds, but
   returns an NTSTATUS for symmetry with initialise_sfri_bounce(). */
static NTSTATUS
initialise_sfri_nonbounce(struct scsifilt_request_internal *sfri,
                          unsigned sector_offset,
                          unsigned nr_sectors,
                          unsigned sector_size,
                          PSCSI_REQUEST_BLOCK srb,
                          PMDL mdl)
{
    const unsigned sectors_per_page = PAGE_SIZE / sector_size;
    struct scsifilt_request *const sfr = &sfri->scsifilt_request;
    unsigned segment_idx;
    unsigned sectors_this_segment;
    unsigned byte_page_off;
    unsigned sector_page_off;
    unsigned sectors_done;
    ULONG_PTR src_va;

    segment_idx = 0;
    sectors_done = 0;
    src_va = (ULONG_PTR)srb->DataBuffer;
    byte_page_off = (unsigned)((src_va + (sector_offset * sector_size))%
                               PAGE_SIZE);
    sector_page_off = byte_page_off / sector_size;
    while (sectors_done < nr_sectors) {
        sectors_this_segment = MIN(nr_sectors - sectors_done,
                                   sectors_per_page - sector_page_off);

        XM_ASSERT3U(segment_idx, <, BLKIF_MAX_SEGMENTS_PER_REQUEST);
        sfr->fragments[segment_idx].pfn =
            mdl_va_to_pfn(mdl,
                          src_va +
                              (sector_offset + sectors_done) * sector_size);
        sfr->fragments[segment_idx].start_sect = (uint8_t)sector_page_off;
        sfr->fragments[segment_idx].last_sect =
            (uint8_t)(sectors_this_segment + sector_page_off - 1);

        sectors_done += sectors_this_segment;
        segment_idx++;
        sector_page_off = 0;
        byte_page_off = 0;
    }
    sfr->nr_segments = (uint8_t)segment_idx;

    return STATUS_SUCCESS;
}

/* Initialise the requests in the list @requests on the assumption
   that they're going to be used to transfer the request described by
   @irp, @srb, and @sio.  @requests must contain exactly the right
   number of requests. */
/* This is responsible for setting srb->SrbStatus if an error
 * happens. */
static NTSTATUS
initialise_requests(struct scsifilt *sf, PLIST_ENTRY requests, PIRP irp,
                    PSCSI_REQUEST_BLOCK srb, unsigned sector_size,
                    struct scsifilt_irp_overlay *sio)
{
    const unsigned sectors_per_page = PAGE_SIZE / sector_size;
    MDL *const mdl = irp->MdlAddress;
    CDB *const cdb = (CDB *)srb->Cdb;
    unsigned nr_sectors;
    uint8_t operation = 0;
    uint64_t start_sector = 0;
    unsigned sectors_done;
    BOOLEAN use_bounce;
    unsigned sector_off_in_page;
    unsigned sectors_this_time;
    struct scsifilt_request_internal *sfri;
    struct scsifilt_request *sfr;
    PLIST_ENTRY le;
    NTSTATUS status;

    XM_ASSERT3P(mdl->Next, ==, NULL);

    sio->nr_outstanding = 0;

    /* Parse up the CDB to find out whether this is a read or a write,
       and which sector we want to start at. */
    if (srb->CdbLength == 6) {
        if (cdb->CDB6GENERIC.OperationCode == SCSIOP_READ6)
            operation = BLKIF_OP_READ;
        else
            operation = BLKIF_OP_WRITE;
        start_sector =
            cdb->CDB6READWRITE.LogicalBlockLsb |
            ((ULONG)cdb->CDB6READWRITE.LogicalBlockMsb0 << 8) |
            ((ULONG)cdb->CDB6READWRITE.LogicalBlockMsb1 << 16);
    } else if (srb->CdbLength == 10) {
        if (cdb->CDB10.OperationCode == SCSIOP_READ)
            operation = BLKIF_OP_READ;
        else
            operation = BLKIF_OP_WRITE;
        start_sector =
            cdb->CDB10.LogicalBlockByte3 |
            ((ULONG)cdb->CDB10.LogicalBlockByte2 << 8) |
            ((ULONG)cdb->CDB10.LogicalBlockByte1 << 16) |
            ((ULONG)cdb->CDB10.LogicalBlockByte0 << 24);
    } else if (srb->CdbLength == 12) {
        if (cdb->CDB12.OperationCode == SCSIOP_READ12)
            operation = BLKIF_OP_READ;
        else
            operation = BLKIF_OP_WRITE;
        start_sector = get_big_endian_dword(cdb->CDB12.LogicalBlock);
    } else if (srb->CdbLength == 16) {
        if (cdb->CDB16.OperationCode == SCSIOP_READ16)
            operation = BLKIF_OP_READ;
        else
            operation = BLKIF_OP_WRITE;
        start_sector = get_big_endian_qword(cdb->CDB16.LogicalBlock);
    } else {
        TraceBugCheck(("Bad CDB length %d.\n", srb->CdbLength));
    }

    nr_sectors = get_nr_sectors_from_srb(srb);
    sectors_done = 0;

    /* Use a bounce buffer if the data buffer isn't sector-aligned in
       memory. */
    if ( (ULONG_PTR)srb->DataBuffer & (sector_size - 1) ) {
        use_bounce = TRUE;
    } else {
        use_bounce = FALSE;
    }

    DoTraceMessage(FLAG_UPPER_EDGE,
                   "%s operation %d start %I64d nr_sectors %d irp %p bounce %d",
                   sf->frontend_path, operation, start_sector, nr_sectors,
                   irp, use_bounce);

    if (use_bounce) {
        /* If we're bouncing, the buffer to pass to the backend is
           always page-aligned. */
        sector_off_in_page = 0;
    } else {
        sector_off_in_page =
            (unsigned)((ULONG_PTR)srb->DataBuffer % PAGE_SIZE) / sector_size;
    }

    le = requests->Flink;
    while (sectors_done < nr_sectors) {
        /* How many sectors are we doing this time? */
        sectors_this_time =
            MIN(nr_sectors - sectors_done,
                BLKIF_MAX_SEGMENTS_PER_REQUEST * sectors_per_page -
                    sector_off_in_page);

        /* We'd better not have run out of requests. */
        XM_ASSERT(le != requests);

        sfri = CONTAINING_RECORD(le, struct scsifilt_request_internal,
                                 scsifilt_request.list);
        sfr = &sfri->scsifilt_request;
        XM_ASSERT3U(sfr->state, ==, SfrStateFresh);
        sfr->result = BLKIF_RSP_OKAY;
        sfr->operation = operation;
        sfr->start_sector = start_sector + sectors_done;
        sfri->irp = irp;
        sfri->byte_count = sector_size * sectors_this_time;

        if (use_bounce)
            status = initialise_sfri_bounce(sfri,
                                            sectors_done,
                                            sectors_this_time,
                                            sector_size,
                                            irp,
                                            srb,
                                            mdl);
        else
            status = initialise_sfri_nonbounce(sfri,
                                               sectors_done,
                                               sectors_this_time,
                                               sector_size,
                                               srb,
                                               mdl);

        if (!NT_SUCCESS(status)) {
            /* The caller will call release_requests(), which will
               undo all of the work we've done. */
            return status;
        }

        sfr->state = SfrStateInitialised;

        sectors_done += sectors_this_time;
        sector_off_in_page = 0;
        le = le->Flink;
        sio->nr_outstanding++;
    }

    return STATUS_SUCCESS;
}

/* Figure out how many scsifilt_request structures we're going to need
   in order to represent @srb. */
static unsigned
count_requests_for_srb(struct scsifilt *sf, PSCSI_REQUEST_BLOCK srb)
{
    unsigned byte_count;
    unsigned nr_pages;
    unsigned nr_sectors;

    nr_sectors = get_nr_sectors_from_srb(srb);
    byte_count = sf->sector_size * nr_sectors;

    if ( (ULONG_PTR)srb->DataBuffer & (sf->sector_size - 1) ) {
        /* This request needs to be bounced -> we can assume that the
           request will be page-aligned. */
        nr_pages = BYTES_TO_PAGES_ROUND_UP(byte_count);
    } else {
        /* We're not bouncing, so we'll use whatever sub-page
           alignment Windows gives us. */
        nr_pages =
            (unsigned)BYTES_TO_PAGES_ROUND_UP(byte_count +
                                    ((ULONG_PTR)srb->DataBuffer % PAGE_SIZE));
    }

    /* How many blkif requests are we going to need for nr_pages
       segments?  (Each page needs its own segment, and, because this
       interface isn't true scatter-gather, it never needs more than
       one.) */
    return (nr_pages + BLKIF_MAX_SEGMENTS_PER_REQUEST - 1) / BLKIF_MAX_SEGMENTS_PER_REQUEST;
}

/* We've decided that this IRP is going to be sent down the fast path.
   Do whatever is necessary to achieve this.  This function will
   always complete the IRP (eventually).  Called at IRQL <=
   DISPATCH_LEVEL holding no locks. */
NTSTATUS
filter_process_irp(struct scsifilt *sf, PIRP irp, PSCSI_REQUEST_BLOCK srb)
{
    struct scsifilt_irp_overlay *const sio = get_irp_overlay(irp);
    NTSTATUS status;
    LIST_ENTRY requests;
    unsigned nr_requests;

    memset(sio, 0, sizeof(*sio));
    sio->obtained_from_windows = ReadTimeStampCounter();

    status = IoAcquireRemoveLock(&sf->remove_lock, srb);
    if (!NT_SUCCESS(status)) {
        srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
        return complete_irp(irp, status);
    }

    nr_requests = count_requests_for_srb(sf, srb);

    status = allocate_requests(sf, nr_requests, &requests);
    if (!NT_SUCCESS(status)) {
        TraceWarning(("Failed to allocate a scsifilt request (%x)!\n",
                      status));
        IoReleaseRemoveLock(&sf->remove_lock, srb);
        srb->SrbStatus = SRB_STATUS_INTERNAL_ERROR;
        return complete_irp(irp, status);
    }
    status = initialise_requests(sf, &requests, irp, srb, sf->sector_size,
                                 sio);
    if (!NT_SUCCESS(status)) {
        TraceWarning(("Failed to initialise sfri!\n"));
        release_requests(sf, &requests);
        IoReleaseRemoveLock(&sf->remove_lock, srb);
        return complete_irp(irp, status);
    }
    XM_ASSERT3U(sio->nr_outstanding, ==, nr_requests);
    IoMarkIrpPending(irp);

    /* We'll set an error status later if necessary. */
    irp->IoStatus.Status = STATUS_PENDING;
    irp->IoStatus.Information = 0;

    srb->SrbStatus = SRB_STATUS_SUCCESS;
    srb->ScsiStatus = 0;

    schedule_requests(sf, &requests);
    return STATUS_PENDING;
}

/* ------------- Bits for dealing with responses from xenvbd ------------ */

/* A request just finished.  Update our running time counters to
   reflect how long the various phases of processing took. */
static void update_time_stats(struct scsifilt *sf,
                              struct scsifilt_request *sfr,
                              ULONG64 arrive)
{
    ULONG64 now;
    ULONG64 arrive2submit;
    ULONG64 submit2return;
    ULONG64 return2complete;

    now = ReadTimeStampCounter();
    arrive2submit = sfr->submitted_to_backend - arrive;
    submit2return = sfr->returned_by_backend - sfr->submitted_to_backend;
    return2complete = now - sfr->returned_by_backend;

    sf->nr_requests++;
    sf->arrive2submit += arrive2submit;
    sf->submit2return += submit2return;
    sf->return2complete += return2complete;
}

/* Complete a specific request.  Called from the completion DPC not
   holding any locks. */
static void
complete_this_request(struct scsifilt *sf, struct scsifilt_request *sfr)
{
    struct scsifilt_request_internal *const sfri =
        CONTAINING_RECORD(sfr, struct scsifilt_request_internal,
                          scsifilt_request);
    IRP *const irp = sfri->irp;
    IO_STACK_LOCATION *const isl = IoGetCurrentIrpStackLocation(irp);
    SCSI_REQUEST_BLOCK *const srb = isl->Parameters.Scsi.Srb;
    struct scsifilt_irp_overlay *const sio = get_irp_overlay(irp);

    update_time_stats(sf, sfr, sio->obtained_from_windows);

    XM_ASSERT3U(sfr->state, ==, SfrStateProcessed);
    sfr->state = SfrStateComplete;

    if (sfri->bounce_buffer != NULL)
        sf->nr_bounces++;

    /* We only process the SFR result if the IRP hasn't failed yet. */
    if (srb->SrbStatus == SRB_STATUS_SUCCESS) {
        if (sfr->result == BLKIF_RSP_OKAY) {
            irp->IoStatus.Information += sfri->byte_count;

            /* If it's a read request and we used a bounce buffer then
               we need to copy the results back out of the bounce
               buffer and into the real buffer. */
            if ( sfri->bounce_buffer != NULL &&
                 sfr->operation == BLKIF_OP_READ ) {
                memcpy(sfri->mdl_va, sfri->bounce_buffer, sfri->byte_count);
            }
        } else {
            srb->SrbStatus = SRB_STATUS_ERROR;
            srb->ScsiStatus = 0x40;
        }
    }

    release_request(sf, sfri);

    XM_ASSERT(irp->IoStatus.Status == STATUS_PENDING);
    if (sio->nr_outstanding == 1) {
        sf->nr_irps++;
        sf->arrive2complete +=
            ReadTimeStampCounter() - sio->obtained_from_windows;

        IoReleaseRemoveLock(&sf->remove_lock, srb);

        if (srb->SrbStatus == SRB_STATUS_SUCCESS)
            irp->IoStatus.Status = STATUS_SUCCESS;
        else
            irp->IoStatus.Status = STATUS_UNSUCCESSFUL;

        // Poison the driver context
        irp->Tail.Overlay.DriverContext[0] = (PVOID)(ULONG_PTR)0xfeedface;
        irp->Tail.Overlay.DriverContext[1] = (PVOID)(ULONG_PTR)0xfeedface;
        irp->Tail.Overlay.DriverContext[2] = (PVOID)(ULONG_PTR)0xfeedface;
        irp->Tail.Overlay.DriverContext[3] = (PVOID)(ULONG_PTR)0xfeedface;

        IoCompleteRequest(irp, IO_NO_INCREMENT);

        DoTraceMessage(FLAG_UPPER_EDGE, "%s complete irp %p",
                       sf->frontend_path, irp);
    } else {
        sio->nr_outstanding--;
    }
}

/* Called directly from the xenvbd DPC holding no locks. */
void
finish_requests(struct scsifilt *sf, PLIST_ENTRY requests)
{
    PLIST_ENTRY ple;
    PLIST_ENTRY next_ple;
    struct scsifilt_request *sfr;

    for (ple = requests->Flink;
         ple != requests;
         ple = next_ple) {
        next_ple = ple->Flink;
        sfr = CONTAINING_RECORD(ple, struct scsifilt_request, list);
        complete_this_request(sf, sfr);
    }
}

