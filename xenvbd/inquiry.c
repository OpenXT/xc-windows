/*
 * Copyright (c) 2010 Citrix Systems, Inc.
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

/* SCSI inquiry support */
#pragma warning (push, 3)
#include "xenvbd.h"
#include "scsiboot.h"
#include "xsapi.h"
#pragma warning (pop)

struct scsi_vpd_page {
    struct scsi_vpd_page *next;
    unsigned id;
    void *data;
    size_t data_len;
};

struct scsi_inquiry_data {
    size_t default_page_size;
    void *default_page;
    struct scsi_vpd_page *vpd_pages;
};

/* Insert the VPD page into the inquiry data structure, keeping the
   list in order. */
static void
InsertVpdp(struct scsi_inquiry_data *d, struct scsi_vpd_page *page)
{
    struct scsi_vpd_page **next;

    /* Find the pointer which needs to point at @page when we exit
       i.e. the first pointer which currently points at something with
       an id greated than @page's, or the last pointer in the list. */
    next = &d->vpd_pages;
    while (*next && (*next)->id < page->id)
        next = &(*next)->next;

    /* No duplicates */
    XM_ASSERT(*next == NULL || (*next)->id != page->id);

    /* Swizzle the new page in */
    page->next = *next;
    *next = page;
}

/* Find a VPD page in the list. */
static struct scsi_vpd_page *
FindVpdp(struct scsi_inquiry_data *d, unsigned id)
{
    struct scsi_vpd_page *vpdp;

    for (vpdp = d->vpd_pages;
         vpdp && vpdp->id != id;
         vpdp = vpdp->next)
        ;

    return vpdp;
}

/* Compute SCSI inquiry page 0.  The page consists of three zero
   bytes, followed by a count of available pages, followed by the page
   identifiers in ascending order, starting with page 0 itself. */
static struct scsi_vpd_page *
ComputePage0(struct scsi_inquiry_data *sid)
{
    struct scsi_vpd_page *vpdp;
    unsigned nr_pages;
    struct scsi_vpd_page *work;
    unsigned char *buf;
    unsigned x;

    vpdp = sid->vpd_pages;
    nr_pages = 1; /* Include the 0 page */
    while (vpdp) {
        nr_pages++;
        vpdp = vpdp->next;
    }
    XM_ASSERT(nr_pages < 256);

    work = XmAllocateZeroedMemory(sizeof(*work));
    buf = XmAllocateMemory(nr_pages + 4);
    if (!buf || !work) {
        XmFreeMemory(buf);
        XmFreeMemory(work);
        return NULL;
    }

    buf[0] = buf[1] = buf[2] = buf[4] = 0;
    x = 1;
    vpdp = sid->vpd_pages;
    while (vpdp) {
        buf[x+4] = (unsigned char)vpdp->id;
        x++;
        vpdp = vpdp->next;
    }
    XM_ASSERT(x == nr_pages);
    buf[3] = (unsigned char)nr_pages;

    work->data = buf;
    work->data_len = nr_pages + 4;
    work->id = 0;

    return work;
}

/* An empty VPD page consists of a zero byte, the identifier, and two
   more zero bytes. */
static struct scsi_vpd_page *
EmptyVpdpPage(unsigned id)
{
    struct scsi_vpd_page *work;
    unsigned char *buf;

    work = XmAllocateZeroedMemory(sizeof(*work));
    buf = XmAllocateZeroedMemory(4);
    if (!work || !buf) {
        XmFreeMemory(work);
        XmFreeMemory(buf);
        return NULL;
    } else {
        work->id = id;
        work->data = buf;
        work->data_len = 4;
        buf[1] = (unsigned char)id;
        return work;
    }
}

/* Create a Unit Serial Number VPD page (Page 0x80) and simply hard code
   the serial number to a space (i.e. ' '). 
   Note this is needed in order to pass the HCTs. */
static struct scsi_vpd_page *
UnitSerialNumberVpdpPage()
{
    struct scsi_vpd_page *work;
    PVPD_SERIAL_NUMBER_PAGE vpd;
    ULONG vpdSize = sizeof(VPD_SERIAL_NUMBER_PAGE) + 1;

    work = XmAllocateZeroedMemory(sizeof(*work));
    vpd = XmAllocateZeroedMemory(vpdSize);
    if (!work || !vpd) {
        XmFreeMemory(work);
        XmFreeMemory(vpd);
        return NULL;
    } else {
        work->id = VPD_SERIAL_NUMBER;
        work->data = vpd;
        work->data_len = vpdSize;
        vpd->PageCode = (unsigned char)VPD_SERIAL_NUMBER;
        vpd->PageLength = 1;
        vpd->SerialNumber[0] = ' ';
        return work;
    }
}

static void
DumpSerialNumberVpdpPage(XHBD_TARGET_INFO *Target, struct scsi_vpd_page *work)
{
    PVPD_SERIAL_NUMBER_PAGE vpd = work->data;
    size_t vpdSize = work->data_len;
    char *buffer;

    XM_ASSERT(vpd->PageCode == (unsigned char)VPD_SERIAL_NUMBER);
    XM_ASSERT(sizeof (VPD_SERIAL_NUMBER_PAGE) + vpd->PageLength == vpdSize);

    buffer = XmAllocateMemory(vpd->PageLength + 1);
    XM_ASSERT(buffer != NULL);

    memcpy(buffer, vpd->SerialNumber, vpd->PageLength);
    buffer[vpd->PageLength] = '\0';

    TraceNotice(("target %d: unit serial number = '%s'\n", Target->targetId, buffer));
    XmFreeMemory(buffer);
}

static const char *
CodeSetName(VPD_CODE_SET CodeSet)
{
#define _CODE_SET_NAME(_CodeSet)    \
    case VpdCodeSet ## _CodeSet:    \
        return #_CodeSet;

    switch (CodeSet) {
    _CODE_SET_NAME(Reserved);
    _CODE_SET_NAME(Binary);
    _CODE_SET_NAME(Ascii);
    _CODE_SET_NAME(UTF8);
    default:
        return "UNKNOWN";
    }

#undef  _CODE_SET_NAME
}

static const char *
IdentifierTypeName(VPD_IDENTIFIER_TYPE Type)
{
#define _IDENTIFIER_TYPE_NAME(_Type)    \
    case VpdIdentifierType ## _Type:    \
        return #_Type;

    switch (Type) {
    _IDENTIFIER_TYPE_NAME(VendorSpecific);
    _IDENTIFIER_TYPE_NAME(VendorId);
    _IDENTIFIER_TYPE_NAME(EUI64);
    _IDENTIFIER_TYPE_NAME(FCPHName);
    _IDENTIFIER_TYPE_NAME(PortRelative);
    _IDENTIFIER_TYPE_NAME(TargetPortGroup);
    _IDENTIFIER_TYPE_NAME(LogicalUnitGroup);
    _IDENTIFIER_TYPE_NAME(MD5LogicalUnitId);
    _IDENTIFIER_TYPE_NAME(SCSINameString);
    default:
        return "UNKNOWN";
    }

#undef  _IDENTIFIER_TYPE_NAME
}

static const char *
AssociationName(VPD_ASSOCIATION Association)
{
#define _ASSOCIATION_NAME(_Association) \
    case VpdAssoc ## _Association:      \
        return #_Association;

    switch (Association) {
    _ASSOCIATION_NAME(Device);
    _ASSOCIATION_NAME(Port);
    _ASSOCIATION_NAME(Target);
    _ASSOCIATION_NAME(Reserved1);
    default:
        return "UNKNOWN";
    }

#undef  _ASSOCIATION_NAME
}

static void
DumpIdenticationDescriptor(XHBD_TARGET_INFO *Target, ULONG Index, PVPD_IDENTIFICATION_DESCRIPTOR Descriptor)
{
    char *buffer;

    TraceNotice(("target %d: device identifier[%d]: CodeSet: '%s' Type: '%s' Assocation: '%s'\n",
                 Target->targetId,
                 Index,
                 CodeSetName(Descriptor->CodeSet),
                 IdentifierTypeName(Descriptor->IdentifierType),
                 AssociationName(Descriptor->Association)));

    switch (Descriptor->CodeSet) {
    case VpdCodeSetBinary: {
        ULONG Count;

        buffer = XmAllocateMemory((Descriptor->IdentifierLength * 2) + 1);
        XM_ASSERT(buffer != NULL);
        for (Count = 0; Count < Descriptor->IdentifierLength; Count++)
            Xmsnprintf(&buffer[Count * 2], 2, "%02x", Descriptor->Identifier[Count]);
        buffer[Descriptor->IdentifierLength] = '\0';
        break;
    }
    case VpdCodeSetAscii:
        buffer = XmAllocateMemory(Descriptor->IdentifierLength + 1);
        XM_ASSERT(buffer != NULL);

        memcpy(buffer, Descriptor->Identifier, Descriptor->IdentifierLength);
        buffer[Descriptor->IdentifierLength] = '\0';
        break;

    default:
        buffer = NULL;
    }

    if (buffer != NULL) {
        TraceNotice(("target %d: device identifier[%d]: Length = %d Data = '%s'\n",
                   Target->targetId,
                   Index,
                   Descriptor->IdentifierLength,
                   buffer));
        XmFreeMemory(buffer);
    }
}

static void
DumpDeviceIdentificationVpdpPage(XHBD_TARGET_INFO *Target, struct scsi_vpd_page *work)
{
    PVPD_IDENTIFICATION_PAGE vpd = work->data;
    size_t vpdSize = work->data_len;
    UCHAR *ptr;
    ULONG Index;

    XM_ASSERT(vpd->PageCode == (unsigned char)VPD_DEVICE_IDENTIFIERS);
    XM_ASSERT(sizeof (VPD_IDENTIFICATION_PAGE) + vpd->PageLength == vpdSize);

    ptr = vpd->Descriptors;
    Index = 0;
    while(ptr < (UCHAR *)work->data + work->data_len) {
        PVPD_IDENTIFICATION_DESCRIPTOR Descriptor = (PVPD_IDENTIFICATION_DESCRIPTOR)ptr;
        ULONG descriptorSize = Descriptor->IdentifierLength + sizeof (VPD_IDENTIFICATION_DESCRIPTOR);

        DumpIdenticationDescriptor(Target, Index, Descriptor);
        ptr += descriptorSize;
        Index++;
    }
    XM_ASSERT(ptr == (UCHAR *)work->data + work->data_len);
}

static NTSTATUS
base64_decode_in_place(void *buf, size_t in_buf_size,
                       size_t *out_buf_size)
{
    const unsigned char *src;
    uint8_t *dest;
    unsigned char src_block[4];
    uint8_t *dest_block;
    size_t src_off, dest_off;
    int src_block_avail;
    unsigned pad;

    src = buf;
    dest = buf;
    src_off = 0;
    dest_off = 0;
    src_block_avail = 0;
    pad = 0;
    while (src_off < in_buf_size) {
        if (src[src_off] == '=') {
            pad++;
            if (pad > 2)
                goto invalid_base64;
            src_block[src_block_avail++] = 0;
        } else if (src[src_off] >= 'A' &&
                   src[src_off] <= 'Z') {
            if (pad) goto invalid_base64;
            src_block[src_block_avail++] = src[src_off] - 'A';
        } else if (src[src_off] >= 'a' &&
                   src[src_off] <= 'z') {
            if (pad) goto invalid_base64;
            src_block[src_block_avail++] = src[src_off] - 'a' + 26;
        } else if (src[src_off] >= '0' &&
                   src[src_off] <= '9') {
            if (pad) goto invalid_base64;
            src_block[src_block_avail++] = src[src_off] - '0' + 52;
        } else if (src[src_off] == '+') {
            if (pad) goto invalid_base64;
            src_block[src_block_avail++] = 62;
        } else if (src[src_off] == '/') {
            if (pad) goto invalid_base64;
            src_block[src_block_avail++] = 63;
        } else {
            /* Ignore unknown characters */
        }
        if (src_block_avail == 4) {
            /* We have a full block of 4 input characters available.
               Build the output block. */
            dest_block = dest + dest_off;
            dest_block[2] = src_block[3] | (src_block[2] << 6);
            dest_block[1] = (src_block[2] >> 2) | (src_block[1] << 4);
            dest_block[0] = (src_block[1] >> 4) | (src_block[0] << 2);
            dest_off += 3;
            src_block_avail = 0;
        }
        src_off++;
    }

    if (src_block_avail != 0 || pad > dest_off)
        goto invalid_base64;

    *out_buf_size = dest_off - pad;
    return STATUS_SUCCESS;

invalid_base64:
    return STATUS_INVALID_PARAMETER;
}

/* Read a key from the store and decode as RFC 2045 base64 */
static NTSTATUS
xenbus_read_base64(char *prefix, char *node_name,
                   void **data, size_t *data_size)
{
    NTSTATUS stat;
    void *buf1;
    size_t size1;

    stat = xenbus_read_bin(XBT_NIL, prefix, node_name,
                           &buf1, &size1);
    if (!NT_SUCCESS(stat))
        return stat;
    stat = base64_decode_in_place(buf1, size1, data_size);
    if (NT_SUCCESS(stat)) {
        *data = buf1;
    } else {
        XmFreeMemory(buf1);
        *data_size = 0;
    }
    return stat;
}

void
ReleaseScsiInquiryData(
    IN  XHBD_TARGET_INFO    *Target
    )
{
    struct scsi_inquiry_data *d = Target->inq_data;

    if (d == NULL)
        return;

    Target->inq_data = NULL;

    XmFreeMemory(d->default_page);
    while (d->vpd_pages) {
        struct scsi_vpd_page *vpdp;
        vpdp = d->vpd_pages;
        d->vpd_pages = vpdp->next;
        XmFreeMemory(vpdp->data);
        XmFreeMemory(vpdp);
    }
    XmFreeMemory(d);
}

NTSTATUS
ReadScsiInquiryData(
    IN  XHBD_TARGET_INFO    *Target,
    IN  PCHAR               BackendPath
    )
{
    char *bpath = NULL;
    NTSTATUS stat;
    char **entries = NULL;
    struct scsi_inquiry_data *work = NULL;
    int x;
    struct scsi_vpd_page *page0, *page80, *page83;

    work = XmAllocateZeroedMemory(sizeof(*work));

    stat = STATUS_NO_MEMORY;
    if (work == NULL)
        goto fail1;

    bpath = Xmasprintf("%s/sm-data/scsi/0x12", BackendPath);

    stat = STATUS_NO_MEMORY;
    if (bpath == NULL)
        goto fail2;

    stat = xenbus_ls(XBT_NIL, bpath, &entries);
    if (!NT_SUCCESS(stat)) {
        TraceWarning(("target %d: no inquiry data in xenstore\n", Target->targetId));
        goto out;
    }

    for (x = 0; entries[x]; x++) {
        if (!strcmp(entries[x], "default")) {
            XM_ASSERT(work->default_page == NULL);

            stat = xenbus_read_base64(bpath, entries[x],
                                      &work->default_page,
                                      &work->default_page_size);
            if (!NT_SUCCESS(stat))
                TraceError(("target %d: failed to read inquiry data: default page (%08x)\n",
                            Target->targetId, stat));
        } else if (entries[x][0] == '0' || entries[x][1] == 'x') {
            struct scsi_vpd_page *vpdp;
            unsigned id;
            char *e;

            /* The DDK seems to be missing an implementation of
               strtol.  Oh well. */
            e = entries[x] + 2;
            id = 0;
            while (*e) {
                if (id & 0xF0000000)
                    goto bad_format;
                if (*e >= '0' && *e <= '9')
                    id = id * 16 + *e - '0';
                else if (*e >= 'a' && *e <= 'f')
                    id = id * 16 + *e - 'a' + 10;
                else if (*e >= 'A' && *e <= 'F')
                    id = id * 16 + *e - 'A' + 10;
                else
                    goto bad_format;
                e++;
            }
            if (id == 0 || id >= 256) {
                TraceWarning(("target %d: VPD page 0x%x out of range\n", Target->targetId,
                              id));
                continue;
            }

            vpdp = XmAllocateZeroedMemory(sizeof(*vpdp));
            if (vpdp == NULL) {
                TraceError(("target %d: no memory for VPD page 0x%x\n", Target->targetId,
                            id));
                continue;
            }

            vpdp->id = id;
            stat = xenbus_read_base64(bpath, entries[x],
                                      &vpdp->data, &vpdp->data_len);
            if (!NT_SUCCESS(stat)) {
                TraceError(("target %d: failed to read inquiry data: VPD page 0x%x (%08x)\n",
                            Target->targetId, id, stat));
                XmFreeMemory(vpdp);
            } else {
                InsertVpdp(work, vpdp);
            }
        } else {
        bad_format:
            TraceWarning(("target %d: inquiry key '%s' in unknown format\n", Target->targetId,
                          entries[x]));
        }
    }

out:
    if (entries) {
        for (x = 0; entries[x]; x++)
            XmFreeMemory(entries[x]);
        XmFreeMemory(entries);
    }
    XmFreeMemory(bpath);

    /* If any inquiry data was missing from the store, fill it in from
       the defaults. */
    if (!work->default_page) {
        /* All of these fields are defined in spc2r10, available from
           t10.org. */
        INQUIRYDATA *data = XmAllocateZeroedMemory(sizeof(*data));
        if (data) {
            TraceNotice(("target %d: synthesising inquiry data: default page\n", Target->targetId));

            data->DeviceType = DIRECT_ACCESS_DEVICE;
            data->DeviceTypeQualifier = DEVICE_CONNECTED;

            /* Note that while we may have removable *devices*, we
               don't have removable *media*, so this bit is always
               clear. */
            data->RemovableMedia = 0;

            data->Versions = 4;
            data->AERC = 0;
            data->NormACA = 0;
            data->HiSupport = 0;
            data->ResponseDataFormat = 2;
            data->AdditionalLength = sizeof(*data)-5;
            data->MediumChanger = 0;
            data->MultiPort = 0;
            data->EnclosureServices = 0;
            data->SoftReset = 0; /* Technically vendor specific,
                                    according to the spec. */
            data->CommandQueue = 1;
            data->LinkedCommands = 0;
            data->RelativeAddressing = 0;
            memcpy(data->VendorId, "XENSRC  ", 8);
            memcpy(data->ProductId, "PVDISK          ", 16);
            memcpy(data->ProductRevisionLevel, "1.0 ", 4);

            work->default_page = data;
            work->default_page_size = sizeof(*data);
        } else {
            TraceError(("target %d: no memory for default page\n", Target->targetId));
        }
    }

    if (XenvbdDeviceExtension->OverrideVendorId) {
        INQUIRYDATA *data = work->default_page;
        CHAR buffer[9];

        memcpy(data->VendorId, XenvbdDeviceExtension->VendorId, 8);

        memcpy(buffer, XenvbdDeviceExtension->VendorId, 8);
        buffer[8] = '\0';
        TraceNotice(("target %d: VendorId = '%s'\n", Target->targetId, buffer));
    }

    if (XenvbdDeviceExtension->OverrideProductId) {
        INQUIRYDATA *data = work->default_page;
        CHAR buffer[17];

        memcpy(data->ProductId, XenvbdDeviceExtension->ProductId, 16);

        memcpy(buffer, XenvbdDeviceExtension->ProductId, 16);
        buffer[16] = '\0';
        TraceNotice(("target %d: ProductId = '%s'\n", Target->targetId, buffer));
    }

    if (XenvbdDeviceExtension->OverrideProductRevisionLevel) {
        INQUIRYDATA *data = work->default_page;
        CHAR buffer[5];

        memcpy(data->ProductRevisionLevel, XenvbdDeviceExtension->ProductRevisionLevel, 4);

        memcpy(buffer, XenvbdDeviceExtension->ProductRevisionLevel, 4);
        buffer[4] = '\0';
        TraceNotice(("target %d: ProductRevisionLevel = '%s'\n", Target->targetId, buffer));
    }

    /* Pages 80 and 83 are compulsory (83 according to spc2r20 and 80
       according to WHQL). */
    page80 = FindVpdp(work, 0x80);
    if (!page80) {
        TraceNotice(("target %d: synthesising inquiry data: VPD page 0x80\n", Target->targetId));

        page80 = UnitSerialNumberVpdpPage();
        if (page80) {
            InsertVpdp(work, page80);
        } else {
            TraceWarning(("target %d: failed to synthesise inquiry data: VPD page 0x80\n", Target->targetId));
        }
    } else {
        DumpSerialNumberVpdpPage(Target, page80);
    }
    page83 = FindVpdp(work, 0x83);
    if (!page83) {
        TraceNotice(("target %d: synthesising inquiry data: VPD page 0x83\n", Target->targetId));

        /* We don't have anything useful to put in this page, so just
           use an empty one.  This isn't strictly valid, but it seems
           to work fine. */
        /* (see spc4r09 section 7.6.3 and spc2r20 section 8.4.4 for
         * the full details) */
        page83 = EmptyVpdpPage(0x83);
        if (page83) {
            InsertVpdp(work, page83);
        } else {
            TraceWarning(("target %d: failed to synthesise inquiry data: VPD page 0x83\n", Target->targetId));
        }
    } else {
        DumpDeviceIdentificationVpdpPage(Target, page83);
    }

    page0 = ComputePage0(work);
    if (page0) {
        InsertVpdp(work, page0);
    } else {
        TraceWarning(("target %d: failed to create inquiry data: page 0x00\n", Target->targetId));
    }

    XM_ASSERT(Target->inq_data == NULL);
    Target->inq_data = work;

    return STATUS_SUCCESS;

fail2:
    TraceError(("%s: fail2\n", __FUNCTION__));

    XmFreeMemory(work);

fail1:
    TraceError(("%s: fail1 (%08x)\n", __FUNCTION__, stat));

    return stat;
}

//
// XenvbdInquiry - Handle a SCSI inquiry initiated by the SCSI
//                 port device. For now we simply enumerate a
//                 single device on Target/LUN 0/0.
//
VOID
XenvbdInquiry(
    PXHBD_TARGET_INFO ptargetInfo,
    IN OUT PSCSI_REQUEST_BLOCK srb,
    PVOID DataBuffer
)
{
    PCDB cdb = (PCDB)srb->Cdb;
    struct scsi_vpd_page *page;
    size_t pageLength;
    void *pageData;

    if (srb->DataTransferLength < sizeof (struct _CDB6INQUIRY)) {
        TraceWarning(("target %d: invalid INQUIRY SRB\n", srb->TargetId));
        srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        return;
    }

    XM_ASSERT(ptargetInfo != NULL);
    XM_ASSERT(cdb->CDB6INQUIRY3.OperationCode == SCSIOP_INQUIRY);

    pageData = NULL;
    pageLength = 0;

    TraceInfo(("target %d: INQUIRY (%spage 0x%02x)\n", srb->TargetId,
                  (cdb->CDB6INQUIRY3.EnableVitalProductData) ? "VPD " : "",
                  cdb->CDB6INQUIRY3.PageCode));

    memset(DataBuffer, 0, srb->DataTransferLength);
    if (cdb->CDB6INQUIRY3.EnableVitalProductData) {
        page = FindVpdp(ptargetInfo->inq_data, cdb->CDB6INQUIRY3.PageCode);
        if (page) {
            pageLength = page->data_len;
            pageData = page->data;
        }
    } else {
        if (cdb->CDB6INQUIRY3.PageCode == 0) {
            pageLength = ptargetInfo->inq_data->default_page_size;
            pageData = ptargetInfo->inq_data->default_page;
        }
    }

    if (pageData == NULL) {
        TraceWarning(("target %d: missing INQUIRY data for %spage 0x%02x\n",
                      srb->TargetId,
                      (cdb->CDB6INQUIRY3.EnableVitalProductData) ? "VPD " : "",
                      cdb->CDB6INQUIRY3.PageCode));
        XM_ASSERT(pageLength == 0);
        srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
    } else {
        if (srb->DataTransferLength < pageLength) {
            TraceWarning(("target %d: truncated INQUIRY data for %spage 0x%02x (%d < %d)\n",
                          srb->TargetId,
                          (cdb->CDB6INQUIRY3.EnableVitalProductData) ? "VPD " : "",
                          cdb->CDB6INQUIRY3.PageCode,
                          srb->DataTransferLength,
                          pageLength));
        } else {
            XM_ASSERT3U(pageLength, <=, 0xff);
            srb->DataTransferLength = (UCHAR)pageLength;
        }
        memcpy(DataBuffer, pageData, srb->DataTransferLength);
        srb->SrbStatus = SRB_STATUS_SUCCESS;
    }
}

