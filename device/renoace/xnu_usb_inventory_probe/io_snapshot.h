#pragma once
/* P08 private RAM record in P07 ABI3 reserved tail; no existing offset changes. */
#define IO_MAGIC 0x5030384743435244
#define IO_REC_MAGIC 0xca0
#define IO_REC_STATUS 0xca8
#define IO_REC_PC 0xcb0
#define IO_REC_SP 0xcb8
#define IO_REC_VSS_BEFORE 0xcc0
#define IO_REC_VA 0xcc8
#define IO_REC_BYTES 0xcd0
#define IO_REC_STARTUP 0xcd8
#define IO_REC_PAR 0xce0
#define IO_REC_COUNT 0xce8
#define IO_REC_VSS_AFTER 0xcf0
#define IO_REC_STAGE 0xcf8
#define IO_REC_VALUES 0xd00
#define IO_STATUS_ENTERED 1
#define IO_STATUS_COMPLETE 2
#define IO_STATUS_REFUSED 3
#define IO_GCC_PA 0x100000
#define IO_GCC_BYTES 0x1f0000
#define IO_REGISTER_COUNT 8

#define USB_MAGIC 0x5030395553425244
#define USB_REC_MAGIC 0xd40
#define USB_REC_STATUS 0xd48
#define USB_REC_STAGE 0xd50
#define USB_REC_COUNT 0xd58
#define USB_REC_BCR 0xd60
#define USB_REC_VA 0xd68
#define USB_REC_PAR 0xd70
#define USB_REC_VSS_BEFORE 0xd78
#define USB_REC_VSS_AFTER 0xd80
#define USB_REC_GSNPSID 0xd88
#define USB_REC_HWPARAMS0 0xd90
#define USB_REC_GCTL 0xd98
#define USB_REC_DCTL 0xda0
#define USB_REC_DSTS 0xda8
#define USB_REC_COHERENT 0xdb0
#define USB_REC_REASON 0xdb8
#define USB_CORE_PA 0xa60c000
#define USB_CORE_BYTES 0x1000

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>
struct usb_inventory_record {
    uint64_t magic,status,stage,count,bcr,va,par,vss_before,vss_after,gsnpsid,hwparams0,gctl,dctl,dsts,coherent,reason;
};
_Static_assert(sizeof(struct usb_inventory_record)==0x80,"P09 RAM record extent");
struct io_snapshot_pair { uint32_t offset, value; };
struct io_snapshot_record {
    uint64_t magic, status, pc, sp, vss_before, va, bytes, startup;
    uint64_t par, count, vss_after, stage;
    struct io_snapshot_pair values[IO_REGISTER_COUNT];
};
_Static_assert(sizeof(struct io_snapshot_record)==0xa0,"P08 RAM record extent");
_Static_assert(offsetof(struct io_snapshot_record,values)==IO_REC_VALUES-IO_REC_MAGIC,"P08 RAM pairs offset");
#endif
