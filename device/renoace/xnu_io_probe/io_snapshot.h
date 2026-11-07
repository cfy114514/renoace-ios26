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

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>
struct io_snapshot_pair { uint32_t offset, value; };
struct io_snapshot_record {
    uint64_t magic, status, pc, sp, vss_before, va, bytes, startup;
    uint64_t par, count, vss_after, stage;
    struct io_snapshot_pair values[IO_REGISTER_COUNT];
};
_Static_assert(sizeof(struct io_snapshot_record)==0xa0,"P08 RAM record extent");
_Static_assert(offsetof(struct io_snapshot_record,values)==IO_REC_VALUES-IO_REC_MAGIC,"P08 RAM pairs offset");
#endif
