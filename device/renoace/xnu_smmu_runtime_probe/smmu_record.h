#pragma once
#define SMMU_REC_MAGIC 0xe00
#define SMMU_REC_STATUS 0xe08
#define SMMU_REC_STAGE 0xe10
#define SMMU_REC_COUNT 0xe18
#define SMMU_REC_VA 0xe20
#define SMMU_REC_PAR 0xe28
#define SMMU_REC_VSS_BEFORE 0xe30
#define SMMU_REC_VSS_AFTER 0xe38
#define SMMU_REC_SCR0 0xe40
#define SMMU_REC_IDR0 0xe48
#define SMMU_REC_IDR1 0xe50
#define SMMU_REC_SCR0_2 0xe58
#define SMMU_REC_IDR0_2 0xe60
#define SMMU_REC_IDR1_2 0xe68
#define SMMU_REC_ROWS1 0x1000
#define SMMU_REC_ROWS2 0x1400
#define SMMU_REC_RAW_CRC 0xef0
#define SMMU_REC_REASON 0xef8
#define SMMU_REC_STATUS_ENTERED 1
#define SMMU_REC_STATUS_COMPLETE 2
#define SMMU_REC_STATUS_REFUSED 3
#define SMMU_REC_STAGE_HEADERS 1
#define SMMU_REC_STAGE_ROWS 2
#define SMMU_REC_MAX_ROWS 128
#define SMMU_REC_PA 0x15000000
#define SMMU_REC_BYTES 0x1000
#define SMMU_REC_SCR0_OFF 0x000
#define SMMU_REC_IDR0_OFF 0x020
#define SMMU_REC_IDR1_OFF 0x024
#define SMMU_REC_SMR_OFF 0x800
#define SMMU_REC_S2CR_OFF 0xc00

#ifndef __ASSEMBLER__
#include <stdint.h>
struct smmu_record {
    uint64_t magic, status, stage, count, va, par, vss_before, vss_after;
    uint64_t scr0, idr0, idr1, scr0_2, idr0_2, idr1_2;
    uint64_t rows1[8], rows2[8];
    uint64_t raw_crc, reason;
};
_Static_assert(sizeof(struct smmu_record) == 0x100, "P10 record extent");
#endif
