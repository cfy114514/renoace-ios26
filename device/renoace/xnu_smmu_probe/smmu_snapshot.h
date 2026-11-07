#pragma once

#include <stdint.h>

#define RENOACE_SMMU_BASE 0x15000000ULL
#define RENOACE_SMMU_APERTURE 0x100000ULL
#define RENOACE_SMMU_GR0_PAGE 0x1000U
#define RENOACE_SMMU_SCR0 0x000U
#define RENOACE_SMMU_IDR0 0x020U
#define RENOACE_SMMU_IDR1 0x024U
#define RENOACE_SMMU_SMR 0x800U
#define RENOACE_SMMU_S2CR 0xc00U
#define RENOACE_SMMU_MAX_ROWS 255U

struct renoace_smmu_pass {
    uint32_t scr0;
    uint32_t idr0;
    uint32_t idr1;
    uint32_t row_count;
    uint32_t smr[RENOACE_SMMU_MAX_ROWS];
    uint32_t s2cr[RENOACE_SMMU_MAX_ROWS];
};

/* Read only: the caller must provide one mapped, readable GR0 page. */
int renoace_smmu_read_pass(const volatile uint8_t *gr0,
                           struct renoace_smmu_pass *out);

int renoace_smmu_pass_equal(const struct renoace_smmu_pass *a,
                            const struct renoace_smmu_pass *b);
