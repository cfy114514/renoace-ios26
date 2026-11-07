#include "smmu_snapshot.h"

static uint32_t read32(const volatile uint8_t *base, unsigned offset) {
    const volatile uint32_t *word = (const volatile uint32_t *)(base + offset);
    return *word;
}

int renoace_smmu_read_pass(const volatile uint8_t *gr0,
                           struct renoace_smmu_pass *out) {
    if (!gr0 || !out) return 1;
    out->scr0 = read32(gr0, RENOACE_SMMU_SCR0);
    out->idr0 = read32(gr0, RENOACE_SMMU_IDR0);
    out->idr1 = read32(gr0, RENOACE_SMMU_IDR1);
    if (out->idr0 == 0 || out->idr0 == UINT32_MAX ||
        out->idr1 == 0 || out->idr1 == UINT32_MAX) return 2;

    unsigned rows = (out->idr0 >> 27) & 1U ? out->idr0 & 0xffU : 0U;
    if (rows > RENOACE_SMMU_MAX_ROWS) return 3;
    if (RENOACE_SMMU_SMR + rows * 4U > RENOACE_SMMU_GR0_PAGE ||
        RENOACE_SMMU_S2CR + rows * 4U > RENOACE_SMMU_GR0_PAGE) return 4;
    out->row_count = rows;
    for (unsigned i = 0; i < rows; ++i) {
        out->smr[i] = read32(gr0, RENOACE_SMMU_SMR + i * 4U);
        out->s2cr[i] = read32(gr0, RENOACE_SMMU_S2CR + i * 4U);
    }
    return 0;
}

int renoace_smmu_pass_equal(const struct renoace_smmu_pass *a,
                            const struct renoace_smmu_pass *b) {
    if (!a || !b || a->scr0 != b->scr0 || a->idr0 != b->idr0 ||
        a->idr1 != b->idr1 || a->row_count != b->row_count) return 0;
    for (unsigned i = 0; i < a->row_count; ++i)
        if (a->smr[i] != b->smr[i] || a->s2cr[i] != b->s2cr[i]) return 0;
    return 1;
}
