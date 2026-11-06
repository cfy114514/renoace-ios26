#pragma once
#include <stdint.h>
struct bank { uint64_t base, size; };
struct xnu_input {
    uint64_t image, image_size, dtb, dtb_size, initrd_start, initrd_end;
    const struct bank *banks;
    uint32_t bank_count, reserved_conflict;
};
struct xnu_capture {
    uint64_t returned, x0, x20, x21;
    uint64_t sp_before, sp_after, vbar_before, vbar_after;
    uint64_t sctlr_before, sctlr_after, nzcv_before, nzcv_after;
    uint64_t daif_before, daif_after, oslsr_before, oslsr_after;
};
struct xnu_result {
    uint64_t status, attempted, window_used, source_crc32, source_offset;
    uint64_t copied, zeroed, elapsed_ticks, args, entry, gate;
    struct xnu_capture capture;
    uint64_t budget_ms, phase, segment, phase_bytes, phase_total, phase_ticks;
    uint64_t source_crc_ticks, cache_ticks, copy_ticks, zero_ticks, verify_crc_ticks, verify_zero_ticks;
};
int xnu_gate_call(uint64_t entry, uint64_t args, struct xnu_capture *capture);
void xnu_control(const struct xnu_input *, struct xnu_result *);
void xnu_append_log(const struct xnu_result *);
void value(const char *, uint64_t);
