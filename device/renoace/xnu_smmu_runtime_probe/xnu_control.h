#pragma once
#include <stdint.h>
#include "mmu_bridge.h"
#include "io_snapshot.h"
#include "smmu_record.h"
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
    uint64_t bridge_crc32, adt_crc32, context_pa, config_verified, state_verified;
    uint64_t after_mmu_pc, after_mmu_sctlr, after_mmu_vbar;
    uint64_t pfr1, mmfr2;
    uint64_t fp_saved, fp_verified, q_before_crc32, q_after_crc32, fpcr_before, fpcr_after, fpsr_before, fpsr_after;
    uint64_t pe_initialized, pe_dt_head, pe_boot_args, pe_dt_size, dt_root, dt_size, dt_end, dt_initialized;
    uint64_t soc_base, timebase_frequency, dec_clock_rate, boot_args_global_verified;
    uint64_t vm_gate_entered, vm_gate_kind, vm_gate_pc, vm_ttbr0, vm_ttbr1, vm_cntkctl, vm_nzcv, vm_daif, vm_sctlr, vm_tcr, vm_mair, vm_restored_ttbr0, vm_restored_ttbr1, vm_gate_completed, restored_cntkctl, vm_avail_start, vm_first_avail, vm_kva_active, vm_cpu_tte, vm_invalid_tte, vm_physmap_base, vm_physmap_end, vm_soc_valid, vm_gate_leaf, vm_blob_leaf, vm_verified;
    struct usb_inventory_record usb;
    uint64_t usb_page_verified, usb_verified;
    struct smmu_record smmu;
    uint64_t smmu_verified;
    uint64_t smmu_rows1[SMMU_REC_MAX_ROWS], smmu_rows2[SMMU_REC_MAX_ROWS];
    struct io_snapshot_record io;
    uint64_t io_pages_verified, io_verified;
    struct mmu_bridge_saved saved;
    struct mmu_bridge_observed mmu;
};
void xnu_control(const struct xnu_input *, struct xnu_result *);
void xnu_append_log(const struct xnu_result *);
void value(const char *, uint64_t);
