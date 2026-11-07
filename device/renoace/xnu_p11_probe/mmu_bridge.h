#pragma once
/* Shared, fixed-layout ABI for the copied C-entry assembly blob. All addresses
 * in configuration are absolute; all assembly-internal references are PC relative.
 * Entry ABI: x0=kernel entry PA, x1=boot_args PA, x2=embedded context PA.
 * The caller MUST validate x2 against the exported context offset before entry.
 * Returns x0=status, all other GPRs and both original stack banks restored.
 */
#define MMU_BRIDGE_MAGIC 0x5030344d4d554231
#define MMU_BRIDGE_ABI_VERSION 3
#define MMU_BRIDGE_CONTEXT_BYTES 0x1000
#define MMU_STATUS_NONE 0
#define MMU_STATUS_ARM_INIT 1
#define MMU_STATUS_EXCEPTION 2
#define MMU_STATUS_REFUSED 3
#define MMU_STATUS_NESTED_EXCEPTION 4
#define MMU_STATUS_TABLE_REFUSED 5
#define MMU_STATUS_BOOTSTRAP_FATAL 6
#define MMU_FEATURE_PAN 1
#define MMU_FEATURE_UAO 2
#define MMU_GPR 0x100
#define MMU_SCRATCH 0x600
#define MMU_POST_NZCV 0x700
#define MMU_POST_DAIF 0x708
#define MMU_AFTER_MMU_X16 0x710
#define MMU_AFTER_MMU_X17 0x718
#define MMU_AFTER_MMU_PC 0x720
#define MMU_AFTER_MMU_SCTLR 0x728
#define MMU_AFTER_MMU_VBAR 0x730
/* FP helper uses only these three GPRs, leaving the guard/post witnesses intact. */
#define MMU_FP_SNAPSHOT_X9 0x738
#define MMU_FP_SNAPSHOT_X16 0x740
#define MMU_FP_SNAPSHOT_X17 0x748
#define MMU_FP_SNAPSHOT_NZCV 0x750
#define MMU_FP_SNAPSHOT_CPACR 0x758
#define MMU_FP_SNAPSHOT_PC 0x760
#define MMU_FP_Q_BEFORE 0x800
#define MMU_FP_Q_AFTER 0xa00
#define MMU_FPCR_BEFORE 0xc00
#define MMU_FPSR_BEFORE 0xc08
#define MMU_FPCR_AFTER 0xc10
#define MMU_FPSR_AFTER 0xc18
#define MMU_FP_SAVED 0xc20
/* P07 VM witnesses precede recovery to the original bootstrap translation. */
#define MMU_VM_GATE_ENTERED 0xc28
#define MMU_VM_GATE_KIND 0xc30
#define MMU_VM_GATE_PC 0xc38
#define MMU_VM_TTBR0 0xc40
#define MMU_VM_TTBR1 0xc48
#define MMU_VM_CNTKCTL 0xc50
#define MMU_VM_NZCV 0xc58
#define MMU_VM_DAIF 0xc60
#define MMU_VM_SCTLR 0xc68
#define MMU_VM_TCR 0xc70
#define MMU_VM_MAIR 0xc78
#define MMU_VM_RESTORED_TTBR0 0xc80
#define MMU_VM_RESTORED_TTBR1 0xc88
#define MMU_VM_GATE_COMPLETED 0xc90
#define MMU_OBS_RESTORED_CNTKCTL 0xc98
#define MMU_CFG_MAGIC 0x000
#define MMU_CFG_ABI_VERSION 0x008
#define MMU_CFG_CONTEXT_BYTES 0x010
#define MMU_CFG_BLOB_PA 0x018
#define MMU_CFG_BLOB_VA 0x020
#define MMU_CFG_KERNEL_PHYS_BASE 0x028
#define MMU_CFG_KERNEL_VIRT_BASE 0x030
#define MMU_CFG_WINDOW_SIZE 0x038
#define MMU_CFG_CLEAN_START_PA 0x040
#define MMU_CFG_CLEAN_END_PA 0x048
#define MMU_CFG_EXPECTED_ARM_INIT_VA 0x050
#define MMU_CFG_EXPECTED_ARGS_PA 0x058
#define MMU_CFG_EXPECTED_ARGS_VA 0x060
#define MMU_CFG_EXPECTED_SP0_VA 0x068
#define MMU_CFG_EXPECTED_SP1_VA 0x070
#define MMU_CFG_BUDGET_START_TICKS 0x078
#define MMU_CFG_BUDGET_TICKS 0x080
#define MMU_CFG_GUARD_RESUME_PA 0x088
#define MMU_CFG_BOOTSTRAP_START_PA 0x090
#define MMU_CFG_BOOTSTRAP_END_PA 0x098
#define MMU_CFG_LOW_VECTORS_VA 0x0a0
#define MMU_CFG_HIGH_VECTORS_VA 0x0a8
#define MMU_CFG_KERNEL_STARTUP_VA 0x0b0
#define MMU_CFG_EXPECTED_TCR 0x0b8
#define MMU_CFG_EXPECTED_MAIR 0x0c0
#define MMU_CFG_BOOT_ARGS_SIZE 0x0c8
#define MMU_CFG_ADT_PA 0x0d0
#define MMU_CFG_ADT_VA 0x0d8
#define MMU_CFG_ADT_SIZE 0x0e0
#define MMU_CFG_GUARD_EXPECTED_PAIRS 0x0e8
#define MMU_CFG_FLAGS 0x0f0
#define MMU_SAVE_SP_EL0 0x200
#define MMU_SAVE_SP_EL1 0x208
#define MMU_SAVE_SPSEL 0x210
#define MMU_SAVE_NZCV 0x218
#define MMU_SAVE_DAIF 0x220
#define MMU_SAVE_SCTLR 0x228
#define MMU_SAVE_TCR 0x230
#define MMU_SAVE_TTBR0 0x238
#define MMU_SAVE_TTBR1 0x240
#define MMU_SAVE_MAIR 0x248
#define MMU_SAVE_AMAIR 0x250
#define MMU_SAVE_VBAR 0x258
#define MMU_SAVE_CPACR 0x260
#define MMU_SAVE_CONTEXTIDR 0x268
#define MMU_SAVE_TPIDR_EL1 0x270
#define MMU_SAVE_TPIDR_EL0 0x278
#define MMU_SAVE_TPIDRRO_EL0 0x280
#define MMU_SAVE_PAR 0x288
#define MMU_SAVE_ELR 0x290
#define MMU_SAVE_SPSR 0x298
#define MMU_SAVE_CSSELR 0x2a0
#define MMU_SAVE_PAN 0x2a8
#define MMU_SAVE_UAO 0x2b0
#define MMU_SAVE_FEATURES 0x2b8
#define MMU_SAVE_OSLSR 0x2c0
#define MMU_SAVE_CURRENTEL 0x2c8
#define MMU_SAVE_CNTVCT 0x2d0
#define MMU_SAVE_ESR 0x2d8
#define MMU_SAVE_FAR 0x2e0
#define MMU_SAVE_CNTKCTL 0x2e8
#define MMU_OBS_STATUS 0x400
#define MMU_OBS_PHASE 0x408
#define MMU_OBS_ENTERED 0x410
#define MMU_OBS_RETURNED 0x418
#define MMU_OBS_EXCEPTION_SLOT 0x420
#define MMU_OBS_FAULT_DEPTH 0x428
#define MMU_OBS_OBSERVER_PC 0x430
#define MMU_OBS_X0 0x438
#define MMU_OBS_X20 0x440
#define MMU_OBS_X21 0x448
#define MMU_OBS_X30 0x450
#define MMU_OBS_SP_EL0 0x458
#define MMU_OBS_SP_EL1 0x460
#define MMU_OBS_SPSEL 0x468
#define MMU_OBS_NZCV 0x470
#define MMU_OBS_DAIF 0x478
#define MMU_OBS_SCTLR 0x480
#define MMU_OBS_TCR 0x488
#define MMU_OBS_TTBR0 0x490
#define MMU_OBS_TTBR1 0x498
#define MMU_OBS_MAIR 0x4a0
#define MMU_OBS_VBAR 0x4a8
#define MMU_OBS_CPACR 0x4b0
#define MMU_OBS_CONTEXTIDR 0x4b8
#define MMU_OBS_TPIDR_EL1 0x4c0
#define MMU_OBS_TPIDR_EL0 0x4c8
#define MMU_OBS_TPIDRRO_EL0 0x4d0
#define MMU_OBS_ESR 0x4d8
#define MMU_OBS_FAR 0x4e0
#define MMU_OBS_ELR 0x4e8
#define MMU_OBS_SPSR 0x4f0
#define MMU_OBS_PAR_CODE 0x4f8
#define MMU_OBS_PAR_ARGS 0x500
#define MMU_OBS_PAR_SP0 0x508
#define MMU_OBS_PAR_SP1 0x510
#define MMU_OBS_PAR_IDENTITY 0x518
#define MMU_OBS_IDENTITY_PC 0x520
#define MMU_OBS_RESTORED_SCTLR 0x528
#define MMU_OBS_RESTORED_TCR 0x530
#define MMU_OBS_RESTORED_TTBR0 0x538
#define MMU_OBS_RESTORED_TTBR1 0x540
#define MMU_OBS_RESTORED_MAIR 0x548
#define MMU_OBS_RESTORED_VBAR 0x550
#define MMU_OBS_RESTORED_SP0 0x558
#define MMU_OBS_RESTORED_SP1 0x560
#define MMU_OBS_RESTORED_SPSEL 0x568
#define MMU_OBS_RESTORED_PAN 0x570
#define MMU_OBS_RESTORED_UAO 0x578
#define MMU_OBS_CNTVCT 0x580
#define MMU_OBS_FAULT_PHASE 0x588
#define MMU_OBS_SECONDARY_ESR 0x590
#define MMU_OBS_SECONDARY_FAR 0x598
#define MMU_OBS_SECONDARY_ELR 0x5a0

#define MMU_OBS_GUARD_ENTERED 0x5a8
#define MMU_OBS_GUARD_PASSED 0x5b0
#define MMU_OBS_GUARD_CHECKS 0x5b8
#define MMU_OBS_GUARD_FAILURE_VA 0x5c0
#define MMU_OBS_GUARD_FAILURE_DESCRIPTOR 0x5c8
#define MMU_OBS_GUARD_TTBR0 0x5d0
#define MMU_OBS_GUARD_TTBR1 0x5d8
#define MMU_OBS_GUARD_RESUME_PC 0x5e0
#define MMU_OBS_BOOTSTRAP_FATAL 0x5e8
#define MMU_OBS_BUDGET_EXPIRED 0x5f0
#define MMU_OBS_ELAPSED_TICKS 0x5f8

#ifndef __ASSEMBLER__
#include <stdint.h>
#include <stddef.h>
struct mmu_bridge_config {
    uint64_t magic;
    uint64_t abi_version;
    uint64_t context_bytes;
    uint64_t blob_pa;
    uint64_t blob_va;
    uint64_t kernel_phys_base;
    uint64_t kernel_virt_base;
    uint64_t window_size;
    uint64_t clean_start_pa;
    uint64_t clean_end_pa;
    uint64_t expected_arm_init_va;
    uint64_t expected_args_pa;
    uint64_t expected_args_va;
    uint64_t expected_sp0_va;
    uint64_t expected_sp1_va;
    uint64_t budget_start_ticks;
    uint64_t budget_ticks;
    uint64_t guard_resume_pa;
    uint64_t bootstrap_start_pa;
    uint64_t bootstrap_end_pa;
    uint64_t low_vectors_va;
    uint64_t high_vectors_va;
    uint64_t kernel_startup_va;
    uint64_t expected_tcr;
    uint64_t expected_mair;
    uint64_t boot_args_size;
    uint64_t adt_pa;
    uint64_t adt_va;
    uint64_t adt_size;
    uint64_t guard_expected_pairs;
    uint64_t flags;
    uint64_t reserved[1];
};
struct mmu_bridge_saved {
    uint64_t sp_el0;
    uint64_t sp_el1;
    uint64_t spsel;
    uint64_t nzcv;
    uint64_t daif;
    uint64_t sctlr;
    uint64_t tcr;
    uint64_t ttbr0;
    uint64_t ttbr1;
    uint64_t mair;
    uint64_t amair;
    uint64_t vbar;
    uint64_t cpacr;
    uint64_t contextidr;
    uint64_t tpidr_el1;
    uint64_t tpidr_el0;
    uint64_t tpidrro_el0;
    uint64_t par;
    uint64_t elr;
    uint64_t spsr;
    uint64_t csselr;
    uint64_t pan;
    uint64_t uao;
    uint64_t features;
    uint64_t oslsr;
    uint64_t currentel;
    uint64_t cntvct;
    uint64_t esr;
    uint64_t far;
    uint64_t cntkctl;
    uint64_t reserved[34];
};
struct mmu_bridge_observed {
    uint64_t status;
    uint64_t phase;
    uint64_t entered;
    uint64_t returned;
    uint64_t exception_slot;
    uint64_t fault_depth;
    uint64_t observer_pc;
    uint64_t x0;
    uint64_t x20;
    uint64_t x21;
    uint64_t x30;
    uint64_t sp_el0;
    uint64_t sp_el1;
    uint64_t spsel;
    uint64_t nzcv;
    uint64_t daif;
    uint64_t sctlr;
    uint64_t tcr;
    uint64_t ttbr0;
    uint64_t ttbr1;
    uint64_t mair;
    uint64_t vbar;
    uint64_t cpacr;
    uint64_t contextidr;
    uint64_t tpidr_el1;
    uint64_t tpidr_el0;
    uint64_t tpidrro_el0;
    uint64_t esr;
    uint64_t far;
    uint64_t elr;
    uint64_t spsr;
    uint64_t par_code;
    uint64_t par_args;
    uint64_t par_sp0;
    uint64_t par_sp1;
    uint64_t par_identity;
    uint64_t identity_pc;
    uint64_t restored_sctlr;
    uint64_t restored_tcr;
    uint64_t restored_ttbr0;
    uint64_t restored_ttbr1;
    uint64_t restored_mair;
    uint64_t restored_vbar;
    uint64_t restored_sp0;
    uint64_t restored_sp1;
    uint64_t restored_spsel;
    uint64_t restored_pan;
    uint64_t restored_uao;
    uint64_t cntvct;
    uint64_t fault_phase;
    uint64_t secondary_esr;
    uint64_t secondary_far;
    uint64_t secondary_elr;
    uint64_t guard_entered;
    uint64_t guard_passed;
    uint64_t guard_checks;
    uint64_t guard_failure_va;
    uint64_t guard_failure_descriptor;
    uint64_t guard_ttbr0;
    uint64_t guard_ttbr1;
    uint64_t guard_resume_pc;
    uint64_t bootstrap_fatal;
    uint64_t budget_expired;
    uint64_t elapsed_ticks;
};
struct mmu_bridge_context {
    struct mmu_bridge_config config;       /* 0x000 */
    uint64_t gpr[31];                      /* 0x100 */
    uint64_t gpr_padding;
    struct mmu_bridge_saved saved;         /* 0x200 */
    struct mmu_bridge_observed observed;   /* 0x400 */
    uint64_t scratch[64];                  /* 0x600; guard, post flags, MMU/FP helper witnesses */
    uint64_t q_before[32][2];              /* 0x800; little-endian 128-bit Q registers */
    uint64_t q_after[32][2];               /* 0xa00; actual readback after physical restore */
    uint64_t fpcr_before;                  /* 0xc00 */
    uint64_t fpsr_before;                  /* 0xc08 */
    uint64_t fpcr_after;                   /* 0xc10 */
    uint64_t fpsr_after;                   /* 0xc18 */
    uint64_t fp_saved;                     /* 0xc20; snapshot complete iff one */
    uint64_t vm_gate_entered;             /* 0xc28 */
    uint64_t vm_gate_kind;                /* 0xc30; UINT64_MAX normal, 0..15 fault */
    uint64_t vm_gate_pc;                  /* 0xc38 */
    uint64_t vm_ttbr0;                    /* 0xc40; before bootstrap recovery */
    uint64_t vm_ttbr1;                    /* 0xc48 */
    uint64_t vm_cntkctl;                  /* 0xc50 */
    uint64_t vm_nzcv;                     /* 0xc58 */
    uint64_t vm_daif;                     /* 0xc60 */
    uint64_t vm_sctlr;                    /* 0xc68 */
    uint64_t vm_tcr;                      /* 0xc70 */
    uint64_t vm_mair;                     /* 0xc78 */
    uint64_t vm_restored_ttbr0;            /* 0xc80; after bootstrap recovery */
    uint64_t vm_restored_ttbr1;            /* 0xc88 */
    uint64_t vm_gate_completed;            /* 0xc90 */
    uint64_t restored_cntkctl;             /* 0xc98; actual caller readback */
    uint64_t vm_reserved[108];             /* 0xca0..0xfff */
};
_Static_assert(sizeof(struct mmu_bridge_context)==MMU_BRIDGE_CONTEXT_BYTES, "bridge ABI size");
_Static_assert(offsetof(struct mmu_bridge_context,saved.cntkctl)==MMU_SAVE_CNTKCTL, "CNTKCTL saved offset");
_Static_assert(offsetof(struct mmu_bridge_context,vm_gate_entered)==MMU_VM_GATE_ENTERED, "VM extension offset");
_Static_assert(offsetof(struct mmu_bridge_context,restored_cntkctl)==MMU_OBS_RESTORED_CNTKCTL, "CNTKCTL readback offset");
_Static_assert(offsetof(struct mmu_bridge_context,gpr)==MMU_GPR, "bridge GPR offset");
_Static_assert(offsetof(struct mmu_bridge_context,saved)==0x200, "bridge saved offset");
_Static_assert(offsetof(struct mmu_bridge_context,observed)==0x400, "bridge observed offset");
_Static_assert(offsetof(struct mmu_bridge_context,scratch)==MMU_SCRATCH, "bridge scratch offset");
_Static_assert(offsetof(struct mmu_bridge_context,q_before)==MMU_FP_Q_BEFORE, "bridge Q before offset");
_Static_assert(offsetof(struct mmu_bridge_context,q_after)==MMU_FP_Q_AFTER, "bridge Q after offset");
_Static_assert(offsetof(struct mmu_bridge_context,fpcr_before)==MMU_FPCR_BEFORE, "bridge FPCR before offset");
_Static_assert(offsetof(struct mmu_bridge_context,fpsr_before)==MMU_FPSR_BEFORE, "bridge FPSR before offset");
_Static_assert(offsetof(struct mmu_bridge_context,fpcr_after)==MMU_FPCR_AFTER, "bridge FPCR after offset");
_Static_assert(offsetof(struct mmu_bridge_context,fpsr_after)==MMU_FPSR_AFTER, "bridge FPSR after offset");
_Static_assert(offsetof(struct mmu_bridge_context,fp_saved)==MMU_FP_SAVED, "bridge FP saved offset");
_Static_assert(sizeof(((struct mmu_bridge_context *)0)->q_before)==0x200, "bridge Q bank size");
typedef uint64_t (*mmu_bridge_entry_fn)(uint64_t entry_pa, uint64_t args_pa,
                                      struct mmu_bridge_context *context_pa);
extern const unsigned char mmu_bridge_start[], mmu_bridge_end[];
extern const unsigned char mmu_bridge_entry[], mmu_bridge_observer[];
extern const unsigned char mmu_bridge_vectors[], mmu_bridge_context[];
extern const unsigned char mmu_bridge_identity[], mmu_bridge_park[];
extern const unsigned char mmu_bridge_guard[], mmu_bridge_guard_resume[];
extern const unsigned char mmu_bridge_bootstrap_fatal[];
extern const unsigned char mmu_bridge_after_mmu[], mmu_bridge_after_mmu_resume[];
extern const unsigned char mmu_bridge_fp_snapshot[], mmu_bridge_fp_resume[];
#endif
