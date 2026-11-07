/* P08: execute original VM + original ml_io_map + GCC read-only snapshot, with
 * a truthful identity arm-io bus and the compiled checked zero-base API.
 * SIMD state is snapshotted before the C prologue and restored on return.
 */
#include <stddef.h>
#include <stdint.h>
#include "layout.h"
#include "xnu_control.h"
struct xnu_segment { uint64_t offset, memory_size, file_offset, file_size; uint32_t crc; };
#include "xnu_layout.h"
extern const unsigned char bridge_payload_start[], bridge_payload_end[];
#define RSR(r) ({ uint64_t v; __asm__ volatile("mrs %0, " #r : "=r"(v)); v; })
_Static_assert(sizeof(struct xnu_capture)==128,"assembly capture layout");
_Static_assert(offsetof(struct xnu_capture,oslsr_after)==120,"assembly capture offset");
_Static_assert(sizeof(xnu_boot_args)==XNU_BOOT_ARGS_SIZE,"boot_args template size");
_Static_assert(sizeof(xnu_adt)==XNU_ADT_SIZE,"ADT template size");
static uint64_t started, budget_ticks;
static struct xnu_result *active_result;
static uint64_t phase_started;
static int phase_open;
static int within(uint64_t a,uint64_t n,uint64_t b,uint64_t m) {
    return n && m && a+n>=a && b+m>=b && a>=b && a+n<=b+m;
}
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m) {
    return n && m && (a+n<a || b+m<b || (a<b+m && b<a+n));
}
static uint64_t ticks(void) { __asm__ volatile("isb"); return RSR(cntvct_el0); }
static int expired(void) { return ticks()-started>budget_ticks; }
static void phase_end(void) {
    if(!phase_open) return;
    uint64_t elapsed=ticks()-phase_started;
    struct xnu_result *r=active_result;
    r->phase_ticks=elapsed;
    switch(r->phase) {
        case 1:r->source_crc_ticks+=elapsed;break;
        case 2:r->cache_ticks+=elapsed;break;
        case 3:r->copy_ticks+=elapsed;break;
        case 4:r->zero_ticks+=elapsed;break;
        case 5:r->verify_crc_ticks+=elapsed;break;
        case 6:r->verify_zero_ticks+=elapsed;break;
    }
    phase_open=0;
}
static void phase_begin(uint64_t phase,uint64_t segment,uint64_t total) {
    phase_end();
    active_result->phase=phase;active_result->segment=segment;
    active_result->phase_bytes=0;active_result->phase_total=total;active_result->phase_ticks=0;
    phase_started=ticks();phase_open=1;
}
static void progress(uint64_t n) {
    if(!active_result) return;
    uint64_t previous=active_result->phase_bytes;
    if(active_result->phase==3) active_result->copied+=n-previous;
    if(active_result->phase==4) active_result->zeroed+=n-previous;
    active_result->phase_bytes=n;
}
/* No cache/MMU change: naturally aligned, wider DDR transactions only.
 * Every primitive checks time and commits progress at <=64KiB intervals. */
__attribute__((noinline)) static uint32_t crc32_bounded(uintptr_t pointer,uint64_t bytes,int *bad) {
    uint32_t crc=0xffffffffU;uint64_t i=0;
    while(i<bytes) {
        if(expired()) { *bad=1; return 0; }
        uint64_t end=bytes-i>0x10000?i+0x10000:bytes;
        while(i<end && ((pointer+i)&7)) {
            uint32_t byte=*(const volatile uint8_t *)(pointer+i++);
            __asm__ volatile("crc32b %w0, %w0, %w1":"+r"(crc):"r"(byte));
        }
        for(;i+8<=end;i+=8) {
            uint64_t word=*(const volatile uint64_t *)(pointer+i);
            __asm__ volatile("crc32x %w0, %w0, %1":"+r"(crc):"r"(word));
        }
        for(;i<end;++i) {
            uint32_t byte=*(const volatile uint8_t *)(pointer+i);
            __asm__ volatile("crc32b %w0, %w0, %w1":"+r"(crc):"r"(byte));
        }
        progress(i);
    }
    return ~crc;
}
__attribute__((noinline)) static int zero_bounded(uintptr_t p,uint64_t n) {
    if((p|n)&7) return -1;
    uint64_t i=0;
    while(i<n) {
        if(expired()) return -1;
        uint64_t end=n-i>0x10000?i+0x10000:n;
        for(;i+16<=end;i+=16) __asm__ volatile("stp xzr, xzr, [%0]"::"r"(p+i):"memory");
        if(i<end) { *(volatile uint64_t *)(p+i)=0;i+=8; }
        progress(i);
    }
    return 0;
}
__attribute__((noinline)) static int copy_bounded(uintptr_t to,uintptr_t from,uint64_t n) {
    if((to|from|n)&7) return -1;
    uint64_t i=0;
    while(i<n) {
        if(expired()) return -1;
        uint64_t end=n-i>0x10000?i+0x10000:n;
        for(;i+16<=end;i+=16) {
            uint64_t a,b;
            __asm__ volatile("ldp %0, %1, [%2]":"=&r"(a),"=&r"(b):"r"(from+i):"memory");
            __asm__ volatile("stp %0, %1, [%2]"::"r"(a),"r"(b),"r"(to+i):"memory");
        }
        if(i<end) { *(volatile uint64_t *)(to+i)=*(const volatile uint64_t *)(from+i);i+=8; }
        progress(i);
    }
    return 0;
}
__attribute__((noinline)) static int check_zero_bounded(uintptr_t p,uint64_t n) {
    if((p|n)&7) return -1;
    uint64_t i=0;
    while(i<n) {
        if(expired()) return -1;
        uint64_t end=n-i>0x10000?i+0x10000:n,combined=0;
        for(;i+16<=end;i+=16) {
            uint64_t a,b;
            __asm__ volatile("ldp %0, %1, [%2]":"=&r"(a),"=&r"(b):"r"(p+i):"memory");
            combined|=a|b;
        }
        if(i<end) { combined|=*(const volatile uint64_t *)(p+i);i+=8; }
        progress(i);
        if(combined) return -2;
    }
    return 0;
}
static int invalidate_range(uintptr_t p,uint64_t n) {
    uint64_t line=4UL<<((RSR(ctr_el0)>>16)&15);
    if(line<16 || line>2048 || p+n<p) return -1;
    __asm__ volatile("dsb sy":::"memory");
    for(uintptr_t a=p&~(line-1);a<p+n;a+=line) {
        if(!(a&0xffff) && expired()) return -1;
        __asm__ volatile("dc ivac, %0"::"r"(a):"memory");
        if(!((a+line)&0xffff)) progress(a+line-p);
    }
    __asm__ volatile("dsb sy":::"memory");
    progress(n);
    return 0;
}
static void clean_range(uintptr_t first,uintptr_t end) {
    uint64_t line=4UL<<((RSR(ctr_el0)>>16)&15);
    __asm__ volatile("dsb sy":::"memory");
    for(uintptr_t a=first&~(line-1);a<end;a+=line) __asm__ volatile("dc cvac, %0"::"r"(a):"memory");
    __asm__ volatile("dsb sy; ic iallu; dsb sy; isb":::"memory");
}

/* Separate, visible checkpoint for the model's gate-not-patched control. */
__attribute__((noinline)) int xnu_validate_gate(void) {
    for(unsigned i=0;i<XNU_PATCH_COUNT;++i)
        if(*(volatile uint32_t *)(XNU_PHYS_BASE+xnu_patches[i].offset)!=xnu_patches[i].replacement) return 0;
    return 1;
}

static int translated(uint64_t par,uint64_t va,uint64_t pa) {
    return !(par&1) && ((par&0x000000fffffff000UL)|(va&0xfff))==pa;
}

static uint32_t snapshot_crc(const void *p,unsigned n) {
    const uint8_t *bytes=p;uint32_t crc=0xffffffffU;
    for(unsigned i=0;i<n;++i) {
        uint32_t byte=bytes[i];
        __asm__ volatile("crc32b %w0, %w0, %w1":"+r"(crc):"r"(byte));
    }
    return ~crc;
}

/* Read only the final owned 4-KiB page-table pages after M=0 restoration.
 * T1SZ=26 gives38input bits; restrict the root index before descriptor reads. */
static int vm_walk(uint64_t root,uint64_t va,uint64_t limit,uint64_t *pa,uint64_t *leaf,uint64_t *xn) {
    uint64_t table=root&0x0000fffffffff000UL,input=va&((1UL<<38)-1),pxn=0;
    if(limit>XNU_VM_MAX_ALLOC_PA || limit<=XNU_VM_CPU_ROOT_PA) return 0;
    for(unsigned level=1;level<=3;++level) {
        if(!within(table,0x1000,XNU_PHYS_BASE,limit-XNU_PHYS_BASE)) return 0;
        unsigned shift=level==1?30:level==2?21:12;
        uint64_t d=*(const volatile uint64_t *)(table+((input>>shift)&511)*8);
        if(!(d&1)) return 0;
        if(level<3 && (d&2)) { pxn|=(d>>59)&1;table=d&0x0000fffffffff000UL;continue; }
        if(level==1 || (level==3 && !(d&2))) return 0;
        *pa=(d&0x0000fffffffff000UL&~((1UL<<shift)-1))|(va&((1UL<<shift)-1));
        *leaf=d;*xn=pxn|((d>>53)&1);return 1;
    }
    return 0;
}

__attribute__((always_inline)) static inline int state_restored(const struct mmu_bridge_saved *s) {
#define CHECK_REG(reg,member) if(RSR(reg)!=s->member) return 0
    CHECK_REG(CurrentEL,currentel);CHECK_REG(sctlr_el1,sctlr);CHECK_REG(tcr_el1,tcr);
    CHECK_REG(ttbr0_el1,ttbr0);CHECK_REG(ttbr1_el1,ttbr1);CHECK_REG(mair_el1,mair);
    CHECK_REG(amair_el1,amair);CHECK_REG(vbar_el1,vbar);CHECK_REG(cpacr_el1,cpacr);
    CHECK_REG(contextidr_el1,contextidr);CHECK_REG(tpidr_el1,tpidr_el1);
    CHECK_REG(tpidr_el0,tpidr_el0);CHECK_REG(tpidrro_el0,tpidrro_el0);
    CHECK_REG(par_el1,par);CHECK_REG(elr_el1,elr);CHECK_REG(spsr_el1,spsr);
    CHECK_REG(esr_el1,esr);CHECK_REG(far_el1,far);
    CHECK_REG(cntkctl_el1,cntkctl);CHECK_REG(csselr_el1,csselr);CHECK_REG(oslsr_el1,oslsr);
    if(s->features&MMU_FEATURE_PAN) { CHECK_REG(pan,pan); }
    if(s->features&MMU_FEATURE_UAO) { CHECK_REG(uao,uao); }
#undef CHECK_REG
    uint64_t sp0,sp1,selection;
    __asm__ volatile("mrs %2, SPSel; msr SPSel, #0; mov %0, sp; msr SPSel, #1; mov %1, sp; msr SPSel, %2"
                     :"=&r"(sp0),"=&r"(sp1),"=&r"(selection)::"memory");
    return sp0==s->sp_el0 && sp1==s->sp_el1 && selection==s->spsel;
}

void xnu_control(const struct xnu_input *in,struct xnu_result *r) {
    active_result=r;phase_open=0;r->budget_ms=15000;
    r->status=1; /* EL gate */
    if(RSR(CurrentEL)!=4) return;
    if((RSR(sctlr_el1)&5)!=0) { r->status=2; return; }
    r->capture.oslsr_before=RSR(oslsr_el1);
    if(r->capture.oslsr_before&2) { r->status=3; return; }
    r->pfr1=RSR(id_aa64pfr1_el1);r->mmfr2=RSR(id_aa64mmfr2_el1);
    if((r->pfr1>>4)&15) { r->status=21; return; }
    if(((RSR(id_aa64isar0_el1)>>16)&15)==0) { r->status=15; return; }
    r->status=4; /* high-window containment/ownership contract */
    if(in->reserved_conflict || overlap(XNU_PHYS_BASE,XNU_WINDOW_SIZE,in->image,in->image_size) ||
       overlap(XNU_PHYS_BASE,XNU_WINDOW_SIZE,in->dtb,in->dtb_size) ||
       overlap(XNU_PHYS_BASE,XNU_WINDOW_SIZE,in->initrd_start,in->initrd_end-in->initrd_start)) return;
    unsigned bank;
    for(bank=0;bank<in->bank_count;++bank)
        if(within(XNU_PHYS_BASE,XNU_WINDOW_SIZE,in->banks[bank].base,in->banks[bank].size)) break;
    if(bank==in->bank_count || (XNU_PHYS_BASE&0x1fffff)!=(XNU_LINK_BASE&0x1fffff)) return;
    r->status=5; /* raw newc member range */
    if(in->initrd_end-in->initrd_start!=NORMAL_RAMDISK_SIZE || XNU_INITRD_OFFSET+XNU_FILE_SIZE>NORMAL_RAMDISK_SIZE) return;
    uintptr_t src=in->initrd_start+XNU_INITRD_OFFSET;
    if((src&7) || src<in->initrd_start) return;
    r->source_offset=XNU_INITRD_OFFSET;
    uint64_t freq=RSR(cntfrq_el0);
    if(!freq || freq>1000000000UL) { r->status=6; return; }
    started=ticks();budget_ticks=freq*15;
    int bad=0;
    phase_begin(1,UINT64_MAX,XNU_FILE_SIZE);
    r->source_crc32=crc32_bounded(src,XNU_FILE_SIZE,&bad);
    phase_end();
    if(bad) { r->status=7; goto done; }
    if(r->source_crc32!=XNU_FILE_CRC32) { r->status=8; goto done; }

    for(unsigned i=0;i<XNU_SEGMENT_COUNT;++i) {
        const struct xnu_segment *s=&xnu_segments[i];
        if(!within(s->offset,s->memory_size,0,XNU_WINDOW_SIZE) || s->file_size>s->memory_size ||
           (s->file_size && !within(s->file_offset,s->file_size,0,XNU_FILE_SIZE)) ||
           ((s->offset|s->file_offset|s->file_size|s->memory_size)&7)) { r->status=10; goto done; }
        uintptr_t dst=XNU_PHYS_BASE+s->offset;
        phase_begin(2,i,s->memory_size);
        if(invalidate_range(dst,s->memory_size)) { r->status=7; goto done; }
        r->window_used=1;
        phase_begin(3,i,s->file_size);
        if(copy_bounded(dst,src+s->file_offset,s->file_size)) { r->status=7; goto done; }
        phase_begin(4,i,s->memory_size-s->file_size);
        if(zero_bounded(dst+s->file_size,s->memory_size-s->file_size)) { r->status=7; goto done; }
        phase_begin(5,i,s->file_size);
        uint32_t copied_crc=crc32_bounded(dst,s->file_size,&bad);
        if(bad) { r->status=7; goto done; }
        phase_begin(6,i,s->memory_size-s->file_size);
        int zero_check=check_zero_bounded(dst+s->file_size,s->memory_size-s->file_size);
        phase_end();
        if(zero_check==-1) { r->status=7; goto done; }
        if(copied_crc!=s->crc || zero_check) { r->status=11; goto done; }
    }
    r->args=XNU_PHYS_BASE+XNU_ARGS_OFFSET;
    r->entry=XNU_PHYS_BASE+XNU_ENTRY_OFFSET;r->gate=XNU_PHYS_BASE+XNU_CHECKPOINT_OFFSET;
    uint64_t blob=XNU_PHYS_BASE+XNU_BLOB_OFFSET;
    uint64_t clean_end=XNU_MAPPED_CLEAN_END;
    uint64_t metadata_bytes=(XNU_ADT_OFFSET+XNU_ADT_SIZE-XNU_ARGS_OFFSET+7)&~7UL;
    phase_begin(7,XNU_SEGMENT_COUNT,XNU_BLOB_RESERVE);
    if(XNU_BRIDGE_BYTES>XNU_BLOB_RESERVE || XNU_BRIDGE_CONTEXT_OFFSET+sizeof(struct mmu_bridge_context)>XNU_BRIDGE_BYTES ||
       (uintptr_t)bridge_payload_end-(uintptr_t)bridge_payload_start!=XNU_BRIDGE_BYTES ||
       clean_end>XNU_MAPPED_CLEAN_END || metadata_bytes>XNU_BLOB_RESERVE ||
       XNU_ADT_OFFSET+XNU_ADT_SIZE>XNU_BLOB_OFFSET || XNU_ARGS_OFFSET<XNU_ENTRY_OFFSET ||
       !within(XNU_BLOB_OFFSET,XNU_BLOB_RESERVE,0,XNU_WINDOW_SIZE)) { r->status=20; goto done; }
    if(invalidate_range(r->args,metadata_bytes) || zero_bounded(r->args,metadata_bytes) ||
       copy_bounded(r->args,(uintptr_t)xnu_boot_args,XNU_BOOT_ARGS_SIZE)) { r->status=7; goto done; }
    for(unsigned i=0;i<XNU_ADT_SIZE;++i) *(volatile uint8_t *)(XNU_PHYS_BASE+XNU_ADT_OFFSET+i)=xnu_adt[i];
    r->adt_crc32=crc32_bounded(XNU_PHYS_BASE+XNU_ADT_OFFSET,XNU_ADT_SIZE,&bad);
    if(bad) { r->status=7; goto done; }
    if(r->adt_crc32!=XNU_ADT_CRC32) { r->status=17; goto done; }
    for(unsigned i=0;i<XNU_BOOT_ARGS_SIZE;++i)
        if(*(volatile uint8_t *)(r->args+i)!=xnu_boot_args[i]) { r->status=17; goto done; }
    if(invalidate_range(blob,XNU_BLOB_RESERVE) || zero_bounded(blob,XNU_BLOB_RESERVE) ||
       copy_bounded(blob,(uintptr_t)bridge_payload_start,XNU_BRIDGE_BYTES)) { r->status=7; goto done; }
    r->bridge_crc32=crc32_bounded(blob,XNU_BRIDGE_BYTES,&bad);
    if(bad) { r->status=7; goto done; }
    if(r->bridge_crc32!=XNU_BRIDGE_CRC32) { r->status=16; goto done; }
    struct mmu_bridge_context *ctx=(struct mmu_bridge_context *)(blob+XNU_BRIDGE_CONTEXT_OFFSET);
    r->context_pa=(uintptr_t)ctx;
    uint64_t guard_pairs=2*(((clean_end-1)>>21)-(XNU_PHYS_BASE>>21)+1)+13;
    struct mmu_bridge_config configured={
        .magic=MMU_BRIDGE_MAGIC,.abi_version=MMU_BRIDGE_ABI_VERSION,.context_bytes=sizeof(*ctx),
        .blob_pa=blob,.blob_va=XNU_LINK_BASE+XNU_BLOB_OFFSET,
        .kernel_phys_base=XNU_PHYS_BASE,.kernel_virt_base=XNU_LINK_BASE,.window_size=XNU_WINDOW_SIZE,
        .clean_start_pa=XNU_PHYS_BASE,.clean_end_pa=clean_end,
        .expected_arm_init_va=XNU_LINK_BASE+XNU_CHECKPOINT_OFFSET,
        .expected_args_pa=r->args,.expected_args_va=XNU_LINK_BASE+XNU_ARGS_OFFSET,
        .expected_sp0_va=XNU_SP0_VA,.expected_sp1_va=XNU_SP1_VA,
        .budget_start_ticks=started,.budget_ticks=budget_ticks,
        .guard_resume_pa=XNU_PHYS_BASE+XNU_COMMON_START_OFFSET,
        .bootstrap_start_pa=XNU_PHYS_BASE+XNU_BOOTSTRAP_OFFSET,
        .bootstrap_end_pa=XNU_PHYS_BASE+XNU_BOOTSTRAP_OFFSET+XNU_BOOTSTRAP_BYTES,
        .low_vectors_va=XNU_LINK_BASE+XNU_LOW_VECTORS_OFFSET,
        .high_vectors_va=XNU_LINK_BASE+XNU_HIGH_VECTORS_OFFSET,
        .kernel_startup_va=XNU_LINK_BASE+XNU_ENTRY_OFFSET,
        .expected_tcr=XNU_EXPECTED_TCR,.expected_mair=XNU_EXPECTED_MAIR,
        .boot_args_size=XNU_BOOT_ARGS_SIZE,.adt_pa=XNU_PHYS_BASE+XNU_ADT_OFFSET,
        .adt_va=XNU_LINK_BASE+XNU_ADT_OFFSET,.adt_size=XNU_ADT_SIZE,
        .guard_expected_pairs=guard_pairs,
    };
    ctx->config=configured;
    for(unsigned i=0;i<XNU_PATCH_COUNT;++i) {
        const struct xnu_patch *p=&xnu_patches[i];
        if((p->offset&3) || !within(p->offset,4,0,XNU_ARGS_OFFSET)) { r->status=10; goto done; }
        volatile uint32_t *word=(volatile uint32_t *)(XNU_PHYS_BASE+p->offset);
        if(*word!=p->original) { r->status=9; goto done; }
        *word=p->replacement;
        clean_range((uintptr_t)word,(uintptr_t)word+4);
    }
    clean_range(r->args,r->args+metadata_bytes);
    clean_range(blob,blob+XNU_BRIDGE_BYTES);
    if(!xnu_validate_gate()) { r->status=12; goto done; }
    if(expired()) { r->status=7; goto done; }
    if(RSR(oslsr_el1)&2) { r->status=3; goto done; }
    phase_begin(8,XNU_SEGMENT_COUNT,0);
    r->attempted=1;
    mmu_bridge_entry_fn enter=(mmu_bridge_entry_fn)(blob+XNU_BRIDGE_ENTRY_OFFSET);
    uint64_t bridge_status=enter(r->entry,r->args,ctx);
    __asm__ volatile("":::"memory");
    r->saved=ctx->saved;r->mmu=ctx->observed;r->attempted=r->mmu.entered;
    r->io=*(const volatile struct io_snapshot_record *)((uintptr_t)ctx+IO_REC_MAGIC);
    r->usb=*(const volatile struct usb_inventory_record *)((uintptr_t)ctx+USB_REC_MAGIC);
    r->smmu=*(const volatile struct smmu_record *)((uintptr_t)ctx+SMMU_REC_MAGIC);
    for(unsigned i=0;i<SMMU_REC_MAX_ROWS;++i) {
        r->smmu_rows1[i]=*(const volatile uint64_t *)((uintptr_t)ctx+SMMU_REC_ROWS1+i*8);
        r->smmu_rows2[i]=*(const volatile uint64_t *)((uintptr_t)ctx+SMMU_REC_ROWS2+i*8);
    }
    r->vm_gate_entered=ctx->vm_gate_entered;
    r->vm_gate_kind=ctx->vm_gate_kind;
    r->vm_gate_pc=ctx->vm_gate_pc;
    r->vm_ttbr0=ctx->vm_ttbr0;
    r->vm_ttbr1=ctx->vm_ttbr1;
    r->vm_cntkctl=ctx->vm_cntkctl;
    r->vm_nzcv=ctx->vm_nzcv;
    r->vm_daif=ctx->vm_daif;
    r->vm_sctlr=ctx->vm_sctlr;
    r->vm_tcr=ctx->vm_tcr;
    r->vm_mair=ctx->vm_mair;
    r->vm_restored_ttbr0=ctx->vm_restored_ttbr0;
    r->vm_restored_ttbr1=ctx->vm_restored_ttbr1;
    r->vm_gate_completed=ctx->vm_gate_completed;
    r->restored_cntkctl=ctx->restored_cntkctl;
    r->fp_saved=ctx->fp_saved;r->fpcr_before=ctx->fpcr_before;r->fpcr_after=ctx->fpcr_after;
    r->fpsr_before=ctx->fpsr_before;r->fpsr_after=ctx->fpsr_after;
    r->q_before_crc32=snapshot_crc(ctx->q_before,sizeof(ctx->q_before));
    r->q_after_crc32=snapshot_crc(ctx->q_after,sizeof(ctx->q_after));
    r->fp_verified=r->fp_saved==1 && r->fpcr_before==r->fpcr_after && r->fpsr_before==r->fpsr_after;
    for(unsigned i=0;i<sizeof(ctx->q_before);++i)
        if(((const volatile uint8_t *)ctx->q_before)[i]!=((const volatile uint8_t *)ctx->q_after)[i]) r->fp_verified=0;
#define RAM32(name) (*(const volatile uint32_t *)(XNU_PHYS_BASE+XNU_##name##_OFFSET))
#define RAM64(name) (*(const volatile uint64_t *)(XNU_PHYS_BASE+XNU_##name##_OFFSET))
    r->pe_initialized=RAM32(PE_INITIALIZED);r->pe_dt_head=RAM64(PE_DT_HEAD);
    r->pe_boot_args=RAM64(PE_BOOT_ARGS);r->pe_dt_size=RAM64(PE_DT_SIZE);
    r->dt_root=RAM64(DT_ROOT);r->dt_size=RAM64(DT_SIZE);r->dt_end=RAM64(DT_END);r->dt_initialized=RAM32(DT_INITIALIZED);
    r->soc_base=RAM64(SOC_BASE);r->timebase_frequency=RAM64(TIMEBASE_FREQUENCY);r->dec_clock_rate=RAM64(DEC_CLOCK_RATE);
    r->vm_avail_start=RAM64(VM_AVAIL_START);r->vm_first_avail=RAM64(VM_FIRST_AVAIL);
    r->vm_kva_active=*(const volatile uint8_t *)(XNU_PHYS_BASE+XNU_VM_KVA_ACTIVE_OFFSET);
    r->vm_cpu_tte=RAM64(VM_CPU_TTE);r->vm_invalid_tte=RAM64(VM_INVALID_TTE);
    r->vm_physmap_base=RAM64(VM_PHYSMAP_BASE);r->vm_physmap_end=RAM64(VM_PHYSMAP_END);
    r->vm_soc_valid=*(const volatile uint8_t *)(XNU_PHYS_BASE+XNU_SOC_VALID_OFFSET);
#undef RAM32
#undef RAM64
    const volatile uint64_t *global_args=(const volatile uint64_t *)(XNU_PHYS_BASE+XNU_CONST_BOOT_ARGS_OFFSET);
    r->boot_args_global_verified=*(const volatile uint64_t *)(XNU_PHYS_BASE+XNU_BOOT_ARGS_GLOBAL_OFFSET)==XNU_CONST_BOOT_ARGS_VA &&
        *(const volatile uint32_t *)global_args==0x00020002 &&
        global_args[1]==XNU_LINK_BASE && global_args[2]==XNU_PHYS_BASE && global_args[3]==XNU_WINDOW_SIZE &&
        global_args[0x60/8]==XNU_LINK_BASE+XNU_ADT_OFFSET &&
        *(const volatile uint32_t *)((uintptr_t)global_args+0x68)==XNU_ADT_SIZE;
    r->after_mmu_pc=ctx->scratch[(MMU_AFTER_MMU_PC-MMU_SCRATCH)/8];
    r->after_mmu_sctlr=ctx->scratch[(MMU_AFTER_MMU_SCTLR-MMU_SCRATCH)/8];
    r->after_mmu_vbar=ctx->scratch[(MMU_AFTER_MMU_VBAR-MMU_SCRATCH)/8];
    r->capture.returned=r->mmu.entered&&r->mmu.returned;r->capture.x0=r->mmu.x0;r->capture.x20=r->mmu.x20;r->capture.x21=r->mmu.x21;
    r->capture.sp_before=r->saved.spsel?r->saved.sp_el1:r->saved.sp_el0;
    r->capture.sp_after=r->mmu.restored_spsel?r->mmu.restored_sp1:r->mmu.restored_sp0;
    r->capture.vbar_before=r->saved.vbar;r->capture.vbar_after=RSR(vbar_el1);
    r->capture.sctlr_before=r->saved.sctlr;r->capture.sctlr_after=RSR(sctlr_el1);
    r->capture.nzcv_before=r->saved.nzcv;r->capture.nzcv_after=ctx->scratch[(MMU_POST_NZCV-MMU_SCRATCH)/8];
    r->capture.daif_before=r->saved.daif;r->capture.daif_after=ctx->scratch[(MMU_POST_DAIF-MMU_SCRATCH)/8];
    r->capture.oslsr_before=r->saved.oslsr;r->capture.oslsr_after=RSR(oslsr_el1);
    r->config_verified=1;
    for(unsigned i=0;i<sizeof(configured);++i)
        if(((const volatile uint8_t *)&ctx->config)[i]!=((const uint8_t *)&configured)[i]) r->config_verified=0;
    r->state_verified=state_restored(&r->saved);
    if(!r->mmu.returned) { r->status=13; goto done; }
    if(!r->config_verified) { r->status=19; goto done; }
    if(bridge_status!=MMU_STATUS_ARM_INIT || r->mmu.status!=MMU_STATUS_ARM_INIT) { r->status=18; goto done; }
    if(!r->fp_verified) { r->status=22; goto done; }
    if(!r->boot_args_global_verified || r->pe_initialized!=1 || r->dt_initialized!=1 ||
       r->pe_dt_head!=configured.adt_va || r->pe_boot_args!=XNU_CONST_BOOT_ARGS_VA || r->pe_dt_size!=XNU_ADT_SIZE ||
       r->dt_root!=configured.adt_va || r->dt_size!=XNU_ADT_SIZE || r->dt_end!=configured.adt_va+XNU_ADT_SIZE ||
       r->soc_base!=0 || r->timebase_frequency!=19200000 || r->dec_clock_rate!=19200000) { r->status=23; goto done; }
    if(!r->state_verified || r->capture.nzcv_before!=r->capture.nzcv_after || r->capture.daif_before!=r->capture.daif_after ||
       r->mmu.entered!=1 || r->mmu.guard_entered!=1 || r->mmu.guard_passed!=1 || r->mmu.guard_checks!=guard_pairs ||
       r->mmu.observer_pc!=configured.blob_va+XNU_BRIDGE_OBSERVER_OFFSET ||
       r->mmu.identity_pc!=blob+XNU_BRIDGE_IDENTITY_OFFSET ||
       r->mmu.x20!=XNU_EXPECTED_OBS_X20 || r->mmu.x21!=XNU_EXPECTED_OBS_X21 || r->mmu.x30!=configured.expected_arm_init_va ||
       r->mmu.sp_el0!=XNU_OBS_SP0_VA || r->mmu.sp_el1!=XNU_OBS_SP1_VA || r->mmu.spsel!=0 ||
       (r->mmu.sctlr&0x1005)!=0x1005 || r->mmu.tcr!=XNU_EXPECTED_TCR || r->mmu.mair!=XNU_EXPECTED_MAIR ||
       r->mmu.ttbr0!=configured.bootstrap_start_pa || r->mmu.ttbr1!=configured.bootstrap_start_pa+0x1000 ||
       r->mmu.vbar!=configured.high_vectors_va || r->mmu.fault_depth || r->mmu.bootstrap_fatal ||
       r->after_mmu_pc!=blob+XNU_BRIDGE_AFTER_MMU_OFFSET ||
       (r->after_mmu_sctlr&0x1005)!=0x1005 || r->after_mmu_vbar!=configured.high_vectors_va ||
       !translated(r->mmu.par_code,r->mmu.observer_pc,blob+XNU_BRIDGE_OBSERVER_OFFSET) ||
       !translated(r->mmu.par_args,configured.expected_args_va,r->args) ||
       !translated(r->mmu.par_sp0,XNU_OBS_SP0_VA-16,XNU_PHYS_BASE+XNU_OBS_SP0_VA-16-XNU_LINK_BASE) ||
       !translated(r->mmu.par_sp1,XNU_OBS_SP1_VA-16,XNU_PHYS_BASE+XNU_OBS_SP1_VA-16-XNU_LINK_BASE) ||
       !translated(r->mmu.par_identity,blob+XNU_BRIDGE_IDENTITY_OFFSET,blob+XNU_BRIDGE_IDENTITY_OFFSET)) { r->status=14; goto done; }
    uint64_t gate_pa=0,blob_pa=0,gate_xn=0,blob_xn=0;
    int gate_ok=vm_walk(r->vm_ttbr1,XNU_VM_GATE_VA,r->vm_first_avail,&gate_pa,&r->vm_gate_leaf,&gate_xn);
    int blob_ok=vm_walk(r->vm_ttbr1,configured.blob_va,r->vm_first_avail,&blob_pa,&r->vm_blob_leaf,&blob_xn);
    r->vm_verified=r->vm_gate_entered==1 && r->vm_gate_completed==1 && r->vm_gate_kind==UINT64_MAX &&
        r->vm_gate_pc==XNU_VM_GATE_VA && r->vm_ttbr0==XNU_VM_INVALID_ROOT_PA && r->vm_ttbr1==XNU_VM_CPU_ROOT_PA &&
        r->vm_restored_ttbr0==r->mmu.guard_ttbr0 && r->vm_restored_ttbr1==r->mmu.guard_ttbr1 &&
        r->vm_tcr==XNU_EXPECTED_TCR && r->vm_mair==XNU_EXPECTED_MAIR && (r->vm_sctlr&0x1005)==0x1005 &&
        r->vm_avail_start==r->vm_first_avail && r->vm_first_avail>XNU_VM_CPU_ROOT_PA &&
        r->vm_first_avail<=XNU_VM_MAX_ALLOC_PA && !(r->vm_first_avail&0xfff) && r->vm_kva_active==1 &&
        r->vm_soc_valid==1 && r->restored_cntkctl==r->saved.cntkctl &&
        gate_ok && blob_ok && gate_pa==XNU_PHYS_BASE+XNU_VM_GATE_VA-XNU_LINK_BASE && !gate_xn &&
        blob_pa==blob && blob_xn;
    if(!r->vm_verified) { r->status=24;goto done; }
    /* M=0: inspect captured RAM and bounded original XNU page-table pages only. */
    if(r->io.magic!=IO_MAGIC || r->io.status!=IO_STATUS_COMPLETE || r->io.count!=IO_REGISTER_COUNT ||
       r->io.pc!=XNU_IO_SNAPSHOT_GATE_VA || r->io.sp!=XNU_OBS_SP0_VA || r->io.bytes!=IO_GCC_BYTES ||
       r->io.startup>5 || r->io.stage!=2 || (r->io.par&1) || (r->io.par>>56)!=0 ||
       (r->io.par&0x0000fffffffff000UL)!=IO_GCC_PA ||
       r->io.va<0xffffffc000000000UL || (r->io.va&0xfff) || r->io.va+IO_GCC_BYTES<r->io.va ||
       r->io.va!=((r->io.vss_before+0xfff)&~0xfffUL) || r->io.vss_before+0xfff<r->io.vss_before ||
       r->io.vss_after!=r->io.va+IO_GCC_BYTES) { r->status=25;goto done; }
    static const uint32_t io_offsets[IO_REGISTER_COUNT]={0xf004,0xf010,0xf014,0xf018,0xf078,0xf07c,0xf050,0x8c028};
    for(unsigned i=0;i<IO_REGISTER_COUNT;++i)
        if(r->io.values[i].offset!=io_offsets[i] || io_offsets[i]+4>IO_GCC_BYTES) { r->status=25;goto done; }
    for(uint64_t delta=0;delta<IO_GCC_BYTES;delta+=0x1000) {
        uint64_t pa=0,leaf=0,xn=0;
        if(!vm_walk(r->vm_ttbr1,r->io.va+delta,r->vm_first_avail,&pa,&leaf,&xn) ||
           pa!=IO_GCC_PA+delta || (leaf&3)!=3 || ((leaf>>2)&7)!=3 || ((leaf>>6)&3)!=0 ||
           !(leaf&(1UL<<10)) || !xn || !(leaf&(1UL<<54)) || ((r->vm_mair>>24)&255)!=0) {
            r->status=26;goto done;
        }
        ++r->io_pages_verified;
    }
    r->io_verified=r->io_pages_verified==IO_GCC_BYTES/0x1000;
    if(!r->io_verified) { r->status=26;goto done; }
    if(r->usb.magic!=USB_MAGIC || r->usb.status!=2 || r->usb.stage!=2 || r->usb.count!=5 ||
       r->usb.coherent!=1 || r->usb.reason || (r->usb.bcr&1) || (r->usb.par&1) || (r->usb.par>>56) ||
       (r->usb.par&0x0000fffffffff000UL)!=USB_CORE_PA ||
       r->usb.va!=r->io.vss_after || (r->usb.va&0xfff) || r->usb.va+USB_CORE_BYTES<r->usb.va ||
       r->usb.vss_before!=r->usb.va || r->usb.vss_after!=r->usb.va+USB_CORE_BYTES ||
       ((r->usb.gsnpsid>>16)!=0x5533 && (r->usb.gsnpsid>>16)!=0x3331) ||
       ((r->usb.hwparams0&3)!=0 && (r->usb.hwparams0&3)!=2) ||
       ((r->usb.gctl>>12)&3)!=2 || (r->usb.gctl&(1UL<<11)) || (r->usb.dctl&(1UL<<30))) { r->status=27;goto done; }
    uint64_t usb_pa=0,usb_leaf=0,usb_xn=0;
    r->usb_page_verified=vm_walk(r->vm_ttbr1,r->usb.va,r->vm_first_avail,&usb_pa,&usb_leaf,&usb_xn) &&
        usb_pa==USB_CORE_PA && (usb_leaf&3)==3 && ((usb_leaf>>2)&7)==3 && ((usb_leaf>>6)&3)==0 &&
        (usb_leaf&(1UL<<10)) && usb_xn && (usb_leaf&(1UL<<54));
    r->usb_verified=r->usb_page_verified;
    if(!r->usb_verified) { r->status=28;goto done; }
    if(r->smmu.magic!=0x303131504d4d5553ULL || r->smmu.status!=SMMU_REC_STATUS_COMPLETE ||
       r->smmu.stage!=SMMU_REC_STAGE_ROWS || r->smmu.count>SMMU_REC_MAX_ROWS ||
       (r->smmu.va&0xfff) || (r->smmu.par&1) || (r->smmu.par>>56) ||
       (r->smmu.par&0x0000fffffffff000ULL)!=SMMU_REC_PA ||
       r->smmu.vss_after!=r->smmu.va+SMMU_REC_BYTES ||
       r->smmu.scr0!=r->smmu.scr0_2 || r->smmu.idr0!=r->smmu.idr0_2 || r->smmu.idr1!=r->smmu.idr1_2)
        { r->status=29;goto done; }
    for(unsigned i=0;i<SMMU_REC_MAX_ROWS;++i)
        if(i<r->smmu.count && r->smmu_rows1[i]!=r->smmu_rows2[i]) { r->status=29;goto done; }
    r->smmu_verified=1;
    r->status=0;
done:
    phase_end();
    r->elapsed_ticks=ticks()-started;
}

void xnu_append_log(const struct xnu_result *r) {
    value("xnu_status",r->status);value("xnu_attempted",r->attempted);value("xnu_returned",r->capture.returned);
    value("xnu_window_used",r->window_used);value("xnu_phys_base",XNU_PHYS_BASE);value("xnu_window_size",XNU_WINDOW_SIZE);
    value("xnu_source_crc32",r->source_crc32);value("xnu_source_offset",r->source_offset);
    value("xnu_copied",r->copied);value("xnu_zeroed",r->zeroed);value("xnu_elapsed_ticks",r->elapsed_ticks);
    value("xnu_args",r->args);value("xnu_entry",r->entry);value("xnu_gate",r->gate);
    value("xnu_x0",r->capture.x0);value("xnu_x20",r->capture.x20);value("xnu_x21",r->capture.x21);
    value("xnu_sp_before",r->capture.sp_before);value("xnu_sp_after",r->capture.sp_after);
    value("xnu_vbar_before",r->capture.vbar_before);value("xnu_vbar_after",r->capture.vbar_after);
    value("xnu_sctlr_before",r->capture.sctlr_before);value("xnu_sctlr_after",r->capture.sctlr_after);
    value("xnu_nzcv_before",r->capture.nzcv_before);value("xnu_nzcv_after",r->capture.nzcv_after);
    value("xnu_daif_before",r->capture.daif_before);value("xnu_daif_after",r->capture.daif_after);
    value("xnu_oslsr_before",r->capture.oslsr_before);value("xnu_oslsr_after",r->capture.oslsr_after);
    value("xnu_budget_ms",r->budget_ms);value("xnu_phase",r->phase);value("xnu_segment",r->segment);
    value("xnu_phase_bytes",r->phase_bytes);value("xnu_phase_total",r->phase_total);value("xnu_phase_ticks",r->phase_ticks);
    value("xnu_source_crc_ticks",r->source_crc_ticks);value("xnu_cache_ticks",r->cache_ticks);
    value("xnu_copy_ticks",r->copy_ticks);value("xnu_zero_ticks",r->zero_ticks);
    value("xnu_verify_crc_ticks",r->verify_crc_ticks);value("xnu_verify_zero_ticks",r->verify_zero_ticks);
    value("mmu_context_pa",r->context_pa);value("mmu_blob_crc32",r->bridge_crc32);value("mmu_adt_crc32",r->adt_crc32);
    value("mmu_config_verified",r->config_verified);value("mmu_state_verified",r->state_verified);
    value("mmu_status",r->mmu.status);value("mmu_phase",r->mmu.phase);
    value("mmu_entered",r->mmu.entered);value("mmu_returned",r->mmu.returned);
    value("mmu_guard_entered",r->mmu.guard_entered);value("mmu_guard_passed",r->mmu.guard_passed);
    value("mmu_guard_checks",r->mmu.guard_checks);value("mmu_guard_failure_va",r->mmu.guard_failure_va);
    value("mmu_guard_failure_descriptor",r->mmu.guard_failure_descriptor);
    value("mmu_observer_pc",r->mmu.observer_pc);value("mmu_identity_pc",r->mmu.identity_pc);value("mmu_x30",r->mmu.x30);
    value("mmu_sp_el0",r->mmu.sp_el0);value("mmu_sp_el1",r->mmu.sp_el1);value("mmu_spsel",r->mmu.spsel);
    value("mmu_sctlr",r->mmu.sctlr);value("mmu_tcr",r->mmu.tcr);value("mmu_ttbr0",r->mmu.ttbr0);
    value("mmu_ttbr1",r->mmu.ttbr1);value("mmu_mair",r->mmu.mair);value("mmu_vbar",r->mmu.vbar);
    value("mmu_par_code",r->mmu.par_code);value("mmu_par_args",r->mmu.par_args);
    value("mmu_par_sp0",r->mmu.par_sp0);value("mmu_par_sp1",r->mmu.par_sp1);value("mmu_par_identity",r->mmu.par_identity);
    value("mmu_after_mmu_pc",r->after_mmu_pc);value("mmu_after_mmu_sctlr",r->after_mmu_sctlr);value("mmu_after_mmu_vbar",r->after_mmu_vbar);
    value("mmu_exception_slot",r->mmu.exception_slot);value("mmu_fault_depth",r->mmu.fault_depth);
    value("mmu_esr",r->mmu.esr);value("mmu_far",r->mmu.far);value("mmu_elr",r->mmu.elr);value("mmu_spsr",r->mmu.spsr);
    value("mmu_guard_ttbr0",r->mmu.guard_ttbr0);value("mmu_guard_ttbr1",r->mmu.guard_ttbr1);
    value("mmu_restored_tcr",r->mmu.restored_tcr);value("mmu_saved_tcr",r->saved.tcr);
    value("mmu_restored_ttbr0",r->mmu.restored_ttbr0);value("mmu_saved_ttbr0",r->saved.ttbr0);
    value("mmu_restored_ttbr1",r->mmu.restored_ttbr1);value("mmu_saved_ttbr1",r->saved.ttbr1);
    value("mmu_restored_mair",r->mmu.restored_mair);value("mmu_saved_mair",r->saved.mair);
    value("mmu_restored_sp0",r->mmu.restored_sp0);value("mmu_saved_sp0",r->saved.sp_el0);
    value("mmu_restored_sp1",r->mmu.restored_sp1);value("mmu_saved_sp1",r->saved.sp_el1);
    value("mmu_restored_spsel",r->mmu.restored_spsel);value("mmu_saved_spsel",r->saved.spsel);
    value("mmu_bootstrap_fatal",r->mmu.bootstrap_fatal);value("mmu_budget_expired",r->mmu.budget_expired);
    value("mmu_pfr1",r->pfr1);value("mmu_mmfr2",r->mmfr2);value("mmu_features",r->saved.features);
    value("mmu_saved_pan",r->saved.pan);value("mmu_restored_pan",r->mmu.restored_pan);
    value("mmu_saved_uao",r->saved.uao);value("mmu_restored_uao",r->mmu.restored_uao);
    value("vm_gate_entered",r->vm_gate_entered);
    value("vm_gate_kind",r->vm_gate_kind);
    value("vm_gate_pc",r->vm_gate_pc);
    value("vm_ttbr0",r->vm_ttbr0);
    value("vm_ttbr1",r->vm_ttbr1);
    value("vm_cntkctl",r->vm_cntkctl);
    value("vm_nzcv",r->vm_nzcv);
    value("vm_daif",r->vm_daif);
    value("vm_sctlr",r->vm_sctlr);
    value("vm_tcr",r->vm_tcr);
    value("vm_mair",r->vm_mair);
    value("vm_restored_ttbr0",r->vm_restored_ttbr0);
    value("vm_restored_ttbr1",r->vm_restored_ttbr1);
    value("vm_gate_completed",r->vm_gate_completed);
    value("restored_cntkctl",r->restored_cntkctl);
    value("vm_avail_start",r->vm_avail_start);
    value("vm_first_avail",r->vm_first_avail);
    value("vm_kva_active",r->vm_kva_active);
    value("vm_cpu_tte",r->vm_cpu_tte);
    value("vm_invalid_tte",r->vm_invalid_tte);
    value("vm_physmap_base",r->vm_physmap_base);
    value("vm_physmap_end",r->vm_physmap_end);
    value("vm_soc_valid",r->vm_soc_valid);
    value("vm_gate_leaf",r->vm_gate_leaf);
    value("vm_blob_leaf",r->vm_blob_leaf);
    value("vm_verified",r->vm_verified);
    value("vm_saved_cntkctl",r->saved.cntkctl);
    value("usb_schema",1);value("usb_page_verified",r->usb_page_verified);value("usb_verified",r->usb_verified);
    value("usb_magic",r->usb.magic);
    value("usb_status",r->usb.status);
    value("usb_stage",r->usb.stage);
    value("usb_count",r->usb.count);
    value("usb_bcr",r->usb.bcr);
    value("usb_va",r->usb.va);
    value("usb_par",r->usb.par);
    value("usb_vss_before",r->usb.vss_before);
    value("usb_vss_after",r->usb.vss_after);
    value("usb_gsnpsid",r->usb.gsnpsid);
    value("usb_hwparams0",r->usb.hwparams0);
    value("usb_gctl",r->usb.gctl);
    value("usb_dctl",r->usb.dctl);
    value("usb_dsts",r->usb.dsts);
    value("usb_coherent",r->usb.coherent);
    value("usb_reason",r->usb.reason);
    value("smmu_schema",1);value("smmu_verified",r->smmu_verified);
    value("smmu_magic",r->smmu.magic);value("smmu_reason",r->smmu.reason);
    value("smmu_status",r->smmu.status);value("smmu_stage",r->smmu.stage);
    value("smmu_count",r->smmu.count);value("smmu_va",r->smmu.va);value("smmu_par",r->smmu.par);
    value("smmu_vss_before",r->smmu.vss_before);value("smmu_vss_after",r->smmu.vss_after);
    value("smmu_scr0",r->smmu.scr0);value("smmu_idr0",r->smmu.idr0);value("smmu_idr1",r->smmu.idr1);
    value("smmu_scr0_2",r->smmu.scr0_2);value("smmu_idr0_2",r->smmu.idr0_2);value("smmu_idr1_2",r->smmu.idr1_2);
    value("smmu_row1_0",r->smmu.rows1[0]);value("smmu_row1_1",r->smmu.rows1[1]);
    value("smmu_row2_0",r->smmu.rows2[0]);value("smmu_row2_1",r->smmu.rows2[1]);
    value("smmu_rows_crc1",snapshot_crc(r->smmu_rows1,r->smmu.count*8));
    value("smmu_rows_crc2",snapshot_crc(r->smmu_rows2,r->smmu.count*8));
    value("io_schema",1);value("io_magic",r->io.magic);value("io_status",r->io.status);
    value("io_gate_pc",r->io.pc);value("io_sp",r->io.sp);value("io_vss_before",r->io.vss_before);
    value("io_map_va",r->io.va);value("io_map_pa",IO_GCC_PA);value("io_map_bytes",r->io.bytes);
    value("io_startup_phase",r->io.startup);value("io_par",r->io.par);value("io_read_count",r->io.count);
    value("io_vss_after",r->io.vss_after);value("io_stage",r->io.stage);
    value("io_pages_verified",r->io_pages_verified);value("io_verified",r->io_verified);
    value("io_offset_0",r->io.values[0].offset);value("io_value_0",r->io.values[0].value);
    value("io_offset_1",r->io.values[1].offset);value("io_value_1",r->io.values[1].value);
    value("io_offset_2",r->io.values[2].offset);value("io_value_2",r->io.values[2].value);
    value("io_offset_3",r->io.values[3].offset);value("io_value_3",r->io.values[3].value);
    value("io_offset_4",r->io.values[4].offset);value("io_value_4",r->io.values[4].value);
    value("io_offset_5",r->io.values[5].offset);value("io_value_5",r->io.values[5].value);
    value("io_offset_6",r->io.values[6].offset);value("io_value_6",r->io.values[6].value);
    value("io_offset_7",r->io.values[7].offset);value("io_value_7",r->io.values[7].value);
    value("c_fp_saved",r->fp_saved);value("c_fp_verified",r->fp_verified);
    value("c_q_before_crc32",r->q_before_crc32);value("c_q_after_crc32",r->q_after_crc32);
    value("c_fpcr_before",r->fpcr_before);value("c_fpcr_after",r->fpcr_after);
    value("c_fpsr_before",r->fpsr_before);value("c_fpsr_after",r->fpsr_after);
    value("c_pe_initialized",r->pe_initialized);value("c_pe_dt_head",r->pe_dt_head);
    value("c_pe_boot_args",r->pe_boot_args);value("c_pe_dt_size",r->pe_dt_size);
    value("c_dt_root",r->dt_root);value("c_dt_size",r->dt_size);value("c_dt_end",r->dt_end);
    value("c_dt_initialized",r->dt_initialized);value("c_soc_base",r->soc_base);
    value("c_timebase_frequency",r->timebase_frequency);value("c_dec_clock_rate",r->dec_clock_rate);
    value("c_boot_args_global_verified",r->boot_args_global_verified);
}
