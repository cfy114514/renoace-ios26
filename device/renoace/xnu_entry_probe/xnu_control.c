/* P03 entry control: full pinned Mach-O layout, seven original instructions,
 * then a RET substituted only in the private loaded RAM copy. No startup past
 * the VBAR gate, MMU change, storage operation, reset or peripheral access.
 */
#include <stddef.h>
#include <stdint.h>
#include "layout.h"
#include "xnu_control.h"
struct xnu_segment { uint64_t offset, memory_size, file_offset, file_size; uint32_t crc; };
#include "xnu_layout.h"
#define RSR(r) ({ uint64_t v; __asm__ volatile("mrs %0, " #r : "=r"(v)); v; })
_Static_assert(sizeof(struct xnu_capture)==128,"assembly capture layout");
_Static_assert(offsetof(struct xnu_capture,oslsr_after)==120,"assembly capture offset");
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
static void clean_gate(void) {
    /* C=0 throughout; prior invalidation prevents stale lines over stores.
     * The seven-instruction path only fetches these two 4KiB code pages. */
    uint64_t line=4UL<<((RSR(ctr_el0)>>16)&15);
    uintptr_t first=(XNU_PHYS_BASE+XNU_ENTRY_OFFSET)&~(line-1);
    uintptr_t end=XNU_PHYS_BASE+XNU_GATE_OFFSET+4;
    __asm__ volatile("dsb sy":::"memory");
    for(uintptr_t a=first;a<end;a+=line) __asm__ volatile("dc cvac, %0"::"r"(a):"memory");
    __asm__ volatile("dsb sy; ic iallu; dsb sy; isb":::"memory");
}

/* Separate, visible checkpoint for the model's gate-not-patched control. */
__attribute__((noinline)) int xnu_validate_gate(void) {
    if(*(volatile uint32_t *)(XNU_PHYS_BASE+XNU_ENTRY_OFFSET)!=0x140006daU) return 0;
    const volatile uint32_t *p=(const volatile uint32_t *)(XNU_PHYS_BASE+XNU_FIRST_CPU_OFFSET);
    for(unsigned i=0;i<6;++i) if(p[i]!=xnu_original_prefix[i]) return 0;
    return p[6]==0xd65f03c0U;
}

void xnu_control(const struct xnu_input *in,struct xnu_result *r) {
    active_result=r;phase_open=0;r->budget_ms=15000;
    r->status=1; /* EL gate */
    if(RSR(CurrentEL)!=4) return;
    if((RSR(sctlr_el1)&5)!=0) { r->status=2; return; }
    r->capture.oslsr_before=RSR(oslsr_el1);
    if(r->capture.oslsr_before&2) { r->status=3; return; }
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
    if(*(volatile uint32_t *)(src+XNU_GATE_FILE_OFFSET)!=0xd518c000U) { r->status=9; goto done; }

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
    r->entry=XNU_PHYS_BASE+XNU_ENTRY_OFFSET; r->gate=XNU_PHYS_BASE+XNU_GATE_OFFSET;
    phase_begin(7,XNU_SEGMENT_COUNT,0x480);
    if(invalidate_range(r->args,0x480) || zero_bounded(r->args,0x480)) { r->status=7; goto done; }
    volatile uint64_t *args=(volatile uint64_t *)r->args;
    *(volatile uint32_t *)r->args=0x00020002;
    args[1]=XNU_LINK_BASE;args[2]=XNU_PHYS_BASE;args[3]=XNU_WINDOW_SIZE;
    args[4]=XNU_PHYS_BASE+XNU_ARGS_OFFSET+0x4000;
    args[0x478/8]=XNU_WINDOW_SIZE;
    /* Gate goes into the loaded private copy only. The initrd file stays exact. */
    *(volatile uint32_t *)r->gate=0xd65f03c0U;
    clean_gate();
    if(!xnu_validate_gate()) { r->status=12; goto done; }
    if(expired()) { r->status=7; goto done; }
    if(RSR(oslsr_el1)&2) { r->status=3; goto done; }
    phase_begin(8,XNU_SEGMENT_COUNT,0);
    r->attempted=1;
    (void)xnu_gate_call(r->entry,r->args,&r->capture);
    if(!r->capture.returned) { r->status=13; goto done; }
    if(r->capture.x20!=r->args || r->capture.x21!=0 || r->capture.x0!=XNU_PHYS_BASE+XNU_VECTOR_OFFSET ||
       r->capture.sp_before!=r->capture.sp_after || r->capture.vbar_before!=r->capture.vbar_after ||
       r->capture.sctlr_before!=r->capture.sctlr_after || (r->capture.oslsr_after&2)) { r->status=14; goto done; }
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
}
