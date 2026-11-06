/* Reno Ace P01: bounded CPU/entry probe, with one reserved ramoops record.
 * Own implementation from the documented ARM and Linux/Qualcomm interfaces.
 * No disk driver, partition writes, display programming or extra CPU startup.
 * PMIC boot-reason + IMEM select the next boot; PMIC PS_HOLD type requests a
 * warm reset. Retention and return still require a real hardware test.
 */
#include <stdint.h>
#ifndef PROBE_DELAY_MS
#define PROBE_DELAY_MS 3000
#endif
#define RSR(name) ({ uint64_t v; __asm__ volatile("mrs %0, " #name : "=r"(v)); v; })
#define RAMOOPS_BASE 0xb7e00000UL
#define RAMOOPS_BYTES 0x400000UL
#define RECORD_BYTES 0x40000UL
static char log_buffer[8192];
static unsigned log_length, record_allowed, exception_active;
static unsigned boot_reason_ready;
volatile uint32_t reset_fallback_allowed;
extern void reset_now(void) __attribute__((noreturn));
extern void reset_fallback(void) __attribute__((noreturn));
extern void probe_park(void) __attribute__((noreturn));

static uint32_t rd(uintptr_t p) { return *(volatile uint32_t *)p; }
static void wr(uintptr_t p, uint32_t v) { *(volatile uint32_t *)p = v; }
static uint32_t be32(uintptr_t p) {
    const volatile unsigned char *b = (const volatile unsigned char *)p;
    return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}
static int equal(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static void put(char c) { if (log_length < sizeof(log_buffer)-1) log_buffer[log_length++] = c; }
static void text(const char *s) { while (*s) put(*s++); }
static void number(const char *name, uint64_t v) {
    text(name); text("=0x");
    for (int shift = 60; shift >= 0; shift -= 4) {
        unsigned n = (unsigned)(v >> shift) & 15;
        put(n < 10 ? '0' + n : 'a' + n - 10);
    }
    put('\n');
}
static uint64_t ticks(void) { __asm__ volatile("isb"); return RSR(cntvct_el0); }
static void wait_ms(unsigned ms) {
    uint64_t end = ticks() + RSR(cntfrq_el0) / 1000 * ms;
    while (ticks() < end) __asm__ volatile("nop");
}

/* Check the *runtime* FDT before accessing the board's reserved log region.
 * Only the direct ramoops node under /reserved-memory is accepted.
 */
static int check_record(uintptr_t dt) {
    if (dt < 0x80000000UL || (dt & 3) || be32(dt) != 0xd00dfeed) return 0;
    uint32_t size = be32(dt+4), so = be32(dt+8), no = be32(dt+12);
    if (size < 40 || size > 0x200000 || so >= size || no >= size) return 0;
    uintptr_t p = dt+so, end = dt+size, strings = dt+no;
    unsigned depth = 0, reserved = 0, target = 0, compatible = 0, region = 0, record = 0, ecc_ok = 1;
    while (p+4 <= end) {
        uint32_t token = be32(p); p += 4;
        if (token == 1) {
            uintptr_t start = p;
            while (p < end && *(const volatile char *)p) ++p;
            if (p >= end) return 0;
            ++depth;
            if (depth == 2) reserved = equal((const char *)start, "reserved-memory");
            if (reserved && depth == 3) { target=1; compatible=region=record=0; ecc_ok=1; }
            p = (p+4)&~3UL;
        } else if (token == 2) {
            if (target && depth == 3) {
                if (compatible && region && record && ecc_ok) return 1;
                target=0;
            }
            if (!depth) return 0;
            --depth;
        } else if (token == 3) {
            if (p+8 > end) return 0;
            uint32_t n = be32(p), off = be32(p+4); p += 8;
            if (n > (uint32_t)(end-p) || off >= size-no) return 0;
            uintptr_t name_end = strings+off;
            while (name_end < end && *(const volatile char *)name_end) ++name_end;
            if (name_end == end) return 0;
            const char *name = (const char *)(strings+off);
            if (target && depth == 3) {
                if (equal(name,"compatible") && n == 8 && equal((const char *)p,"ramoops")) compatible=1;
                if (equal(name,"reg") && n == 16 && be32(p)==0 && be32(p+4)==RAMOOPS_BASE && be32(p+8)==0 && be32(p+12)==RAMOOPS_BYTES) region=1;
                if (equal(name,"record-size") && n == 4 && be32(p)==RECORD_BYTES) record=1;
                if (equal(name,"ecc-size") && (n != 4 || be32(p) != 0)) ecc_ok=0;
            }
            p = (p+n+3)&~3UL;
        } else if (token == 4) {
            continue;
        } else return 0;
    }
    return 0;
}

static void persist(void) {
    if (!record_allowed || log_length > RECORD_BYTES-12) return;
    volatile unsigned char *data=(volatile unsigned char *)(RAMOOPS_BASE+12);
    for (unsigned i=0; i<log_length; ++i) data[i]=(unsigned char)log_buffer[i];
    wr(RAMOOPS_BASE+4,log_length); wr(RAMOOPS_BASE+8,log_length);
    __asm__ volatile("dsb sy" ::: "memory");
    wr(RAMOOPS_BASE,0x43474244); /* PERSISTENT_RAM_SIG, no ECC in this DT. */
    __asm__ volatile("dsb sy" ::: "memory");
}

static int transfer(uintptr_t channel, uint32_t command) {
    wr(channel,command);
    uint64_t end=ticks()+RSR(cntfrq_el0)/10;
    do {
        uint32_t status=rd(channel+8);
        if (status&1) return status&14 ? -1:0;
    } while (ticks()<end);
    return -2;
}

static int pmic_read(uintptr_t observer, uint8_t offset, uint8_t *value) {
    if (transfer(observer,1U<<27 | (uint32_t)offset<<4)) return -1;
    *value=(uint8_t)rd(observer+0x18); return 0;
}
static int pmic_write(uintptr_t channel, uint8_t offset, uint8_t value) {
    wr(channel+0x10,value);
    return transfer(channel,(uint32_t)offset<<4);
}

static int select_bootloader(void) {
    const uintptr_t core=0xc440000, config=0xc40a000;
    uint32_t version=rd(core), count=rd(core+4)&0x7ff;
    if (version<0x50000000 || version>=0x70000000 || !count || count>512) return -1;
    /* PM8150 SID0, PON peripheral 0x08; only the apps-owned APID. */
    unsigned apid;
    for (apid=0; apid<count; ++apid)
        if (((rd(core+0x900+4*apid)>>8)&0xfff)==8 && (rd(config+0x700+4*apid)&7)==0) break;
    if (apid==count) return -2;
    uintptr_t obs=0xe600000+0x80UL*apid, ch=0xc600000+0x10000UL*apid;
    uint8_t before, after, ctl, ctl2;
    if (pmic_read(obs,0x8f,&before)) return -3;
    uint8_t desired=(before&1)|4;
    if (pmic_write(ch,0x8f,desired)) return -4;
    if (pmic_read(obs,0x8f,&after) || after!=desired) return -5;
    wr(0x146bf65c,0x77665500);
    __asm__ volatile("dsb sy" ::: "memory");
    boot_reason_ready=1;
    /* qpnp-power-on: disable PS_HOLD reset, wait >=500us, set type1,
     * then re-enable. Preserve every unrelated bit, and verify readback. */
    if (pmic_read(obs,0x5a,&ctl) || pmic_read(obs,0x5b,&ctl2)) return -6;
    if (pmic_write(ch,0x5b,ctl2&0x7f)) return -7;
    wait_ms(1);
    if (pmic_write(ch,0x5a,(ctl&0xf0)|1) || pmic_write(ch,0x5b,ctl2|0x80)) {
        (void)pmic_write(ch,0x5a,ctl); (void)pmic_write(ch,0x5b,ctl2); return -8;
    }
    uint8_t verify1,verify2;
    if (pmic_read(obs,0x5a,&verify1) || pmic_read(obs,0x5b,&verify2) || (verify1&15)!=1 || !(verify2&0x80)) {
        (void)pmic_write(ch,0x5a,ctl); (void)pmic_write(ch,0x5b,ctl2); return -9;
    }
    reset_fallback_allowed=1;
    return 0;
}

void probe_exception(uint64_t slot) {
    /* A fault in PSCI may use PS_HOLD once; a fault in that fallback must
     * park instead of recursively consuming the exception stack. */
    unsigned previous_exception=exception_active++;
    if (previous_exception>=2) probe_park();
    if (previous_exception==1) reset_fallback();
    number("exception_slot",slot);
    if (RSR(CurrentEL)==4) { number("esr_el1",RSR(esr_el1)); number("elr_el1",RSR(elr_el1)); number("far_el1",RSR(far_el1)); }
    else { number("esr_el2",RSR(esr_el2)); number("elr_el2",RSR(elr_el2)); number("far_el2",RSR(far_el2)); }
    persist();
    if (boot_reason_ready) reset_now();
    probe_park();
}

void probe_main(uintptr_t dt) {
    text("====0.0-D\nRENOACE-P01 entry\n");
    uint64_t el=RSR(CurrentEL), sctlr=el==4 ? RSR(sctlr_el1):RSR(sctlr_el2);
    /* Linux Image ABI requires MMU off. Do not use a PA through an unknown VA mapping. */
    if (sctlr&1) probe_park();
    record_allowed=check_record(dt);
    if (!record_allowed) probe_park();
    /* Prepare return before less essential CPU register reads. */
    number("dtb",dt); persist();
    int selected=select_bootloader();
    number("bootloader_reason_result",(uint64_t)(int64_t)selected); persist();
    if (selected) {
        if (boot_reason_ready) reset_now();
        probe_park();
    }
    number("dtb",dt); number("current_el",el>>2); number("sctlr",sctlr);
    number("midr",RSR(midr_el1)); number("mpidr",RSR(mpidr_el1));
    number("isar0",RSR(id_aa64isar0_el1)); number("isar1",RSR(id_aa64isar1_el1));
    number("mmfr0",RSR(id_aa64mmfr0_el1)); number("mmfr1",RSR(id_aa64mmfr1_el1));
    number("cntfrq",RSR(cntfrq_el0)); number("delay_ms",PROBE_DELAY_MS);
    persist();
    wait_ms(PROBE_DELAY_MS);
#if PROBE_DIRECT_PS_HOLD
    text("RENOACE-P01 DIRECT PS_HOLD reset\n");
#else
    text("RENOACE-P01 PSCI reset\n");
#endif
    persist(); reset_now();
}
