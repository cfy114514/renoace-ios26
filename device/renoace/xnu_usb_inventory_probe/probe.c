/* P02: append a CPU observation to a cloned runtime FDT, then enter Linux.
 * No reset, SMC, PMIC, GIC, USB, storage or display programming is performed.
 * All writes are confined to the expanded, loader-owned Image allocation.
 */
#include <stdint.h>
#include <stddef.h>
#include "layout.h"
#include "xnu_control.h"
#define RSR(r) ({ uint64_t v; __asm__ volatile("mrs %0, " #r : "=r"(v)); v; })
#define MAX_DEPTH 32
#define MAX_BANKS 32
#define LOG_CAPACITY 8192
extern unsigned char _dtb_buffer[];
volatile uint32_t chain_status;
static char message[LOG_CAPACITY];
static unsigned message_length;

struct frame {
    unsigned memory, reserved_root, reserved_child, chosen, ac, sc;
    uintptr_t reg;
    uint32_t reglen;
};
struct tree_info {
    uintptr_t dt;
    uint32_t total, structure, structure_size, strings, strings_size, reserve;
    uint32_t reserve_bytes, insertion;
    unsigned chosen, soc, bank_count, have_start, have_end, xnu_conflict;
    uint64_t initrd_start, initrd_end;
    struct bank banks[MAX_BANKS];
};

static uint32_t be32(uintptr_t a) {
    const volatile uint8_t *p=(const volatile uint8_t *)a;
    return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3];
}
static uint64_t be64(uintptr_t a) { return (uint64_t)be32(a)<<32 | be32(a+4); }
static void put32(uintptr_t a, uint32_t v) {
    volatile uint8_t *p=(volatile uint8_t *)a;
    p[0]=(uint8_t)(v>>24); p[1]=(uint8_t)(v>>16); p[2]=(uint8_t)(v>>8); p[3]=(uint8_t)v;
}
static void put64(uintptr_t a, uint64_t v) { put32(a,(uint32_t)(v>>32)); put32(a+4,(uint32_t)v); }
static uintptr_t align4(uintptr_t v) { return (v+3)&~3UL; }
static int equal(const char *a, const char *b) {
    while (*a && *a==*b) { ++a; ++b; }
    return *a==*b;
}
static int memory_name(const char *s) {
    const char *p="memory";
    while (*p) if (*s++!=*p++) return 0;
    return *s==0 || *s=='@';
}
static int overlap(uint64_t a, uint64_t n, uint64_t b, uint64_t m) {
    if (!n || !m) return 0;
    if (a+n<a || b+m<b) return 1;
    return a<b+m && b<a+n;
}
static int within(uint64_t a, uint64_t n, uint64_t b, uint64_t m) {
    return n && a+n>=a && m && b+m>=b && a>=b && a+n<=b+m;
}
static void copy_bytes(uintptr_t dst, uintptr_t src, uint32_t n) {
    volatile uint8_t *d=(volatile uint8_t *)dst;
    const volatile uint8_t *s=(const volatile uint8_t *)src;
    while (n--) *d++=*s++;
}
static void zero_bytes(uintptr_t dst, uint32_t n) {
    volatile uint8_t *d=(volatile uint8_t *)dst;
    while (n--) *d++=0;
}
void *memset(void *dst, int value, size_t n) {
    volatile uint8_t *p=dst;
    while(n--) *p++=(uint8_t)value;
    return dst;
}
void *memcpy(void *dst, const void *src, size_t n) {
    volatile uint8_t *d=dst;
    const volatile uint8_t *s=src;
    while(n--) *d++=*s++;
    return dst;
}
static uint32_t string_length(uintptr_t p, uintptr_t end) {
    uintptr_t start=p;
    while (p<end && *(const volatile uint8_t *)p) ++p;
    return p==end ? UINT32_MAX:(uint32_t)(p-start);
}
static int contained_in_bank(struct tree_info *t, uint64_t base, uint64_t size) {
    for (unsigned i=0;i<t->bank_count;++i)
        if (within(base,size,t->banks[i].base,t->banks[i].size)) return 1;
    return 0;
}

/* Parse first, write later. Accept this board's two-cell address/size binding.
 * Fixed reserved regions are checked conservatively even if status=disabled.
 */
static int inspect_tree(struct tree_info *t, uintptr_t dt, uintptr_t image) {
    if ((dt&7) || dt<0x80000000UL || dt>=0x280000000UL || be32(dt)!=0xd00dfeed) return 10;
    t->dt=dt; t->total=be32(dt+4); t->structure=be32(dt+8); t->strings=be32(dt+12);
    t->reserve=be32(dt+16); t->strings_size=be32(dt+32); t->structure_size=be32(dt+36);
    if (be32(dt+20)!=17 || be32(dt+24)>17 || t->total<40 || t->total>DTB_CAPACITY-LOG_CAPACITY-512) return 11;
    if (dt+t->total<dt || t->structure<40 || t->strings<40 || (t->structure&3) || (t->reserve&7) || t->reserve<40) return 12;
    if (!within(t->structure,t->structure_size,0,t->total) || !within(t->strings,t->strings_size,0,t->total)) return 13;
    if (overlap(t->structure,t->structure_size,t->strings,t->strings_size) || overlap(image,CHAIN_IMAGE_SIZE,dt,t->total)) return 14;
    uint32_t r=t->reserve;
    for (unsigned count=0;;++count,r+=16) {
        if (count>=1024 || r>t->total-16) return 15;
        uint64_t a=be64(dt+r), n=be64(dt+r+8);
        if (!a && !n) break;
        if (overlap(image,CHAIN_IMAGE_SIZE,a,n)) return 16;
        if (overlap(XNU_PHYS_BASE,XNU_WINDOW_SIZE,a,n)) t->xnu_conflict=1;
    }
    t->reserve_bytes=r-t->reserve;
    if (overlap(t->reserve,t->reserve_bytes+16,t->structure,t->structure_size) ||
        overlap(t->reserve,t->reserve_bytes+16,t->strings,t->strings_size)) return 17;

    struct frame frames[MAX_DEPTH]={0};
    unsigned depth=0, root_ac=0, root_sc=0, ended=0;
    uintptr_t p=dt+t->structure, end=p+t->structure_size;
    while (p+4<=end) {
        uint32_t token=be32(p); p+=4;
        if (token==1) {
            uint32_t len=string_length(p,end);
            if (len==UINT32_MAX || depth==MAX_DEPTH || align4(p+len+1)>end) return 18;
            struct frame *f=&frames[depth];
            f->memory=depth==1 && memory_name((const char *)p);
            f->reserved_root=depth==1 && equal((const char *)p,"reserved-memory");
            f->reserved_child=depth==2 && frames[depth-1].reserved_root;
            f->chosen=depth==1 && equal((const char *)p,"chosen");
            f->ac=root_ac; f->sc=root_sc; f->reg=0; f->reglen=0;
            p=align4(p+len+1);
            if (f->chosen) {
                if (t->chosen) return 19;
                t->chosen=1; t->insertion=(uint32_t)(p-(dt+t->structure));
            }
            ++depth;
        } else if (token==2) {
            if (!depth) return 20;
            struct frame *f=&frames[--depth];
            if ((f->memory || f->reserved_child) && f->reglen) {
                if (root_ac!=2 || root_sc!=2 || f->reglen%16) return 21;
                if (f->reserved_child && (frames[depth-1].ac!=2 || frames[depth-1].sc!=2)) return 22;
                for (uint32_t i=0;i<f->reglen;i+=16) {
                    uint64_t a=be64(f->reg+i), n=be64(f->reg+i+8);
                    if (a+n<a) return 23;
                    if (f->memory && n) {
                        if (t->bank_count==MAX_BANKS) return 24;
                        t->banks[t->bank_count++]=(struct bank){a,n};
                    }
                    if (f->reserved_child && overlap(image,CHAIN_IMAGE_SIZE,a,n)) return 25;
                    if (f->reserved_child && overlap(XNU_PHYS_BASE,XNU_WINDOW_SIZE,a,n)) t->xnu_conflict=1;
                }
            }
        } else if (token==3) {
            if (!depth || p+8>end) return 26;
            uint32_t len=be32(p), off=be32(p+4); p+=8;
            if (len>(uint32_t)(end-p) || off>=t->strings_size || align4(p+len)>end) return 27;
            uintptr_t name=dt+t->strings+off;
            if (string_length(name,dt+t->strings+t->strings_size)==UINT32_MAX) return 28;
            struct frame *f=&frames[depth-1];
            if (equal((const char *)name,"#address-cells")) {
                if (len!=4) return 29;
                f->ac=be32(p); if (depth==1) root_ac=f->ac;
            } else if (equal((const char *)name,"#size-cells")) {
                if (len!=4) return 29;
                f->sc=be32(p); if (depth==1) root_sc=f->sc;
            } else if (equal((const char *)name,"reg")) {
                f->reg=p; f->reglen=len;
            } else if (depth==1 && equal((const char *)name,"qcom,msm-id")) {
                if (len>=8 && be32(p)==339) t->soc=1;
            }
            if (f->chosen) {
                if (equal((const char *)name,"renoace-probe-log")) return 30;
                if (equal((const char *)name,"linux,initrd-start")) {
                    if (len!=4 && len!=8) return 31;
                    t->initrd_start=len==8?be64(p):be32(p); t->have_start=1;
                } else if (equal((const char *)name,"linux,initrd-end")) {
                    if (len!=4 && len!=8) return 31;
                    t->initrd_end=len==8?be64(p):be32(p); t->have_end=1;
                }
            }
            p=align4(p+len);
        } else if (token==4) {
            continue;
        } else if (token==9) {
            if (depth || p!=end) return 32;
            ended=1; break;
        } else return 33;
    }
    if (!ended || !t->chosen || !t->soc || root_ac!=2 || root_sc!=2) return 34;
    if (!t->have_start || !t->have_end || t->initrd_end<=t->initrd_start ||
        t->initrd_end-t->initrd_start!=NORMAL_RAMDISK_SIZE) return 35;
    if (overlap(image,CHAIN_IMAGE_SIZE,t->initrd_start,t->initrd_end-t->initrd_start)) return 36;
    if (!contained_in_bank(t,image,CHAIN_IMAGE_SIZE) || !contained_in_bank(t,dt,t->total) ||
        !contained_in_bank(t,t->initrd_start,t->initrd_end-t->initrd_start)) return 37;
    return 0;
}

static void put(char c) { if (message_length<LOG_CAPACITY-1) message[message_length++]=c; }
static void text(const char *s) { while (*s) put(*s++); }
void value(const char *key, uint64_t v) {
    text(key); text("=0x");
    for (int shift=60;shift>=0;shift-=4) { unsigned n=(unsigned)(v>>shift)&15; put(n<10?'0'+n:'a'+n-10); }
    put('\n');
}
static uint32_t crc32(const char *s, unsigned n) {
    uint32_t crc=0xffffffffU;
    while(n--) { crc^=(uint8_t)*s++; for(unsigned i=0;i<8;++i) crc=(crc>>1)^((0U-(crc&1))&0xedb88320U); }
    return ~crc;
}
static void invalidate(uintptr_t start, uintptr_t end) {
    uint64_t line=4UL<<((RSR(ctr_el0)>>16)&15);
    __asm__ volatile("dsb sy" ::: "memory");
    for(uintptr_t p=start&~(line-1);p<end;p+=line) __asm__ volatile("dc ivac, %0"::"r"(p):"memory");
    __asm__ volatile("dsb sy" ::: "memory");
}
static void clean(uintptr_t start, uintptr_t end) {
    uint64_t line=4UL<<((RSR(ctr_el0)>>16)&15);
    __asm__ volatile("dsb sy" ::: "memory");
    for(uintptr_t p=start&~(line-1);p<end;p+=line) __asm__ volatile("dc cvac, %0"::"r"(p):"memory");
    __asm__ volatile("dsb sy; isb" ::: "memory");
}

uintptr_t chain_main(uintptr_t dt, uintptr_t image) {
    struct tree_info t={0};
    chain_status=1;
    if ((image-LINUX_TEXT_OFFSET)&0x1fffffUL || image+CHAIN_IMAGE_SIZE<image) { chain_status=2; return dt; }
    int error=inspect_tree(&t,dt,image);
    if (error) { chain_status=(uint32_t)error; return dt; }
    uintptr_t out=(uintptr_t)_dtb_buffer;
    if (out!=image+DTB_OFFSET) { chain_status=38; return dt; }
    text("RENOACE-XNU-USB-P09\n");
    text("build=" CHAIN_BUILD_ID "\n");
    value("image",image); value("original_dtb",dt); value("log_dtb",out);
    value("initrd_start",t.initrd_start); value("initrd_end",t.initrd_end);
    value("current_el",RSR(CurrentEL)>>2); value("midr",RSR(midr_el1)); value("mpidr",RSR(mpidr_el1));
    value("isar0",RSR(id_aa64isar0_el1)); value("isar1",RSR(id_aa64isar1_el1));
    value("mmfr0",RSR(id_aa64mmfr0_el1)); value("mmfr1",RSR(id_aa64mmfr1_el1)); value("cntfrq",RSR(cntfrq_el0));
    struct xnu_input input={image,CHAIN_IMAGE_SIZE,dt,t.total,t.initrd_start,t.initrd_end,t.banks,t.bank_count,t.xnu_conflict};
    struct xnu_result result={0};
    xnu_control(&input,&result);
    xnu_append_log(&result);
    value("crc32",crc32(message,message_length)); message[message_length]=0;

    const char propname[]="renoace-probe-log";
    uint32_t propbytes=12+(uint32_t)align4(message_length+1);
    uint32_t roff=40, extra_reserve=result.window_used?48:32, soff=roff+t.reserve_bytes+extra_reserve;
    uint32_t ssize=t.structure_size+propbytes, noff=soff+ssize;
    uint32_t total=noff+t.strings_size+sizeof(propname);
    if (total>DTB_CAPACITY || total<noff) { chain_status=39; return dt; }
    invalidate(out,out+DTB_CAPACITY);
    copy_bytes(out,dt,40);
    put32(out+4,total); put32(out+8,soff); put32(out+12,noff); put32(out+16,roff);
    put32(out+32,t.strings_size+sizeof(propname)); put32(out+36,ssize);
    copy_bytes(out+roff,dt+t.reserve,t.reserve_bytes);
    put64(out+roff+t.reserve_bytes,image+LINUX_EFFECTIVE_SIZE);
    put64(out+roff+t.reserve_bytes+8,CHAIN_IMAGE_SIZE-LINUX_EFFECTIVE_SIZE);
    if(result.window_used) {
        put64(out+roff+t.reserve_bytes+16,XNU_PHYS_BASE);
        put64(out+roff+t.reserve_bytes+24,XNU_WINDOW_SIZE);
        zero_bytes(out+roff+t.reserve_bytes+32,16);
    } else zero_bytes(out+roff+t.reserve_bytes+16,16);
    copy_bytes(out+soff,dt+t.structure,t.insertion);
    uintptr_t prop=out+soff+t.insertion;
    put32(prop,3); put32(prop+4,message_length+1); put32(prop+8,t.strings_size);
    zero_bytes(prop+12,propbytes-12); copy_bytes(prop+12,(uintptr_t)message,message_length+1);
    copy_bytes(prop+propbytes,dt+t.structure+t.insertion,t.structure_size-t.insertion);
    copy_bytes(out+noff,dt+t.strings,t.strings_size);
    copy_bytes(out+noff+t.strings_size,(uintptr_t)propname,sizeof(propname));
    clean(out,out+total);
    chain_status=0;
    return out;
}
