#!/usr/bin/env python3
"""Run the complete compiled P03 loader and bounded XNU entry in Unicorn.

The actual CRC instructions, copy/zero loops, gate validation and eight XNU
instructions execute. System registers/cache operations are modeled. Linux is
never executed: stop at its restored entry. No phone operation is performed.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import re
import struct
import sys
import time
import zlib

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"out/probe-test-deps"))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID, UC_PROT_READ, UcError
from unicorn import arm64_const as ar

OUT=ROOT/"out/xnu-entry-probe"
BUILD=json.loads((OUT/"build.json").read_text())
IMAGE=(OUT/"Image").read_bytes();ORIGINAL=(OUT/"original-linux.Image").read_bytes()
INITRD=(OUT/"ramdisk").read_bytes();XNU=BUILD["xnu"];XC=XNU["constants"]
S=BUILD["symbols"];C=BUILD["constants"]
KBASE=C["XNU_PHYS_BASE"];KBYTES=C["XNU_WINDOW_SIZE"]
MACHO=(ROOT/XNU["source"]).read_bytes()
FDT=(ROOT/"local-device/20261106T115059Z/live.dtb").read_bytes()
assert hashlib.sha256(IMAGE).hexdigest()==BUILD["image_sha256"]
assert hashlib.sha256(INITRD).hexdigest()==XNU["combined_ramdisk_sha256"]
assert hashlib.sha256(MACHO).hexdigest()==XNU["source_sha256"]
spec=importlib.util.spec_from_file_location("fdt_model",ROOT/"references/ios-flame/tools/fdt.py")
fdt=importlib.util.module_from_spec(spec);spec.loader.exec_module(fdt)


def locations(blob):
    so,no=struct.unpack_from(">II",blob,8);p=so;stack=[];out={}
    while True:
        token,=struct.unpack_from(">I",blob,p);p+=4
        if token==1:
            e=blob.index(0,p);stack.append(blob[p:e].decode());p=(e+4)&~3
        elif token==2:stack.pop()
        elif token==3:
            n,off=struct.unpack_from(">II",blob,p);p+=8
            name=blob[no+off:blob.index(0,no+off)].decode()
            out[("/"+"/".join(stack[1:]),name)]=(p,n);p=(p+n+3)&~3
        elif token==4:pass
        elif token==9:return out
        else:raise ValueError(token)


LOC=locations(FDT)
def fixture_for(initrd_base,conflict=False):
    b=bytearray(FDT)
    for prop,value in (("linux,initrd-start",initrd_base),("linux,initrd-end",initrd_base+len(INITRD))):
        at,n=LOC[("/chosen",prop)];assert n==8;struct.pack_into(">Q",b,at,value)
    if conflict:
        at,n=LOC[("/reserved-memory/hyp_mem","reg")];assert n==16
        struct.pack_into(">QQ",b,at,KBASE,KBYTES)
    return bytes(b)


SPECIAL={}
for line in (OUT/"disassembly.txt").read_text().splitlines():
    m=re.match(r"\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(\w+)\s*(.*)",line)
    if m and m[2].lower() in ("mrs","msr","dc","ic","dsb","isb","wfe"):
        SPECIAL[int(m[1],16)]=(m[2].lower(),m[3].split("//")[0].strip().lower())


def reg(name):return getattr(ar,"UC_ARM64_REG_"+name.upper())
def tree_semantics(blob):return {n.path:dict(n.props) for n in fdt.parse(blob).walk()}
def read_all_equals(uc,address,length,byte):
    for off in range(0,length,1<<20):
        size=min(1<<20,length-off)
        if uc.mem_read(address+off,size)!=bytes([byte])*size:return False
    return True


def run_case(name,base=0xa8880000,crc_bad=False,conflict=False,gate_bad=False,oslock=False,budget=False,no_crc=False,budget_bss=False,corrupt_bss=False):
    # Owning ABL's queried-window arithmetic; not a claim of future placement.
    window_end=(base-0x80000)+0x8000000
    ramdisk_base=window_end-((len(INITRD)+4095)&~4095)-4096
    dt=ramdisk_base-0x200000-4096
    fixture=fixture_for(ramdisk_base,conflict)
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    uc.mem_map(base,(len(IMAGE)+4095)&~4095);uc.mem_write(base,IMAGE)
    uc.mem_map(dt,(len(fixture)+4095)&~4095);uc.mem_write(dt,fixture);uc.mem_protect(dt,(len(fixture)+4095)&~4095,UC_PROT_READ)
    uc.mem_map(ramdisk_base,(len(INITRD)+4095)&~4095);uc.mem_write(ramdisk_base,INITRD)
    if crc_bad:
        at=ramdisk_base+XC["XNU_INITRD_OFFSET"]+0x1000
        value=uc.mem_read(at,1)[0];uc.mem_write(at,bytes([value^1]))
    uc.mem_protect(ramdisk_base,(len(INITRD)+4095)&~4095,UC_PROT_READ)
    high_used=not (crc_bad or conflict or oslock or budget or no_crc)
    if high_used:
        uc.mem_map(KBASE,KBYTES)
        fill=bytes([0xa5])*(1<<20)
        for off in range(0,KBYTES,1<<20):uc.mem_write(KBASE+off,fill)
    original_sp=0xb7500000
    uc.reg_write(ar.UC_ARM64_REG_PSTATE,5);uc.reg_write(ar.UC_ARM64_REG_SP,original_sp);uc.reg_write(ar.UC_ARM64_REG_X0,dt)
    state={"currentel":4,"sctlr_el1":0x30d00800,"sctlr_el2":0,
           "vbar_el1":0x83800000,"vbar_el2":0x83800800,"midr_el1":0x51df805e,"mpidr_el1":0x81000000,
           "id_aa64isar0_el1":0 if no_crc else 0x100010211120,"id_aa64isar1_el1":0x100001,
           "id_aa64mmfr0_el1":0x101122,"id_aa64mmfr1_el1":0x10212122,"cntfrq_el0":19200000,
           "ctr_el0":0x8444c004,"oslsr_el1":3 if oslock else 1,"daif":0}
    initial=dict(state);fault=[];events=[];trace=[];stop={"first":False,"reason":None};counter=0
    injection={"bss_zero_started":False,"bss_corrupted":False,"budget_injected":False}
    def forbidden_write(engine,access,address,size,value,user):
        # The only admitted original-kernel edits are restored code0/size.
        allowed=(base<=address and address+size<=base+4) or (base+16<=address and address+size<=base+24)
        if not allowed:fault.append(f"forbidden write {address:#x}+{size}");engine.emu_stop()
    # Native engine range filtering avoids per-store Python calls for139MiB BSS.
    uc.hook_add(UC_HOOK_MEM_WRITE,forbidden_write,begin=base,end=base+C["LINUX_EFFECTIVE_SIZE"]-1)
    if high_used:
        uc.hook_add(UC_HOOK_MEM_WRITE,forbidden_write,begin=KBASE+XC["XNU_ARGS_OFFSET"]+0x480,end=KBASE+KBYTES-1)
    def invalid(engine,access,address,size,value,user):
        fault.append(f"unmapped/protected {access} {address:#x}+{size}");return False
    uc.hook_add(UC_HOOK_MEM_INVALID,invalid)
    def linux_stop(engine,address,size,user):
        if not stop["first"]:stop["first"]=True;return
        stop["reason"]="restored-linux-entry";engine.emu_stop()
    uc.hook_add(UC_HOOK_CODE,linux_stop,begin=base,end=base)
    def parked(engine,address,size,user):stop["reason"]="unexpected-park";engine.emu_stop()
    uc.hook_add(UC_HOOK_CODE,parked,begin=base+S["chain_park"],end=base+S["chain_park"])
    def special(engine,address,size,operation):
        nonlocal counter
        mnemonic,operands=operation
        if mnemonic=="mrs":
            target,key=[x.strip() for x in operands.split(",",1)]
            if key=="spsel":value=engine.reg_read(ar.UC_ARM64_REG_PSTATE)&1
            elif key=="nzcv":value=engine.reg_read(ar.UC_ARM64_REG_NZCV)
            elif key=="cntvct_el0":
                if budget or (budget_bss and injection["bss_zero_started"]):
                    counter+=400000000
                    injection["budget_injected"]=True
                else:counter+=64
                value=counter
            else:value=state[key]
            engine.reg_write(reg(target),value)
        elif mnemonic=="msr":
            key,source=[x.strip() for x in operands.split(",",1)]
            value=int(source[1:],0) if source.startswith("#") else (0 if source in ("xzr","wzr") else engine.reg_read(reg(source)))
            if key=="spsel":engine.reg_write(ar.UC_ARM64_REG_PSTATE,(engine.reg_read(ar.UC_ARM64_REG_PSTATE)&~1)|(value&1))
            elif key=="nzcv":engine.reg_write(ar.UC_ARM64_REG_NZCV,value)
            elif key=="daifset":state["daif"]|=(value&15)<<6
            elif key=="daif":state["daif"]=value
            elif key=="oslar_el1":
                assert value==0 and not state["oslsr_el1"]&2,"non-idempotent OS lock operation"
            elif key in ("vbar_el1","vbar_el2"):state[key]=value
            else:raise AssertionError("unmodeled MSR "+key)
            events.append([address,mnemonic,key,value])
        elif mnemonic=="wfe":raise AssertionError("unexpected WFE")
        engine.reg_write(ar.UC_ARM64_REG_PC,address+4)
    for offset,op in SPECIAL.items():
        if offset==S["chain_park"]:continue
        uc.hook_add(UC_HOOK_CODE,special,user_data=op,begin=base+offset,end=base+offset)
    expected_trace=[KBASE+XC["XNU_ENTRY_OFFSET"]]+[KBASE+XC["XNU_FIRST_CPU_OFFSET"]+i*4 for i in range(7)]
    expected_bytes=[MACHO[XC["XNU_ENTRY_OFFSET"]:XC["XNU_ENTRY_OFFSET"]+4]]+[MACHO[XC["XNU_FIRST_CPU_OFFSET"]+i*4:XC["XNU_FIRST_CPU_OFFSET"]+i*4+4] for i in range(6)]+[bytes.fromhex("c0035fd6")]
    def xnu_instruction(engine,address,size,user):
        i=len(trace)
        assert i<len(expected_trace) and address==expected_trace[i],f"unexpected XNU instruction {address:#x}"
        assert bytes(engine.mem_read(address,4))==expected_bytes[i],"unexpected XNU/gate instruction bytes"
        trace.append(address)
    if high_used:
        uc.hook_add(UC_HOOK_CODE,xnu_instruction,begin=KBASE,end=KBASE+KBYTES-1)
        uc.hook_add(UC_HOOK_CODE,special,user_data=("msr","oslar_el1, xzr"),begin=KBASE+XC["XNU_FIRST_CPU_OFFSET"],end=KBASE+XC["XNU_FIRST_CPU_OFFSET"])
        uc.hook_add(UC_HOOK_CODE,special,user_data=("msr","daifset, #0xf"),begin=KBASE+XC["XNU_FIRST_CPU_OFFSET"]+4,end=KBASE+XC["XNU_FIRST_CPU_OFFSET"]+4)
    if gate_bad:
        def remove_gate(engine,address,size,user):engine.mem_write(KBASE+XC["XNU_GATE_OFFSET"],bytes.fromhex("00c018d5"))
        uc.hook_add(UC_HOOK_CODE,remove_gate,begin=base+S["xnu_validate_gate"],end=base+S["xnu_validate_gate"])
    data_segment=next(s for s in XNU["segments"] if s["name"]=="__DATA")
    large_bss=KBASE+data_segment["relative"]+data_segment["fil"]
    if budget_bss:
        def bss_progress(engine,access,address,size,value,user):
            # Trigger only after a real store beyond the first 64KiB of BSS.
            # The next counter check must refuse, preserve the window and
            # return through Linux without any XNU entry instruction.
            injection["bss_zero_started"]=True
        uc.hook_add(UC_HOOK_MEM_WRITE,bss_progress,begin=large_bss+0x10000,end=large_bss+0x10007)
    if corrupt_bss:
        def corrupt_readback(engine,address,size,user):
            start=engine.reg_read(ar.UC_ARM64_REG_X0)
            length=engine.reg_read(ar.UC_ARM64_REG_X1)
            if start==large_bss and length>0x10028 and not injection["bss_corrupted"]:
                # A non-first word past a 64KiB boundary exercises all-word OR.
                engine.mem_write(start+0x10020,struct.pack("<Q",1))
                injection["bss_corrupted"]=True
        uc.hook_add(UC_HOOK_CODE,corrupt_readback,begin=base+S["check_zero_bounded"],end=base+S["check_zero_bounded"])
    begin=time.monotonic()
    try:uc.emu_start(base,base+len(IMAGE),timeout=150_000_000,count=900_000_000)
    except UcError as exc:raise AssertionError(f"{name}: {exc}; {fault}") from exc
    elapsed=time.monotonic()-begin
    assert not fault,(name,fault)
    assert stop["reason"]=="restored-linux-entry",(name,stop,hex(uc.reg_read(ar.UC_ARM64_REG_PC)))
    assert bytes(uc.mem_read(base,len(ORIGINAL)))==ORIGINAL,name+": Linux changed"
    assert bytes(uc.mem_read(dt,len(fixture)))==fixture,name+": incoming FDT changed"
    assert uc.reg_read(ar.UC_ARM64_REG_SP)==original_sp and uc.reg_read(ar.UC_ARM64_REG_PSTATE)&1==1
    assert state["vbar_el1"]==initial["vbar_el1"] and state["sctlr_el1"]==initial["sctlr_el1"]
    assert all(uc.reg_read(reg("x"+str(i)))==0 for i in (1,2,3))
    ptr=uc.reg_read(ar.UC_ARM64_REG_X0);assert ptr==base+C["DTB_OFFSET"]
    total=struct.unpack(">I",uc.mem_read(ptr+4,4))[0];output=bytes(uc.mem_read(ptr,total))
    before=tree_semantics(fixture);after=tree_semantics(output);message=after["/chosen"].pop("renoace-probe-log")
    assert before==after,name+": unrelated FDT property changed"
    assert message.endswith(b"\0")
    data=message[:-1];crc_at=data.rfind(b"crc32=");assert crc_at>0
    assert zlib.crc32(data[:crc_at])==int(data[crc_at:].split(b"=",1)[1].strip(),16)
    assert data.startswith(b"RENOACE-XNU-ENTRY-P03\nbuild="+BUILD["build_id"].encode()+b"\n")
    vals={key:int(value,16) for key,value in (line.split("=",1) for line in data.decode().splitlines()[2:])}
    expected_status=8 if crc_bad else 4 if conflict else 12 if gate_bad else 3 if oslock else 7 if (budget or budget_bss) else 11 if corrupt_bss else 15 if no_crc else 0
    assert vals["xnu_status"]==expected_status,(name,vals["xnu_status"],expected_status)
    if expected_status==0:
        assert trace==expected_trace,(name,trace)
        assert vals["xnu_attempted"]==vals["xnu_returned"]==1
        assert vals["xnu_x0"]==KBASE+XC["XNU_VECTOR_OFFSET"] and vals["xnu_x20"]==KBASE+XC["XNU_ARGS_OFFSET"] and vals["xnu_x21"]==0
        for key in ("sp","vbar","sctlr","nzcv","daif","oslsr"):
            assert vals["xnu_"+key+"_before"]==vals["xnu_"+key+"_after"],(name,key)
        (OUT/"model-record.bin").write_bytes(message)
    else:
        assert not trace and vals["xnu_attempted"]==vals["xnu_returned"]==0,(name,trace)
    if XNU.get("diagnostics_version")==1:
        assert vals["xnu_budget_ms"]==XNU["budget_ms"]
        assert 0<=vals["xnu_phase_bytes"]<=vals["xnu_phase_total"]
        if expected_status==0:
            assert vals["xnu_phase"]==8 and vals["xnu_segment"]==10
            assert vals["xnu_phase_bytes"]==vals["xnu_phase_total"]==0
        if budget_bss:
            assert injection["bss_zero_started"] and injection["budget_injected"]
            assert vals["xnu_phase"]==4 and vals["xnu_segment"]==6
            assert 0<vals["xnu_phase_bytes"]<vals["xnu_phase_total"]
            assert vals["xnu_zeroed"]>0 and vals["xnu_window_used"]==1
        if corrupt_bss:
            assert injection["bss_corrupted"] and vals["xnu_phase"]==6
            assert vals["xnu_segment"]==6 and vals["xnu_window_used"]==1
    complete_load=high_used and not (budget_bss or corrupt_bss)
    if complete_load:
        for segment in XNU["segments"]:
            target=KBASE+segment["relative"];expected=bytearray(MACHO[segment["off"]:segment["off"]+segment["fil"]])
            if not gate_bad and segment["relative"]<=XC["XNU_GATE_OFFSET"]<segment["relative"]+segment["fil"]:
                offset=XC["XNU_GATE_OFFSET"]-segment["relative"];expected[offset:offset+4]=bytes.fromhex("c0035fd6")
            assert bytes(uc.mem_read(target,segment["fil"]))==expected,(name,segment["name"],"file bytes")
            assert read_all_equals(uc,target+segment["fil"],segment["mem"]-segment["fil"],0),(name,segment["name"],"BSS")
        tail=XC["XNU_ARGS_OFFSET"]+0x480
        assert read_all_equals(uc,KBASE+tail,KBYTES-tail,0xa5),name+": high-window sentinel modified"
        assert hashlib.sha256(uc.mem_read(ramdisk_base+XC["XNU_INITRD_OFFSET"],len(MACHO))).hexdigest()==XNU["source_sha256"]
    elif budget_bss:
        assert read_all_equals(uc,large_bss,0x10000,0),"budget case never completed its first BSS chunk"
        assert read_all_equals(uc,large_bss+data_segment["mem"]-data_segment["fil"]-0x10000,0x10000,0xa5),"budget case unexpectedly completed full BSS"
    elif corrupt_bss:
        assert bytes(uc.mem_read(large_bss+0x10020,8))==struct.pack("<Q",1)
    reservations=[];at=struct.unpack_from(">I",output,16)[0]
    while True:
        a,n=struct.unpack_from(">QQ",output,at);at+=16
        if not a and not n:break
        reservations.append((a,n))
    assert (KBASE,KBYTES) in reservations if high_used else (KBASE,KBYTES) not in reservations
    return {"name":name,"base":hex(base),"status":vals["xnu_status"],"trace":[hex(x) for x in trace],
            "elapsed_host_seconds":round(elapsed,3),"modeled_elapsed_ticks":vals["xnu_elapsed_ticks"],"message_sha256":hashlib.sha256(message).hexdigest(),
            "full_segment_and_BSS_check":complete_load,"source_initrd_readonly":True,"linux_restored":True,"injection":injection}


def main():
    results=[]
    for case in (dict(name="complete-loader-and-seven-instruction-entry"),dict(name="source-CRC-refusal",crc_bad=True),
                 dict(name="high-window-refusal",conflict=True),dict(name="private-gate-not-patched",gate_bad=True),
                 dict(name="OSLK-refusal",oslock=True),dict(name="budget-refusal",budget=True),dict(name="CRC-ISA-refusal",no_crc=True),
                 dict(name="budget-during-BSS",budget_bss=True),dict(name="BSS-readback-corruption",corrupt_bss=True)):
        result=run_case(**case);results.append(result);print("PASS",json.dumps(result),flush=True)
    report={"passed":True,"hardware_tested":False,"image_sha256":BUILD["image_sha256"],"build_id":BUILD["build_id"],
            "source_hashes":BUILD["source_hashes"],"test_source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "model_record_sha256":hashlib.sha256((OUT/"model-record.bin").read_bytes()).hexdigest(),"cases":results,
            "scope":"actual compiled full loader/copy/zero/CRC/gate plus seven original XNU instructions and RET; stop before restored Linux",
            "modeled_not_verified":["CPU/sysregister values","cache maintenance","physical exceptions","counter timing/performance","bootloader/hardware memory ownership"]}
    (OUT/"instruction-tests.json").write_text(json.dumps(report,indent=2)+"\n")
    print("PASS: all P03 full-loader model cases; no hardware execution",flush=True)


if __name__=="__main__":main()
