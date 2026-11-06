#!/usr/bin/env python3
"""Execute the actual P02 tail in Unicorn, stopping BEFORE restored Linux runs.

Privileged register reads/writes and cache maintenance are explicit models.
These checks verify instruction/control/memory behavior, not real coherency,
ABL allocation, native CPU features, Android startup or physical exceptions.
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
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID, UcError
from unicorn import arm64_const as ar

OUT=ROOT/"out/chainprobe"
BUILD=json.loads((OUT/"build.json").read_text())
IMAGE=(OUT/"Image").read_bytes()
ORIGINAL=(OUT/"original-linux.Image").read_bytes()
FDT=(ROOT/"local-device/20261106T115059Z/live.dtb").read_bytes()
SYMS=BUILD["symbols"]; CONST=BUILD["constants"]
assert hashlib.sha256(IMAGE).hexdigest()==BUILD["image_sha256"]
assert hashlib.sha256(ORIGINAL).hexdigest()==BUILD["original_linux_sha256"]
spec=importlib.util.spec_from_file_location("fdt_inspector",ROOT/"references/ios-flame/tools/fdt.py")
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
            out[("/"+"/".join(stack[1:]),name)]=(p,n,p-4)
            p=(p+n+3)&~3
        elif token==4:pass
        elif token==9:return out
        else:raise ValueError(token)


LOC=locations(FDT)
def changed_property(path,name,value):
    at,n,_=LOC[(path,name)];assert len(value)==n
    b=bytearray(FDT);b[at:at+n]=value;return bytes(b)


def initrd_overlap_fixture(base):
    b=bytearray(FDT);start=base+CONST["DTB_OFFSET"]
    for key,value in (("linux,initrd-start",start),("linux,initrd-end",start+CONST["NORMAL_RAMDISK_SIZE"])):
        at,n,_=LOC[("/chosen",key)];assert n==8;struct.pack_into(">Q",b,at,value)
    return bytes(b)


def malformed_header_fixture():
    b=bytearray(FDT);struct.pack_into(">I",b,8,len(b)+4);return bytes(b)


def reserve_fixture(base):
    b=bytearray(FDT);roff=struct.unpack_from(">I",b,16)[0]
    assert b[roff:roff+16]==bytes(16)
    b[roff:roff]=struct.pack(">QQ",base+CONST["LINUX_EFFECTIVE_SIZE"],0x1000)
    for off in (4,8,12):struct.pack_into(">I",b,off,struct.unpack_from(">I",b,off)[0]+16)
    return bytes(b)


def existing_log_fixture():
    b=bytearray(FDT);no,=struct.unpack_from(">I",b,12);ns,=struct.unpack_from(">I",b,32)
    extra=b"renoace-probe-log\0";b[no+ns:no+ns]=extra
    struct.pack_into(">I",b,4,len(b));struct.pack_into(">I",b,32,ns+len(extra))
    _,_,nameoff=LOC[("/chosen","bootargs")];struct.pack_into(">I",b,nameoff,ns)
    return bytes(b)


SPECIAL={}
for line in (OUT/"disassembly.txt").read_text().splitlines():
    m=re.match(r"\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(\w+)\s*(.*)",line)
    if m and m[2].lower() in ("mrs","msr","dc","ic","dsb","isb","wfe"):
        SPECIAL[int(m[1],16)]=(m[2].lower(),m[3].split("//")[0].strip().lower())


def reg(name):return getattr(ar,"UC_ARM64_REG_"+name.upper())
def semantic_tree(blob):return {n.path:dict(n.props) for n in fdt.parse(blob).walk()}


def run_case(name,base=0xa8880000,el=1,spsel=1,fixture=FDT,dt=0xa3000000,success=False,park=False,sctlr=0,abort=False,double_abort=False):
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    uc.mem_map(base,len(IMAGE));uc.mem_write(base,IMAGE)
    if not (base<=dt and dt+len(fixture)<=base+len(IMAGE)):
        uc.mem_map(dt&~4095,((dt%4096+len(fixture)+4095)//4096)*4096)
    uc.mem_write(dt,fixture)
    original_sp=0xb7500000
    uc.reg_write(ar.UC_ARM64_REG_PSTATE,(el<<2)|spsel)
    uc.reg_write(ar.UC_ARM64_REG_SP,original_sp)
    uc.reg_write(ar.UC_ARM64_REG_X0,dt)
    state={"currentel":el<<2,"sctlr_el1":sctlr,"sctlr_el2":sctlr,
           "vbar_el1":0x83800000,"vbar_el2":0x83800800,"midr_el1":0x51df805e,
           "mpidr_el1":0x81000000,"id_aa64isar0_el1":0x10211120,"id_aa64isar1_el1":0x101001,
           "id_aa64mmfr0_el1":0x1122,"id_aa64mmfr1_el1":0x1100000,"cntfrq_el0":19200000,
           "ctr_el0":0x8444c004}
    initial=dict(state);events=[];writes=0;stop={"reason":None,"first":False};fault=[]
    def on_write(engine,access,address,size,value,user):
        nonlocal writes
        writes+=1
        permitted=(base<=address and address+size<=base+4) or (base+16<=address and address+size<=base+24) or (base+CONST["LINUX_EFFECTIVE_SIZE"]<=address and address+size<=base+len(IMAGE))
        if not permitted:
            fault.append(f"forbidden write {address:#x}+{size}");engine.emu_stop()
    uc.hook_add(UC_HOOK_MEM_WRITE,on_write)
    def invalid(engine,access,address,size,value,user):
        fault.append(f"unmapped/protected access {access} {address:#x}+{size}");return False
    uc.hook_add(UC_HOOK_MEM_INVALID,invalid)
    def stop_hook(engine,address,size,user):
        if not stop["first"]:stop["first"]=True;return
        stop["reason"]="restored-linux-entry";engine.emu_stop()
    uc.hook_add(UC_HOOK_CODE,stop_hook,begin=base,end=base)
    def parked(engine,address,size,user):stop["reason"]="park";engine.emu_stop()
    uc.hook_add(UC_HOOK_CODE,parked,begin=base+SYMS["chain_park"],end=base+SYMS["chain_park"])
    def special(engine,address,size,operation):
        mnemonic,operands=operation
        if mnemonic=="mrs":
            target,key=[x.strip() for x in operands.split(",",1)]
            value=(engine.reg_read(ar.UC_ARM64_REG_PSTATE)&1) if key=="spsel" else state[key]
            engine.reg_write(reg(target),value)
        elif mnemonic=="msr":
            key,source=[x.strip() for x in operands.split(",",1)]
            value=int(source[1:],0) if source.startswith("#") else engine.reg_read(reg(source))
            if key=="spsel":
                old=engine.reg_read(ar.UC_ARM64_REG_PSTATE)
                engine.reg_write(ar.UC_ARM64_REG_PSTATE,(old&~1)|(value&1))
            elif key=="daifset":pass
            elif key in ("vbar_el1","vbar_el2"):state[key]=value
            else:raise AssertionError("unmodeled MSR "+key)
            events.append([mnemonic,key,value])
        elif mnemonic in ("dc","ic"):
            events.append([mnemonic,operands])
        elif mnemonic=="wfe":raise AssertionError("unexpected WFE")
        engine.reg_write(ar.UC_ARM64_REG_PC,address+4)
    for offset,operation in SPECIAL.items():
        if offset==SYMS["chain_park"]:continue
        uc.hook_add(UC_HOOK_CODE,special,user_data=operation,begin=base+offset,end=base+offset)
    if abort:
        def inject(engine,address,size,user):engine.reg_write(ar.UC_ARM64_REG_PC,base+SYMS["chain_abort"])
        # After the real C prologue has changed its stack/callee-saved registers.
        point=base+SYMS["chain_main"]+0x40
        uc.hook_add(UC_HOOK_CODE,inject,begin=point,end=point)
        if double_abort:
            point=base+SYMS["chain_finish"]
            uc.hook_add(UC_HOOK_CODE,inject,begin=point,end=point)
    start=time.monotonic()
    try:uc.emu_start(base,base+len(IMAGE),timeout=50_000_000,count=60_000_000)
    except UcError as exc:raise AssertionError(f"{name}: {exc}; faults={fault}") from exc
    elapsed=time.monotonic()-start
    assert not fault,(name,fault)
    assert stop["reason"]==("park" if park else "restored-linux-entry"),(name,stop,hex(uc.reg_read(ar.UC_ARM64_REG_PC)))
    if not park:
        assert bytes(uc.mem_read(base,len(ORIGINAL)))==ORIGINAL,name+": original Linux changed"
        assert bytes(uc.mem_read(dt,len(fixture)))==fixture,name+": input FDT changed"
        assert uc.reg_read(ar.UC_ARM64_REG_SP)==original_sp,(name,"SP",hex(uc.reg_read(ar.UC_ARM64_REG_SP)))
        assert uc.reg_read(ar.UC_ARM64_REG_PSTATE)&1==spsel,name+": SPSel"
        assert state["vbar_el1"]==initial["vbar_el1"] and state["vbar_el2"]==initial["vbar_el2"],name+": VBAR"
        assert all(uc.reg_read(reg("x"+str(i)))==0 for i in (1,2,3)),name+": reserved arguments"
    pointer=uc.reg_read(ar.UC_ARM64_REG_X0)
    status=struct.unpack("<I",uc.mem_read(base+SYMS["chain_status"],4))[0]
    result={"name":name,"base":hex(base),"el":el,"spsel":spsel,"stop":stop["reason"],"chain_status":status,"guest_writes_checked":writes,"elapsed_seconds":round(elapsed,3)}
    if success:
        assert status==0 and pointer==base+CONST["DTB_OFFSET"],(name,status,hex(pointer))
        total=struct.unpack(">I",uc.mem_read(pointer+4,4))[0]
        output=bytes(uc.mem_read(pointer,total));before=semantic_tree(fixture);after=semantic_tree(output)
        message=after["/chosen"].pop("renoace-probe-log")
        if name=="EL1-SP1-relocated":
            (OUT/"model-record.bin").write_bytes(message)
        assert before==after,name+": unrelated FDT property changed"
        assert message.endswith(b"\0")
        data=message[:-1];crc_line=data.rfind(b"crc32=")
        expected=zlib.crc32(data[:crc_line]);got=int(data[crc_line:].split(b"=",1)[1].strip(),16)
        assert expected==got,name+": log CRC"
        assert data.startswith(b"RENOACE-CHAINPROBE-P02\nbuild="+BUILD["build_id"].encode()+b"\n")
        vals=dict(line.split("=",1) for line in data.decode().splitlines()[2:])
        assert int(vals["image"],16)==base and int(vals["original_dtb"],16)==dt
        assert int(vals["current_el"],16)==el and int(vals["midr"],16)==initial["midr_el1"]
        assert int(vals["isar1"],16)==initial["id_aa64isar1_el1"]
        roff=struct.unpack_from(">I",output,16)[0]
        assert struct.unpack_from(">QQ",output,roff)==(base+CONST["LINUX_EFFECTIVE_SIZE"],len(IMAGE)-CONST["LINUX_EFFECTIVE_SIZE"])
        result["log_crc32"]=f"{got:08x}";result["new_fdt_bytes"]=total
    elif not park:
        assert pointer==dt,(name,"fallback replaced original DT")
        assert status!=0 or abort,(name,"unexpected successful status")
    return result


def main():
    results=[]
    cases=[
        dict(name="EL1-SP1-relocated",success=True),
        dict(name="EL1-SP0-fallback-base",base=0x80080000,spsel=0,success=True),
        dict(name="EL2-SP1-relocated",el=2,success=True),
        dict(name="EL2-SP0-relocated",el=2,spsel=0,success=True),
        dict(name="input-DTB-overlap",dt=0xa8880000+CONST["DTB_OFFSET"]),
        dict(name="initrd-overlap",fixture=initrd_overlap_fixture(0xa8880000)),
        dict(name="reserved-memory-overlap",fixture=changed_property("/reserved-memory/hyp_mem","reg",struct.pack(">QQ",0xa8880000+CONST["LINUX_EFFECTIVE_SIZE"],0x1000))),
        dict(name="memreserve-overlap",fixture=reserve_fixture(0xa8880000)),
        dict(name="wrong-SoC",fixture=changed_property("/","qcom,msm-id",struct.pack(">II",340,0x20000))),
        dict(name="preexisting-log",fixture=existing_log_fixture()),
        dict(name="malformed-structure-offset",fixture=malformed_header_fixture()),
        dict(name="no-memory-bank",fixture=changed_property("/memory","reg",bytes(LOC[("/memory","reg")][1]))),
        dict(name="MMU-on-parks",sctlr=1,park=True),
        dict(name="D-cache-on-parks",sctlr=4,park=True),
        dict(name="exception-fallback",abort=True),
        dict(name="second-exception-parks",abort=True,double_abort=True,park=True),
    ]
    for case in cases:
        result=run_case(**case);results.append(result);print("PASS",json.dumps(result),flush=True)
    report={"passed":True,"hardware_tested":False,"image_sha256":BUILD["image_sha256"],"source_hashes":BUILD["source_hashes"],"test_source_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),"model_record_sha256":hashlib.sha256((OUT/"model-record.bin").read_bytes()).hexdigest(),"build_id":BUILD["build_id"],"cases":results,
            "scope":"actual compiled instructions from patched Image entry through restored entry; no Linux instruction executed",
            "modeled_not_verified":["CPU feature registers","EL register values and VBAR","cache maintenance and barriers","physical exception delivery","ABL allocation/peripheral state"]}
    (OUT/"instruction-tests.json").write_text(json.dumps(report,indent=2)+"\n")
    print("PASS: all bounded instruction-model cases; hardware_tested=false",flush=True)


if __name__=="__main__":main()
