#!/usr/bin/env python3
"""Build the P07 original-MMU and full-arm_vm_init checkpoint OFFLINE. Never operates a phone.

Default output is a private experimental kernel payload for instruction-model review.
Packaging requires matching P07 native early-C, SIMD, primitive and integration evidence.
These offline checks do not constitute hardware execution or a firmware map.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import zlib
import os

ROOT=Path(__file__).resolve().parents[1]
_WINDOWS_NDK=Path("C:/Users/123/AppData/Local/Android/Sdk/ndk/30.0.14904198/toolchains/llvm/prebuilt/windows-x86_64/bin")
_LINUX_NDK=Path("/workspace/toolchains/android-ndk/android-ndk-r30-beta1/toolchains/llvm/prebuilt/linux-x86_64/bin")
NDK=Path(os.environ.get("RENOACE_NDK_BIN", os.environ.get("ANDROID_NDK_BIN", str(_WINDOWS_NDK if os.name == "nt" else _LINUX_NDK))))
sha=lambda data:hashlib.sha256(data).hexdigest()
XNU_SHA="c361eda7d383619ec76c814a4f2121955547fadaa8235131d6849aa14d995743"
P11_MODE="second-pe-fiq-timer-return-source-zero-base-rx-gate-v2"
_KERNEL_RELATIVE_CANDIDATES=(
    "out/cloud-kernel/42306878464/extracted/build/renoace/kernel/mach.development.bcm2837.unstripped.noctf",
    "out/cloud-kernel/42306878464/build/renoace/kernel/mach.development.bcm2837.unstripped.noctf",
)
def default_kernel_path():
    for relative in _KERNEL_RELATIVE_CANDIDATES:
        candidate=ROOT/relative
        if candidate.is_file():
            return candidate
    return ROOT/_KERNEL_RELATIVE_CANDIDATES[0]
KERNEL_PATH=default_kernel_path()
CHECKPOINT_VA=0xfffffff007b33e34
CHECKPOINT_FILE=0xb2fe34
GATE_VA=0xfffffff007500800
GATE_OFFSET=0x4fc800
KERNEL_SYMBOLS={"_serialmode","_arm_init","_start_first_cpu","common_start","_bootstrap_pagetables","_LowExceptionVectorBase","_ExceptionVectorsBase","_intstack_top","_excepstack_top",
                "_const_boot_args","_BootArgs","_PE_state","_DTRootNode","_DTSize","_DTEnd","_DTInitialized",
                "_gPESoCBasePhys","_gPESoCBasePhysValid","_gPESoCDeviceTypeBuffer","_gPEClockFrequencyInfo","_pe_identify_machine","_PE_init_platform", "_avail_start","_first_avail","_kva_active","_cpu_tte","_invalid_tte","_physmap_base","_physmap_end","_init_thread","_PAGE_SHIFT_CONST"}


def tool(ndk, name):
    """Resolve an LLVM tool from either the Windows or Linux NDK layout."""
    candidates = (ndk / name, ndk / (name + ".exe"))
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("missing LLVM tool: " + " or ".join(str(p) for p in candidates))


def require(condition,message):
    if not condition:raise ValueError(message)


def read_json(path):
    if not path.is_file():raise ValueError("required evidence missing: "+str(path))
    return json.loads(path.read_text())


def cpio_entries(data,start=0):
    """Read newc members without extracting or executing them."""
    at=start;entries=[];names=set()
    while True:
        require(at%4==0 and at+110<=len(data),"unaligned/truncated newc header")
        require(data[at:at+6] in (b"070701",b"070702"),"invalid newc magic")
        fields=[int(data[at+6+8*i:at+14+8*i],16) for i in range(13)]
        size,namesize=fields[6],fields[11]
        require(0<namesize<=4096 and at+110+namesize<=len(data),"invalid newc name extent")
        rawname=data[at+110:at+110+namesize]
        require(rawname[-1:]==b"\0" and b"\0" not in rawname[:-1],"invalid newc name")
        name=rawname[:-1].decode();body=(at+110+namesize+3)&~3
        require(body+size<=len(data),"truncated newc data")
        require(name not in names,"duplicate newc member")
        names.add(name)
        entries.append({"name":name,"mode":fields[1],"nlink":fields[4],"data_offset":body,
                        "bytes":size,"sha256":sha(data[body:body+size])})
        at=(body+size+3)&~3
        if name=="TRAILER!!!":
            require(size==0,"newc trailer has data")
            return entries,at


def validate_prepared(out,source):
    """Bind a compiled P07 candidate to current inputs; no model claims."""
    build=read_json(out/"build.json")
    image=(out/"Image").read_bytes();layout=build["xnu"];constants=layout["constants"]
    current={p.name:sha(p.read_bytes()) for p in source.iterdir() if p.suffix in (".S",".c",".h",".ld")}
    require(current==build["source_hashes"],"current P07 source differs from build")
    require(build["builder_sha256"]==sha(Path(__file__).read_bytes()),"P07 builder differs from compiled candidate")
    require(sha(image)==build["image_sha256"],"current Image identity mismatch")
    require(layout["source_sha256"]==XNU_SHA,"wrong XNU generation")
    macho=kernel_bytes();segments,symbols=kernel_symbols(macho)
    require(len({p["offset"] for p in layout["patches"]})==len(layout["patches"]),"kernel patch overlap")
    bridge=(out/"mmu_bridge.bin").read_bytes();raw=(out/"mmu_bridge.raw.bin").read_bytes();br=layout["bridge"]
    require(sha(bridge)==br["sha256"] and sha(raw)==br["raw_sha256"],"bridge input identity mismatch")
    repaired=bytearray(raw)
    require(len(br["resume_patches"])==3,"bridge must have three recorded resume patches")
    for item in br["resume_patches"]:
        off=item["blob_offset"]
        require(struct.unpack_from("<I",raw,off)[0]==item["original"],"bridge resume original mismatch")
        require(item["replacement"]==branch_word(constants["XNU_BLOB_OFFSET"]+off,item["target_kernel_offset"]),"wrong bridge resume target")
        struct.pack_into("<I",repaired,off,item["replacement"])
    require(repaired==bridge,"unexpected bridge mutation beyond three resumes")
    for name in ("mmu_bridge_start","mmu_bridge_vectors"):require(br["symbols"][name]==0,"bridge vector origin changed")
    for n in range(16):require(br["symbols"][f"mmu_bridge_fault_{n}"]==n*0x80,"bridge vector stride changed")
    require(br["symbols"]["mmu_bridge_context"]+0x1000==len(bridge)==br["symbols"]["mmu_bridge_end"]<=0x10000,"bridge context/end bounds changed")
    for patch in layout["patches"]:
        require(struct.unpack_from("<I",macho,patch["file_offset"])[0]==patch["original"],"kernel patch original mismatch")
        if patch["bridge_symbol"]:
            require(patch["replacement"]==branch_word(patch["offset"],constants["XNU_BLOB_OFFSET"]+br["symbols"][patch["bridge_symbol"]]),"kernel branch target mismatch")
        elif patch.get("gate_symbol"):
            require(patch["replacement"]==branch_word(constants["XNU_LINK_BASE"]+patch["offset"],br["gate"]["symbols"][patch["gate_symbol"]]),"gate branch target mismatch")
        elif "gate_word" in patch:
            gate_bytes=(out/"vm_gate.bin").read_bytes()
            require(sha(gate_bytes)==br["gate"]["sha256"] and patch["offset"]==GATE_OFFSET+patch["gate_word"] and patch["replacement"]==struct.unpack_from("<I",gate_bytes,patch["gate_word"])[0] and patch["original"]==0xd503201f,"unexpected gate data patch")
        else:require((patch["offset"],patch["replacement"]) == (0x501348,0xd503201f),"unexpected non-branch patch")
    adt=(out/"renoace.adt").read_bytes();args=(out/"boot-args.bin").read_bytes();seed=(out/"build-seed.bin").read_bytes()
    require(sha(adt)==layout["ADT"]["sha256"] and sha(args)==layout["boot_args"]["sha256"],"ADT/boot_args identity mismatch")
    validate_adt(adt,seed)
    require(len(seed)==256 and sha(seed)==layout["ADT"]["seed_sha256"],"persisted ADT seed changed")
    frozen=ROOT/"out/xnu-mmu-probe-attempt1/build-seed.bin"
    require(seed==frozen.read_bytes(),"P11 seed differs from frozen P04 seed")
    require(len(args)==0x480 and struct.unpack_from("<HH",args)==(2,2),"boot_args ABI mismatch")
    require(struct.unpack_from("<Q",args,0x60)[0]==constants["XNU_LINK_BASE"]+constants["XNU_ADT_OFFSET"] and struct.unpack_from("<I",args,0x68)[0]==len(adt),"boot_args ADT pointer/size mismatch")
    spec=importlib.util.spec_from_file_location("p07_validation_pack",ROOT/"tools/build_renoace_probe.py")
    pack=importlib.util.module_from_spec(spec);spec.loader.exec_module(pack)
    private=ROOT/"local-device/20261106T115059Z";manifest=read_json(private/"manifest.json")
    originals={}
    for name in ("boot","recovery"):
        data=(private/(name+".img")).read_bytes()
        require(sha(data)==manifest["files"][name+".img"]["sha256"],name+" backup changed")
        originals[name]=pack.unpack(data)
    normal=originals["boot"][1];recovery=originals["recovery"][1]
    require(normal["dtb"]==recovery["dtb"],"base boot/recovery DTBs differ")
    linux_decoder=zlib.decompressobj(31);linux=linux_decoder.decompress(normal["kernel"])
    require(linux_decoder.eof and linux_decoder.unused_data==normal["dtb"],"normal gzip/DTB arrangement changed")
    require(sha(linux)==build["original_linux_sha256"],"original Linux identity mismatch")
    restored=bytearray(image[:len(linux)])
    struct.pack_into("<I",restored,0,struct.unpack_from("<I",linux,0)[0]);struct.pack_into("<Q",restored,16,struct.unpack_from("<Q",linux,16)[0])
    require(restored==linux,"unexpected original-Linux byte mutation")
    decoder=zlib.decompressobj(31);payload=decoder.decompress((out/"Image.gz-dtb").read_bytes())
    require(decoder.eof and payload==image and decoder.unused_data==normal["dtb"],"P07 gzip/appended-DTB mismatch")
    rd=(out/"ramdisk").read_bytes();prefix=normal["ramdisk"]
    require(rd[:len(prefix)]==prefix and sha(rd)==layout["combined_ramdisk_sha256"],"normal initrd prefix or combined identity changed")
    gz=zlib.decompressobj(31);normal_cpio=gz.decompress(prefix)
    require(gz.eof and not gz.unused_data,"normal ramdisk must be one complete gzip stream")
    normal_entries,normal_end=cpio_entries(normal_cpio)
    require(not any(normal_cpio[normal_end:]),"unexpected data after original cpio trailer")
    archive=layout["archive_offset"]
    require(archive==(len(prefix)+3)&~3 and not any(rd[len(prefix):archive]),"raw archive alignment/padding changed")
    appended,end=cpio_entries(rd,archive)
    require([e["name"] for e in appended]==[".renoace-xnu-p11.macho","TRAILER!!!"] and not any(rd[end:]),"unexpected appended archive contents")
    member=appended[0]
    require(member["name"] not in {e["name"] for e in normal_entries},"appended file replaces an original initrd entry")
    require(member["mode"]==0o100444 and member["nlink"]==1,"appended member mode/link count changed")
    require(member["data_offset"]==layout["member_data_offset"]==constants["XNU_INITRD_OFFSET"] and member["bytes"]==len(macho),"Mach-O member layout mismatch")
    embedded=rd[member["data_offset"]:member["data_offset"]+member["bytes"]]
    require(embedded==macho and member["sha256"]==XNU_SHA and zlib.crc32(embedded)==constants["XNU_FILE_CRC32"],"Mach-O payload CRC/SHA mismatch")
    cpio={"passed":True,"scope":"fresh offline parse of actual P07 inputs; no initramfs execution",
          "build_id":build["build_id"],"image_sha256":build["image_sha256"],"combined_ramdisk_sha256":sha(rd),
          "normal_gzip_sha256":sha(prefix),"normal_gzip_bytes":len(prefix),"normal_entries":len(normal_entries),
          "archive_offset":archive,"padding_bytes":archive-len(prefix),"appended_entries":appended,
          "kernel_sha256":XNU_SHA,"base_DTB_sha256":sha(normal["dtb"]),"base_DTB_copies_identical":True}
    (out/"cpio-validation.json").write_text(json.dumps(cpio,indent=2)+"\n")
    prep={"passed":True,"hardware_tested":False,"scope":"fresh static P07 input/layout binding; not instruction-model or device execution",
          "build_id":build["build_id"],"image_sha256":sha(image),"source_hashes":current,"kernel_sha256":XNU_SHA,
          "bridge_sha256":sha(bridge),"bridge_resume_count":3,"kernel_patch_count":len(layout["patches"]),"vector_slots":16,
          "ADT_sha256":sha(adt),"cpio_validation_sha256":sha((out/"cpio-validation.json").read_bytes()),
          "package_gate":"BLOCKED: static validation alone cannot authorize P07 packaging"}
    (out/"prepare-validation.json").write_text(json.dumps(prep,indent=2)+"\n")
    return build,prep,cpio


def p07_package_evidence(out,source):
    build,prep,cpio=validate_prepared(out,source)
    model=read_json(out/"native-vm-tests.json")
    review=read_json(ROOT/"out/analysis/p07-independent-integration-review.json")
    for report,label in ((model,"native VM model"),(review,"independent integration review")):
        require(report.get("passed") is True and report.get("build_id")==build["build_id"] and report.get("image_sha256")==build["image_sha256"],label+" does not bind current candidate")
    require(model.get("native_mmu") is True and model.get("full_arm_vm_init_return") is True and model.get("translation_register_hooks") is False and model.get("virtual_alias_api_mappings") is False,"model lacks genuine full VM execution")
    require(model.get("positive_injections")==[] and model.get("negative_cases_passed") is True and model.get("caller_state_exact") is True and model.get("FP_SIMD_exact") is True and model.get("CNTKCTL_exact") is True,"model coverage incomplete")
    require(review.get("code_blockers")==[] and review.get("builder_sha256")==build["builder_sha256"] and review.get("all_patches_checked") is True and review.get("ABL_and_carrier_bounds") is True,"independent review incomplete")
    require(model.get("source_hashes")==build["source_hashes"] and model.get("test_source_sha256")==sha((source/"test_instructions.py").read_bytes()),"native model source/test binding changed")
    for rel,digest in model.get("dependency_hashes",{}).items():
        dependency=(ROOT/rel).resolve()
        require(dependency.is_relative_to(ROOT.resolve()) and sha(dependency.read_bytes())==digest,"native model dependency changed: "+rel)
    require(model.get("dependency_hashes"),"native model dependencies absent")
    expected_cases={"positive_native_full_vm","private_patch_refusal","source_crc_refusal","reserved_window_refusal","bad_table_descriptor","bounded_time_refusal","table_guard_deadline","injected_pre_mmu_fault","synthetic_post_vm_gate_fault"}
    cases=model.get("cases",[])
    require(len(cases)==len(expected_cases) and {c.get("name") for c in cases}==expected_cases and all(c.get("passed") is True and c.get("errors")==[] and c.get("native_faults")==[] for c in cases),"native model cases incomplete")
    reader_spec=importlib.util.spec_from_file_location("p07_gate_reader",ROOT/"tools/capture_renoace_chainprobe.py")
    reader=importlib.util.module_from_spec(reader_spec);reader_spec.loader.exec_module(reader)
    for case in cases:
        raw=(out/"model-tests/max"/(case["name"]+".bin")).read_bytes()
        parsed=reader.parse_record(raw,build["build_id"],build)
        require(sha(raw)==case["record"]["sha256"] and len(raw)==case["record"]["bytes"] and parsed["registers"]==case["record"]["fields"],"native raw-record identity mismatch: "+case["name"])
        if case["name"]=="positive_native_full_vm":
            require(parsed.get("xnu_vm_verified") is True and parsed.get("xnu_verification_failures")==[] and case.get("injections")==[],"full VM reader or positive no-injection check failed")
    primitive_path=ROOT/"out/xnu-vm-primitive-tests/results.json";primitive=read_json(primitive_path)
    require(primitive.get("build_id")==build["build_id"] and primitive.get("image_sha256")==build["image_sha256"] and primitive.get("source_hashes")==build["source_hashes"] and primitive.get("passed")==190 and primitive.get("failed")==0 and primitive.get("test_sha256")==sha((source/"test_primitives.py").read_bytes()),"190 compiled primitive checks missing/stale")
    unit_path=ROOT/"out/analysis/p07-vm-bridge-validation.json";unit=read_json(unit_path)
    require(unit.get("passed") is True and unit.get("build_id")==build["build_id"] and unit.get("image_sha256")==build["image_sha256"] and unit.get("CNTKCTL_nonzero_restore") is True and unit.get("all_16_high_fault_slots") is True,"ABI3/gate unit evidence missing/stale")
    return {"passed":True,"build_id":build["build_id"],"image_sha256":build["image_sha256"],"model":model,
        "model_sha256":sha((out/"native-vm-tests.json").read_bytes()),"review_sha256":sha((ROOT/"out/analysis/p07-independent-integration-review.json").read_bytes()),
        "primitive_sha256":sha(primitive_path.read_bytes()),"ABI3_gate_unit_sha256":sha(unit_path.read_bytes()),
        "reader_sha256":sha((ROOT/"tools/capture_renoace_chainprobe.py").read_bytes()),
        "prepare_validation_sha256":sha((out/"prepare-validation.json").read_bytes()),"cpio_validation_sha256":sha((out/"cpio-validation.json").read_bytes()),"hardware_tested":False}



def newc_entry(name,data,mode=0o100444):
    filename=name.encode()+b"\0"
    fields=[1,mode,0,0,1,0,len(data),0,0,0,0,len(filename),0]
    header=b"070701"+b"".join(f"{n:08x}".encode() for n in fields)+filename
    header+=bytes((-len(header))%4)
    return header+data+bytes((-len(data))%4),len(header)


def import_pinned(name,path,expected):
    if sha(path.read_bytes())!=expected:raise ValueError("pinned ADT helper changed: "+str(path))
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def kernel_bytes():
    data=KERNEL_PATH.read_bytes()
    require(sha(data)==XNU_SHA,"pinned fresh XNU source changed")
    return data


def kernel_symbols(data):
    """Read actual non-undefined nlist symbols, rejecting conflicting definitions."""
    require(struct.unpack_from("<4I",data)==(0xfeedfacf,0x100000c,0,2),"unexpected Mach-O identity")
    at=32;segments=[];symbol_command=None
    ncmds,command_bytes=struct.unpack_from("<II",data,16)
    for _ in range(ncmds):
        cmd,size=struct.unpack_from("<II",data,at)
        require(size>=8 and at+size<=32+command_bytes,"bad Mach-O command")
        if cmd==0x19:
            name=data[at+8:at+24].split(b"\0")[0].decode();va,mem,off,fil=struct.unpack_from("<4Q",data,at+24)
            if mem:segments.append(dict(name=name,va=va,mem=mem,off=off,fil=fil))
        if cmd==2:symbol_command=struct.unpack_from("<4I",data,at+8)
        at+=size
    require(symbol_command is not None,"missing Mach-O symbol table")
    so,ns,st,ss=symbol_command
    require(so+ns*16<=len(data) and st+ss<=len(data),"Mach-O symbol bounds")
    symbols={}
    for i in range(ns):
        index,typ,section,desc,address=struct.unpack_from("<IBBHQ",data,so+i*16)
        if not address or not typ&0xe or index>=ss:continue
        end=data.find(b"\0",st+index,st+ss)
        require(end>=0,"unterminated Mach-O symbol")
        name=data[st+index:end].decode(errors="replace")
        if name not in KERNEL_SYMBOLS:continue
        require(name not in symbols or symbols[name]==address,"conflicting symbol definition: "+name)
        symbols[name]=address
    require(set(symbols)==KERNEL_SYMBOLS,"required actual kernel symbols missing")
    return segments,symbols


def measured_bus():
    """Independently decode the captured FDT's complete /soc identity tuple."""
    measured_path=ROOT/"local-device/20261106T115059Z/live.dtb";data=measured_path.read_bytes()
    require(sha(data)=="1503f2b63781e634735f14ecd659abb40c70a2be3fe3e7820ac451a5bb912800","measured FDT changed")
    require(len(data)>=40,"truncated measured FDT")
    magic,total,off,strings,rsv,version,last,bootcpu,strsize,structsize=struct.unpack_from(">10I",data)
    require(magic==0xd00dfeed and total<=len(data) and off+structsize<=total and strings+strsize<=total,"measured FDT header bounds")
    cursor=off;end=off+structsize;stack=[];nodes={};ended=False
    while cursor+4<=end:
        token=struct.unpack_from(">I",data,cursor)[0];cursor+=4
        if token==1:
            stop=data.find(b"\0",cursor,end);require(stop>=0,"FDT node name truncated")
            name=data[cursor:stop].decode("ascii");cursor=(stop+4)&~3
            stack.append(name);path="/"+"/".join(stack[1:]);require(path not in nodes,"duplicate FDT path");nodes[path]={}
        elif token==2:
            require(bool(stack),"FDT unbalanced END_NODE");stack.pop()
        elif token==3:
            require(bool(stack) and cursor+8<=end,"FDT property outside node")
            length,nameoff=struct.unpack_from(">II",data,cursor);cursor+=8
            require(cursor+length<=end and nameoff<strsize,"FDT property bounds")
            stop=data.find(b"\0",strings+nameoff,strings+strsize);require(stop>=0,"FDT property name bounds")
            key=data[strings+nameoff:stop].decode("ascii");path="/"+"/".join(stack[1:])
            require(key not in nodes[path],"duplicate FDT property");nodes[path][key]=data[cursor:cursor+length];cursor=(cursor+length+3)&~3
        elif token==4:continue
        elif token==9:
            require(not stack,"FDT ended inside node");ended=True;break
        else:raise ValueError("unknown measured FDT token")
    require(ended,"measured FDT lacks END")
    root=nodes["/"];soc=nodes["/soc"]
    require(root["#address-cells"]==struct.pack(">I",2) and root["#size-cells"]==struct.pack(">I",2),"measured root cells changed")
    require(soc["#address-cells"]==struct.pack(">I",1) and soc["#size-cells"]==struct.pack(">I",1),"measured soc cells changed")
    require(len(soc["ranges"])==16,"measured soc single tuple changed")
    child,parent,length=struct.unpack(">IQI",soc["ranges"])
    require((child,parent,length)==(0,0,0xffffffff),"measured complete identity bus changed")
    return {"path":str(measured_path.relative_to(ROOT)),"sha256":sha(data),"tuple":[child,parent,length],"FDT_encoding":"BE cells 1/2/1","ADT_encoding":"LE u64/u64/u64"}


def validate_adt(data,seed):
    """Strict whole-tree parser independent of the imported ADT serializer."""
    def read(offset,parent,depth):
        require(depth<=16 and offset+8<=len(data),"ADT node truncated/deep")
        np,nc=struct.unpack_from("<II",data,offset);offset+=8
        require(np<=64 and nc<=64,"ADT node count exceeds bounds");props={}
        for _ in range(np):
            require(offset+36<=len(data),"ADT property header truncated")
            raw=data[offset:offset+32];require(b"\0" in raw,"ADT property name lacks terminator")
            key=raw.split(b"\0",1)[0].decode("ascii");length=struct.unpack_from("<I",data,offset+32)[0];offset+=36
            require(key and key not in props and length<0x80000000 and offset+length<=len(data),"ADT duplicate/placeholder/truncated property")
            stop=offset+length;padded=(stop+3)&~3
            require(padded<=len(data) and not any(data[stop:padded]),"ADT padding invalid")
            props[key]=data[offset:stop];offset=padded
        name=props.get("name",b"");require(name.endswith(b"\0") and b"\0" not in name[:-1],"invalid ADT node name")
        name=name[:-1].decode("ascii");path="/" if depth==0 else parent.rstrip("/")+"/"+name;found={path:props}
        for _ in range(nc):
            child,offset=read(offset,path,depth+1);require(not found.keys()&child.keys(),"duplicate ADT node");found.update(child)
        return found,offset
    nodes,end=read(0,"",0);require(end==len(data),"ADT trailing bytes")
    expected={"/","/chosen","/chosen/memory-map","/chosen/manifest-properties","/cpus","/cpus/cpu0","/psci","/defaults","/options","/product","/arm-io","/arm-io/intc"}
    require(set(nodes)==expected,"unexpected ADT nodes")
    require(nodes["/"]["name"]==b"device-tree\0","ADT root name mismatch")
    u32=lambda value:struct.pack("<I",value)
    for path in ("/","/arm-io"):
        require(nodes[path].get("#address-cells")==u32(2) and nodes[path].get("#size-cells")==u32(2),"ADT address/size cells must be LE2/2")
    bus=measured_bus();ranges=nodes["/arm-io"].get("ranges")
    require(ranges==struct.pack("<QQQ",*bus["tuple"]),"ADT must faithfully represent complete measured identity bus")
    require(nodes["/arm-io"].get("device_type")==b"arm-io\0","ADT device_type must be real NUL-terminated arm-io")
    require(nodes["/cpus/cpu0"].get("device_type")==b"cpu\0" and nodes["/cpus/cpu0"].get("state")==b"running\0" and nodes["/cpus/cpu0"].get("reg")==u32(0),"ADT must identify running CPU0")
    require(nodes["/cpus/cpu0"].get("timebase-frequency")==u32(19200000),"ADT measured 19.2MHz timebase missing")
    require(nodes["/chosen"].get("random-seed")==seed and len(seed)==256 and any(seed),"ADT persisted nonzero 256-byte seed mismatch")
    require(nodes["/arm-io/intc"].get("reg")==struct.pack("<4Q",0x17a00000,0x10000,0x17a60000,0x100000),"complete identity bus child GIC addresses mismatch")
    return {"passed":True,"parser":"independent strict bounded whole-tree reader","bytes":len(data),"nodes":len(nodes),"identity_bus":bus,
            "ranges_hex":ranges.hex(),"root_cells":[2,2],"arm_io_cells":[2,2],"running_cpu":0,"timebase_hz":19200000,
            "compatibility":"source checked zero-base API; measured complete identity bus"}


def make_adt(out,package=False):
    adt=import_pinned("p07_adt",ROOT/"references/ios-flame/tools/adt.py","43d91d2e4fb0a78190a610b4bab7c206489cdede797bfc37175fb2f18367ac00")
    zeta=import_pinned("p07_nvram",ROOT/"references/UniXNU-zeta/scripts/make-zeta-adt.py","0e8fd0343e7f15faacd0ea39b1547117e68ea0258431f37c5a5b79e5340ecf40")
    seed_path=out/"build-seed.bin"
    frozen=ROOT/"out/xnu-mmu-probe-attempt1/build-seed.bin"
    frozen_seed=frozen.read_bytes();require(len(frozen_seed)==256 and any(frozen_seed),"frozen P04 seed invalid")
    require(sha(frozen_seed)==read_json(frozen.parent/"build.json")["xnu"]["ADT"]["seed_sha256"],"frozen P04 seed identity mismatch")
    if not seed_path.exists():
        if package:raise ValueError("package requires the persisted build seed")
        with seed_path.open("xb") as stream:stream.write(frozen_seed)
    seed=seed_path.read_bytes()
    if seed!=frozen_seed:raise ValueError("persisted P07 seed differs from frozen P04 seed")
    u32=lambda n:struct.pack("<I",n);u64=lambda n:struct.pack("<Q",n)
    def node(name,properties=(),children=()):
        value=adt.Node();value.props=[("name",0,name.encode()+b"\0")]+[(k,0,v) for k,v in properties];value.children=list(children);return value
    command=b"cpus=1 serial=0 -v native-ufs-root=0 native-ufs-probe=0 sheng-smp=0\0"
    chosen=node("chosen",[("random-seed",seed),("kernel-ctrr-to-be-enabled",u32(0)),("boot-args",command),
        ("dram-base",u64(0x80000000)),("dram-size",u64(0x200000000)),("darwinboot-memory-size",u64(0x10000000)),
        *zeta.empty_nvram_proxy()],[node("memory-map"),node("manifest-properties")])
    tree=node("device-tree",[("model",b"OPPO Reno Ace\0"),("target-type",b"OP4A89\0"),
        ("compatible",b"oppo,renoace\0qcom,sm8150\0"),("#address-cells",u32(2)),("#size-cells",u32(2))],[
        chosen,node("cpus",[],[node("cpu0",[("device_type",b"cpu\0"),("state",b"running\0"),("reg",u32(0)),
        ("compatible",b"qcom,kryo485\0arm,cortex-a55\0"),("timebase-frequency",u32(19200000))])]),
        node("psci",[("compatible",b"arm,psci-1.0\0"),("method",b"smc\0")]),
        node("defaults",[("sleep-disabled",u32(1))]),node("options"),node("product",[("model",b"OPPO Reno Ace\0")]),
        node("arm-io",[("device_type",b"arm-io\0"),("#address-cells",u32(2)),("#size-cells",u32(2)),
        ("ranges",struct.pack("<QQQ",0,0,0xffffffff))],[node("intc",[("compatible",b"arm,gic-v3\0"),
        ("reg",struct.pack("<4Q",0x17a00000,0x10000,0x17a60000,0x100000)),("redistributor-stride",u64(0x20000))])])])
    data=adt.serialize(tree);again,end=adt.parse(data)
    if end!=len(data) or adt.serialize(again)!=data:raise ValueError("ADT roundtrip failed")
    if len(next(n for n in again.children if n.name=="chosen").prop("random-seed"))!=256:raise ValueError("ADT seed missing")
    validation=validate_adt(data,seed)
    (out/"adt-validation.json").write_text(json.dumps(validation,indent=2)+"\n")
    (out/"renoace.adt").write_bytes(data)
    return data,command,sha(seed)


def branch_word(source,target):
    delta=target-source
    if delta%4 or not -0x8000000<=delta<0x8000000:raise ValueError("branch out of range")
    return 0x14000000|((delta//4)&0x3ffffff)


def build_bridge(source,out,ndk,run):
    obj=out/"mmu_bridge.o";elf=out/"mmu_bridge.elf";raw=out/"mmu_bridge.raw.bin"
    run([tool(ndk, "clang"),"--target=aarch64-none-elf","-mcpu=cortex-a55","-ffreestanding","-nostdlib","-I",source,
         "-c",source/"mmu_bridge.S","-o",obj])
    if "R_AARCH64_ABS" in run([tool(ndk, "llvm-readelf"),"-r",obj]):raise ValueError("bridge absolute relocation")
    run([tool(ndk, "ld.lld"),"-static","-nostdlib","-T",source/"mmu_bridge.ld","--build-id=none",obj,"-o",elf])
    if run([tool(ndk, "llvm-nm"),"-u",elf]).strip():raise ValueError("bridge unresolved symbols")
    symbols={}
    for line in run([tool(ndk, "llvm-nm"),"-n",elf]).splitlines():
        fields=line.split()
        if len(fields)==3 and re.fullmatch("[0-9a-fA-F]+",fields[0]):symbols[fields[2]]=int(fields[0],16)
    required=["fault_common","start","end","entry","observer","guard","guard_resume","after_mmu","after_mmu_resume","fp_snapshot","fp_resume","bootstrap_fatal","vectors","context","identity","park"]+[f"fault_{n}" for n in range(16)]
    if any("mmu_bridge_"+name not in symbols for name in required):raise ValueError("bridge exports missing")
    if symbols["mmu_bridge_start"]!=0 or symbols["mmu_bridge_end"]>0x10000:raise ValueError("bridge layout is not within64KiB")
    run([tool(ndk, "llvm-objcopy"),"-O","binary",elf,raw]);blob=bytearray(raw.read_bytes())
    if len(blob)!=symbols["mmu_bridge_end"] or symbols["mmu_bridge_context"]+0x1000!=len(blob):raise ValueError("bridge ABI3 0x1000 context not emitted exactly")
    resume_patches=[]
    segments,ks=kernel_symbols(kernel_bytes());base=min(s["va"] for s in segments)
    for name,target in (("mmu_bridge_guard_resume",0x501298),("mmu_bridge_after_mmu_resume",0x501368),("mmu_bridge_fp_resume",ks["_arm_init"]-base+4)):
        at=symbols[name];original=struct.unpack_from("<I",blob,at)[0]
        if original!=branch_word(at,symbols["mmu_bridge_park"]):raise ValueError(f"{name} placeholder changed: {original:#x}")
        replacement=branch_word(0x1800000+at,target);struct.pack_into("<I",blob,at,replacement)
        resume_patches.append({"symbol":name,"blob_offset":at,"original":original,"replacement":replacement,"target_kernel_offset":target})
    final=out/"mmu_bridge.bin";final.write_bytes(blob)
    (out/"bridge_payload.S").write_text('.section .rodata.bridge_payload,"a"\n.balign 16\n.global bridge_payload_start, bridge_payload_end\nbridge_payload_start:\n.incbin "'+final.as_posix()+'"\nbridge_payload_end:\n')
    dis=run([tool(ndk, "llvm-objdump"),"-d",elf]);(out/"mmu_bridge.disassembly.txt").write_text(dis)
    report={"bytes":len(blob),"sha256":sha(blob),"crc32":zlib.crc32(blob),"raw_sha256":sha(raw.read_bytes()),"symbols":symbols,
            "resume_patch":resume_patches[0],"resume_patches":resume_patches,
            "abi_version":3,"context_bytes":0x1000,
            "elf_note":"linked ELF retains original resume placeholders; embedded mmu_bridge.bin contains the three recorded B patches"}
    gate_header={"VM_GATE_CONTEXT_VA":base+0x1800000+symbols["mmu_bridge_context"],
                 "VM_GATE_OBSERVER_VA":base+0x1800000+symbols["mmu_bridge_observer"],
                 "VM_GATE_FAULT_COMMON_VA":base+0x1800000+symbols["mmu_bridge_fault_common"]}
    (out/"vm_gate_layout.h").write_text("\n".join(f"#define {k} 0x{v:x}" for k,v in gate_header.items())+"\n")
    run([tool(ndk, "clang"),"--target=aarch64-none-elf","-mcpu=cortex-a55","-ffreestanding","-nostdlib","-I",source,"-I",out,"-c",source/"vm_gate.S","-o",out/"vm_gate.o"])
    run([tool(ndk, "ld.lld"),"-static","-nostdlib","-T",source/"vm_gate.ld","--build-id=none",out/"vm_gate.o","-o",out/"vm_gate.elf"])
    require(not run([tool(ndk, "llvm-nm"),"-u",out/"vm_gate.elf"]).strip(),"unresolved VM gate symbols")
    gate_symbols={}
    for line in run([tool(ndk, "llvm-nm"),"-n",out/"vm_gate.elf"]).splitlines():
        f=line.split()
        if len(f)==3:gate_symbols[f[2]]=int(f[0],16)
    run([tool(ndk, "llvm-objcopy"),"-O","binary",out/"vm_gate.elf",out/"vm_gate.bin"])
    gate=(out/"vm_gate.bin").read_bytes()
    require(gate_symbols["mmu_vm_gate_start"]==GATE_VA and gate_symbols["mmu_vm_gate_end"]-GATE_VA==len(gate)<=0x800 and len(gate)%4==0,"VM RX gate cave bounds changed")
    report["gate"]={"va":GATE_VA,"offset":GATE_OFFSET,"bytes":len(gate),"sha256":sha(gate),"symbols":gate_symbols,"inputs":gate_header,"original_word":0xd503201f}
    (out/"vm_gate.disassembly.txt").write_text(run([tool(ndk, "llvm-objdump"),"-d",out/"vm_gate.elf"]))
    (out/"bridge-layout.json").write_text(json.dumps(report,indent=2)+"\n")
    return bytes(blob),report


def prepare_xnu(out,normal_ramdisk,bridge,bridge_report,package=False):
    path=default_kernel_path()
    data=path.read_bytes()
    if sha(data)!=XNU_SHA:raise ValueError("pinned fresh XNU source changed")
    if struct.unpack_from("<4I",data)!=(0xfeedfacf,0x100000c,0,2):raise ValueError("unexpected Mach-O identity")
    ncmds,command_bytes=struct.unpack_from("<II",data,16);at=32;segments=[];entry=None;symbol_command=None
    for _ in range(ncmds):
        cmd,size=struct.unpack_from("<II",data,at)
        if size<8 or at+size>32+command_bytes:raise ValueError("bad Mach-O command")
        if cmd==0x19:
            name=data[at+8:at+24].split(b"\0")[0].decode();va,mem,off,fil=struct.unpack_from("<4Q",data,at+24)
            if mem:segments.append(dict(name=name,va=va,mem=mem,off=off,fil=fil))
        if cmd==2:symbol_command=struct.unpack_from("<4I",data,at+8)
        if cmd==5:
            flavor,count=struct.unpack_from("<II",data,at+8)
            if flavor!=6 or count!=68:raise ValueError("unexpected ARM thread state")
            entry=struct.unpack_from("<Q",data,at+16+32*8)[0]
        at+=size
    _,symbols=kernel_symbols(data)
    base=min(s["va"] for s in segments);ordered=sorted(segments,key=lambda s:s["va"])
    if base!=0xfffffff007004000 or entry-base!=0x4ff488:raise ValueError("fresh entry/base mismatch")
    for i,s in enumerate(ordered):
        if s["fil"]>s["mem"] or s["off"]+s["fil"]>len(data) or (s["va"]|s["mem"]|s["off"]|s["fil"])&7:raise ValueError("unsafe segment extent")
        if i and ordered[i-1]["va"]+ordered[i-1]["mem"]>s["va"]:raise ValueError("segment memory overlap")
        s["relative"]=s["va"]-base;s["crc"]=zlib.crc32(data[s["off"]:s["off"]+s["fil"]])
    span=max(s["relative"]+s["mem"] for s in ordered)
    if span!=0x16f4000:raise ValueError("fresh loaded span changed")
    args_offset=(span+0x3fff)&~0x3fff;adt_offset=args_offset+0x1000
    adt,command,seed_hash=make_adt(out,package)
    blob_offset=0x1800000;blob_reserve=0x10000;top_data=(blob_offset+blob_reserve+0x3fff)&~0x3fff
    if adt_offset+len(adt)>blob_offset:raise ValueError("ADT overlaps bridge reserve")
    def file_offset(relative):
        for s in ordered:
            if s["relative"]<=relative<s["relative"]+s["fil"]:return s["off"]+relative-s["relative"]
        raise ValueError("patch outside file-backed segment")
    patches=[];bs=bridge_report["symbols"]
    def patch(relative,expected,target,label):
        offset=file_offset(relative);word=struct.unpack_from("<I",data,offset)[0]
        if word!=expected:raise ValueError(f"original instruction mismatch at {label}: {word:#x}")
        patches.append({"offset":relative,"file_offset":offset,"original":word,"replacement":branch_word(relative,blob_offset+bs[target]),"label":label,"bridge_symbol":target})
    patch(symbols["_arm_init"]-base,0xd10343ff,"mmu_bridge_fp_snapshot","arm_init FP/SIMD snapshot; replay displaced SUB SP")
    checkpoint=CHECKPOINT_VA-base
    require(file_offset(checkpoint)==CHECKPOINT_FILE,"checkpoint file mapping changed")
    gate=bridge_report["gate"]
    def gate_branch(relative,expected,target,label):
        offset=file_offset(relative)
        require(struct.unpack_from("<I",data,offset)[0]==expected,"gate branch original mismatch: "+label)
        patches.append({"offset":relative,"file_offset":offset,"original":expected,"replacement":branch_word(base+relative,gate["symbols"][target]),"label":label,"bridge_symbol":None,"gate_symbol":target})
    gate_branch(checkpoint,0xd0ffb368,"mmu_vm_gate_checkpoint","first instruction after complete original arm_vm_init return")
    second_pe=0xb2ffac
    gate_branch(second_pe,0xaa1303e0,"mmu_vm_gate_checkpoint","second PE(TRUE) return")
    fiq_return=0xb2ffe8
    gate_branch(fiq_return,0x97e69a99,"mmu_vm_gate_checkpoint","after fiq_context_init return")
    gate_bytes=(out/"vm_gate.bin").read_bytes()
    for i in range(0,len(gate_bytes),4):
        relative=GATE_OFFSET+i;off=file_offset(relative)
        require(struct.unpack_from("<I",data,off)[0]==0xd503201f,"VM gate cave is not original NOP padding")
        patches.append({"offset":relative,"file_offset":off,"original":0xd503201f,"replacement":struct.unpack_from("<I",gate_bytes,i)[0],"label":"RX VM recovery gate word","bridge_symbol":None,"gate_word":i})
    # Preserve the compiled checked zero-base API; no private NOP at aa005c.
    patch(0x501294,0x14000001,"mmu_bridge_guard","page tables ready")
    patch(0x50128c,0x14000000,"mmu_bridge_bootstrap_fatal","bootstrap table overflow loop")
    if struct.unpack_from("<I",data,file_offset(0x501348))[0]!=0xd518c000:raise ValueError("original high VBAR instruction changed")
    patches.append({"offset":0x501348,"file_offset":file_offset(0x501348),"original":0xd518c000,"replacement":0xd503201f,
                    "label":"defer high VBAR until MMU enabled","bridge_symbol":None})
    patch(0x501364,0xf2e00001,"mmu_bridge_after_mmu","install high VBAR after original SCTLR/ISB")
    high_words=[0x14000400,0x14000425,0x1400041d,0x14000415,0x14000407,0x14000411,0x14000402,0x140003f3,0x140003e4,0x140003d9,0x140003cf,0x140003c5]+[0xd503201f]*4
    for i in range(16):
        patch(symbols["_LowExceptionVectorBase"]-base+i*0x80,0x14000000,f"mmu_bridge_fault_{i}",f"low vector {i}")
        gate_branch(symbols["_ExceptionVectorsBase"]-base+i*0x80,high_words[i],f"mmu_vm_gate_fault_{i}",f"high vector {i}")
    if len({p["offset"] for p in patches})!=len(patches):raise ValueError("overlapping kernel patches")
    member,body_offset=newc_entry(".renoace-xnu-p11.macho",data);trailer,_=newc_entry("TRAILER!!!",b"",0)
    padding=bytes((-len(normal_ramdisk))%4);archive_offset=len(normal_ramdisk)+len(padding);source_offset=archive_offset+body_offset
    ramdisk=normal_ramdisk+padding+member+trailer;ramdisk+=bytes((-len(ramdisk))%4)
    if ramdisk[:len(normal_ramdisk)]!=normal_ramdisk or ramdisk[source_offset:source_offset+len(data)]!=data or source_offset&7:raise ValueError("newc source integrity/alignment")
    cursor=archive_offset;files={}
    while ramdisk[cursor:cursor+6]==b"070701":
        fields=[int(ramdisk[cursor+6+8*i:cursor+14+8*i],16) for i in range(13)]
        name=ramdisk[cursor+110:cursor+110+fields[11]-1].decode();cursor=(cursor+110+fields[11]+3)&~3
        files[name]=ramdisk[cursor:cursor+fields[6]];cursor=(cursor+fields[6]+3)&~3
        if name=="TRAILER!!!":break
    if files!={".renoace-xnu-p11.macho":data,"TRAILER!!!":b""} or any(ramdisk[cursor:]):raise ValueError("newc roundtrip failed")
    constants=dict(XNU_LINK_BASE=base,XNU_ENTRY_OFFSET=entry-base,XNU_FIRST_CPU_OFFSET=symbols["_start_first_cpu"]-base,
        XNU_FILE_SIZE=len(data),XNU_FILE_CRC32=zlib.crc32(data),XNU_INITRD_OFFSET=source_offset,XNU_ARGS_OFFSET=args_offset,
        XNU_BOOT_ARGS_SIZE=0x480,XNU_ADT_OFFSET=adt_offset,XNU_ADT_SIZE=len(adt),XNU_ADT_CRC32=zlib.crc32(adt),
        XNU_SEGMENT_COUNT=len(ordered),XNU_PATCH_COUNT=len(patches),XNU_BLOB_OFFSET=blob_offset,XNU_BLOB_RESERVE=blob_reserve,
        XNU_TOP_DATA_OFFSET=top_data,XNU_MAPPED_CLEAN_START=0x180004000,XNU_MAPPED_CLEAN_END=0x190000000,
        XNU_ARM_INIT_OFFSET=symbols["_arm_init"]-base,XNU_CHECKPOINT_OFFSET=checkpoint,XNU_P11_SECOND_PE_OFFSET=second_pe,XNU_P11_SECOND_PE_VA=base+second_pe,
        XNU_P11_SECOND_CONTINUE_VA=base+0xb2ffb0,XNU_P11_FIQ_RETURN_VA=base+0xb2ffe8,
        XNU_OBS_SP0_VA=symbols["_intstack_top"]-0xd0,XNU_OBS_SP1_VA=symbols["_excepstack_top"],
        XNU_CONST_BOOT_ARGS_VA=symbols["_const_boot_args"],XNU_CONST_BOOT_ARGS_OFFSET=symbols["_const_boot_args"]-base,
        XNU_LOW_VECTORS_OFFSET=symbols["_LowExceptionVectorBase"]-base,
        XNU_HIGH_VECTORS_OFFSET=symbols["_ExceptionVectorsBase"]-base,XNU_COMMON_START_OFFSET=symbols["common_start"]-base,
        XNU_BOOTSTRAP_OFFSET=symbols["_bootstrap_pagetables"]-base,XNU_BOOTSTRAP_BYTES=0x10000,
        XNU_SP0_VA=symbols["_intstack_top"],XNU_SP1_VA=symbols["_excepstack_top"],
        XNU_EXPECTED_TCR=0x22a51a251a,XNU_EXPECTED_MAIR=0x0c0804ff00bb44ff,
        XNU_BRIDGE_BYTES=len(bridge),XNU_BRIDGE_CRC32=zlib.crc32(bridge),XNU_BRIDGE_PAYLOAD_SIZE=len(bridge),XNU_BRIDGE_PAYLOAD_CRC32=zlib.crc32(bridge))
    profile=read_json(ROOT/"out/p07-vm-source-prototype/profile.json")
    require(profile["sha256"]==XNU_SHA and int(profile["sites"]["full_vm_return"]["va"],0)==CHECKPOINT_VA,"fresh original VM checkpoint profile changed")
    pe=symbols["_PE_state"];clock=symbols["_gPEClockFrequencyInfo"]
    witness_vas={"BOOT_ARGS_GLOBAL":symbols["_BootArgs"],"PE_STATE":pe,"PE_INITIALIZED":pe,
        "PE_DT_HEAD":pe+0x98,"PE_BOOT_ARGS":pe+0xa0,"PE_DT_SIZE":pe+0xa8,
        "DT_ROOT":symbols["_DTRootNode"],"DT_SIZE":symbols["_DTSize"],"DT_END":symbols["_DTEnd"],"DT_INITIALIZED":symbols["_DTInitialized"],
        "SOC_BASE":symbols["_gPESoCBasePhys"],"SOC_VALID":symbols["_gPESoCBasePhysValid"],"SOC_DEVICE_TYPE_BUFFER":symbols["_gPESoCDeviceTypeBuffer"],
        "TIMEBASE_FREQUENCY":clock+0x48,"DEC_CLOCK_RATE":clock+0x10}
    for name,va in witness_vas.items():
        constants["XNU_"+name+"_VA"]=va
        constants["XNU_"+name+"_OFFSET"]=va-base
        constants["XNU_"+name+"_PA"]=0x180004000+va-base
    constants.update(XNU_EXPECTED_TIMEBASE_HZ=19200000,XNU_EXPECTED_SOC_BASE=0,
                     XNU_EXPECTED_OBS_LR=base+0xb2ffe8,XNU_EXPECTED_OBS_X20=symbols["_serialmode"],XNU_P11_SECOND_PE_OFFSET=second_pe)
    for label,symbol in (("VM_AVAIL_START","_avail_start"),("VM_FIRST_AVAIL","_first_avail"),("VM_KVA_ACTIVE","_kva_active"),("VM_CPU_TTE","_cpu_tte"),("VM_INVALID_TTE","_invalid_tte"),("VM_PHYSMAP_BASE","_physmap_base"),("VM_PHYSMAP_END","_physmap_end")):
        constants["XNU_"+label+"_OFFSET"]=symbols[symbol]-base
    constants["XNU_EXPECTED_OBS_X21"]=symbols["_PAGE_SHIFT_CONST"]
    constants["XNU_VM_MAX_ALLOC_PA"]=0x181b00000
    constants["XNU_VM_GATE_VA"]=gate["symbols"]["mmu_vm_gate_common"]
    constants["XNU_VM_GATE_NORMAL_VA"]=gate["symbols"]["mmu_vm_gate_checkpoint"]
    constants["XNU_VM_INVALID_ROOT_PA"]=0x180004000+top_data
    constants["XNU_VM_CPU_ROOT_PA"]=0x180004000+top_data+0x1000
    for name,offset in bs.items():
        if name.startswith("mmu_bridge_"):constants["XNU_BRIDGE_"+name[len("mmu_bridge_"):].upper()+"_OFFSET"]=offset
    args=bytearray(0x480);struct.pack_into("<HH",args,0,2,2)
    for offset,value in [(8,base),(16,0x180004000),(24,0x10000000),(32,0x180004000+top_data),(0x60,base+adt_offset),(0x478,0x10000000)]:struct.pack_into("<Q",args,offset,value)
    struct.pack_into("<I",args,0x68,len(adt));args[0x6c:0x6c+len(command)]=command
    (out/"boot-args.bin").write_bytes(args)
    lines=[f"#define {k} 0x{v:x}UL" for k,v in constants.items()]
    lines += ["static const struct xnu_segment xnu_segments[] = {"]
    for s in ordered:lines.append("    {0x%x,0x%x,0x%x,0x%x,0x%x},"%(s["relative"],s["mem"],s["off"],s["fil"],s["crc"]))
    lines += ["};","struct xnu_patch { uint64_t offset; uint32_t original, replacement; };","static const struct xnu_patch xnu_patches[] = {"]
    for p in patches:lines.append("    {0x%x,0x%x,0x%x},"%(p["offset"],p["original"],p["replacement"]))
    lines += ["};","static const uint8_t xnu_adt[] __attribute__((aligned(8))) = {"]
    for i in range(0,len(adt),16):lines.append(",".join(f"0x{x:02x}" for x in adt[i:i+16])+",")
    lines += ["};","static const uint8_t xnu_boot_args[] __attribute__((unused,aligned(8))) = {"]
    for i in range(0,len(args),16):lines.append(",".join(f"0x{x:02x}" for x in args[i:i+16])+",")
    lines += ["};"]
    (out/"xnu_layout.h").write_text("\n".join(lines)+"\n")
    report={"source":str(path.relative_to(ROOT)),"source_sha256":XNU_SHA,"source_bytes":len(data),"source_crc32":f"{zlib.crc32(data):08x}",
        "normal_ramdisk_bytes":len(normal_ramdisk),"normal_ramdisk_sha256":sha(normal_ramdisk),"combined_ramdisk_bytes":len(ramdisk),"combined_ramdisk_sha256":sha(ramdisk),
        "archive_offset":archive_offset,"member_data_offset":source_offset,"constants":constants,"segments":ordered,"symbols":symbols,"patches":patches,
        "ADT":{"bytes":len(adt),"sha256":sha(adt),"seed_sha256":seed_hash,"seed_bytes":256,"profile":"measured complete /soc identity semantics; CPU0/19.2MHz, CHRP NVRAM; compiled zero-base source fix; no storage or USB activation","validation_sha256":sha((out/"adt-validation.json").read_bytes()),"seed_origin":"copied once from frozen P04 attempt1; reused for all P07 rebuilds/packages"},
        "boot_args":{"bytes":len(args),"sha256":sha(args),"device_tree_va":hex(base+adt_offset),"top_of_kernel_data_pa":hex(0x180004000+top_data)},
        "bridge":bridge_report,"diagnostics_version":3,"budget_ms":15000,"mode":P11_MODE,"scope":"original full VM then original arm_init through fiq_context_init return with timer save/restore; no IRQ/IOKit/iOS startup"}
    phys=0x180004000;pool=phys+constants["XNU_BOOTSTRAP_OFFSET"]
    clean_end=constants["XNU_MAPPED_CLEAN_END"];clean_blocks=((clean_end+0x1fffff)&~0x1fffff)-(phys&~0x1fffff)
    if phys+top_data>clean_end:raise ValueError("used data leaves identity mapping")
    report["bridge"].update(physical_base=phys+blob_offset,virtual_base=base+blob_offset,reserve_bytes=blob_reserve,
        clean_start_pa=phys,clean_end_pa=clean_end,mapped_limit_pa=constants["XNU_MAPPED_CLEAN_END"],
        guard_expected_pairs=2*(clean_blocks//0x200000)+13)
    report["boot_args"].update(physical_address=phys+args_offset,virtual_address=base+args_offset,
        adt_physical_address=phys+adt_offset,adt_virtual_address=base+adt_offset)
    report["bootstrap_expected_mutations"]={"pool_image_offset":constants["XNU_BOOTSTRAP_OFFSET"],"pool_bytes":0x10000,
        "TTBR0_root_pa":pool,"TTBR1_root_pa":pool+0x1000,"identity_L2_pa":pool+0x2000,"high_L2_pa":pool+0x3000,
        "TTBR0_root_entry":{"index":6,"value":(pool+0x2000)|3},"TTBR1_root_entry":{"index":192,"value":(pool+0x3000)|3},
        "identity_L2_index_first":0,"high_L2_index_first":56,"leaf_count_each":128,"first_leaf_pa":0x180000000,
        "leaf_stride":0x200000,"leaf_flags":0x40000000000601,"all_other_pool_bytes_zero":True,
        "identity_end_exclusive":0x190000000,"nominal_window_end":0x190004000,
        "assumptions":"physBase/headerPA180004000; linked virtBase; memSize10000000; original MMU; full actual mapped owned window only, excluding nominal unmapped top16KiB"}
    require(report["bridge"]["guard_expected_pairs"]==269,"full mapped-window guard pair count changed")
    report["checkpoint"]={"va":CHECKPOINT_VA,"offset":checkpoint,"file_offset":CHECKPOINT_FILE,"original":0xd0ffb368,
        "meaning":"after original full arm_vm_init returns; before serial/second PE/IOKit",
        "expected_sp0_va":constants["XNU_OBS_SP0_VA"],"expected_sp1_va":constants["XNU_OBS_SP1_VA"],
        "expected_x20":symbols["_init_thread"],"expected_lr":CHECKPOINT_VA,"x0_x21_are_entry_args":False,
        "witness_vas":witness_vas}
    report["source_compatibility"]={"kind":"compiled checked zero-base arm-io API and missing bus frequency guard","patch_sha256":"b971f39f86c44ea65f6c5f3e546764744bff51eb0dd3c9622f29592469f0ec8c","private_zero_base_NOP":False}
    mutated=bytearray(data)
    for patch_item in patches:struct.pack_into("<I",mutated,patch_item["file_offset"],patch_item["replacement"])
    report["private_patched_macho_sha256"]=sha(mutated)
    report["private_patched_macho_note"]="pristine official source kernel plus exactly enumerated runtime observation patches; initrd member stays pristine"
    report["expected_mutable_ranges"]=[]
    report["early_c_mutation_contract"]={"repeat_run_requires_pristine_reload":True,"post_C_kernel_bytes_unchanged_assertion_valid":False,"scope":"Full VM intentionally writes kernel globals, metadata, startup/static-if links and new page tables; positive model must enforce physical allocation envelope"}
    (out/"ramdisk").write_bytes(ramdisk);(out/"xnu-layout.json").write_text(json.dumps(report,indent=2)+"\n")
    return ramdisk,report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ndk-bin",type=Path,default=NDK)
    ap.add_argument("--bridge-only",action="store_true",help="compile and validate the AArch64 bridge/RX gate without private boot images")
    ap.add_argument("--package",action="store_true")
    ap.add_argument("--prepare-only",action="store_true",help="generate bridge, ADT and headers without compiling main C")
    ap.add_argument("--validate-only",action="store_true",help="refresh input evidence and check package gates without compiling or packaging")
    args=ap.parse_args()
    if sum((args.bridge_only,args.package,args.prepare_only,args.validate_only))>1:
        ap.error("select only one of --bridge-only, --package, --prepare-only, --validate-only")
    source=ROOT/"device/renoace/xnu_p11_probe"
    out=ROOT/"out/xnu-p11-probe";out.mkdir(parents=True,exist_ok=True)
    (source/"p11_gate_layout.h").write_text("#define P11_PHASE 0xca0\n#define P11_DISPLACED_PAGE 0xfffffff0071a1000UL\n#define P11_DISPLACED_OFF 0x1e8\n#define P11_CONTINUE_VA 0xfffffff007b33e40UL\n#define P11_SECOND_CONTINUE_VA 0xfffffff007b2ffb0UL\n#define P11_FIQ_RETURN_VA 0xfffffff007b33fe8UL\n",encoding="utf-8",newline="\n")
    if args.validate_only or args.package:
        evidence=p07_package_evidence(out,source)
        if args.validate_only:
            (out/"package-evidence.json").write_text(json.dumps(evidence,indent=2)+"\n")
            print("P07 evidence gates passed; no compilation or package created")
            return
    def source_snapshot():
        return {p.name:sha(p.read_bytes()) for p in source.iterdir() if p.suffix in (".S",".c",".h",".ld")}
    source_hashes=source_snapshot()
    ndk=args.ndk_bin;commands=[]
    def run(command):
        command=[str(x) for x in command];commands.append(command)
        result=subprocess.run(command,cwd=out,capture_output=True,text=True,timeout=120)
        if result.returncode:raise RuntimeError(result.stdout+result.stderr)
        return result.stdout
    if args.bridge_only:
        source_hashes=source_snapshot()
        bridge,bridge_report=build_bridge(source,out,ndk,run)
        require(source_snapshot()==source_hashes,"source changed during bridge-only compile; rerun")
        report={"status":"compiled AArch64 P11 bridge and RX gate; carrier/model inputs not required",
                "mode":P11_MODE,"hardware_tested":False,"ndk_bin":str(ndk),
                "toolchain":{"clang":str(tool(ndk,"clang")),"ld_lld":str(tool(ndk,"ld.lld")),
                             "llvm_nm":str(tool(ndk,"llvm-nm")),"llvm_readelf":str(tool(ndk,"llvm-readelf")),
                             "llvm_objcopy":str(tool(ndk,"llvm-objcopy")),"llvm_objdump":str(tool(ndk,"llvm-objdump"))},
                "kernel_sha256":sha(kernel_bytes()),"source_hashes":source_hashes,
                "bridge_sha256":sha(bridge),"bridge_bytes":len(bridge),"bridge":bridge_report,
                "commands":commands,"instruction_model":"not run: private boot/recovery carrier and model fixture are separate inputs"}
        (out/"bridge-only.json").write_text(json.dumps(report,indent=2)+"\n")
        print(f"Compiled P11 bridge: {out/'mmu_bridge.bin'} ({len(bridge)} bytes)")
        print(f"Compiled RX gate: {out/'vm_gate.bin'} ({bridge_report['gate']['bytes']} bytes)")
        print("Hardware tested: false. Full instruction model requires the private carrier fixture.")
        return
    private=ROOT/"local-device/20261106T115059Z"
    manifest=json.loads((private/"manifest.json").read_text())
    spec=importlib.util.spec_from_file_location("p01_pack_helpers",ROOT/"tools/build_renoace_probe.py")
    pack=importlib.util.module_from_spec(spec);spec.loader.exec_module(pack)
    inputs={}
    for name in ("boot","recovery"):
        data=(private/(name+".img")).read_bytes()
        if sha(data)!=manifest["files"][name+".img"]["sha256"]:
            raise ValueError(name+" backup hash changed")
        hdr,parts=pack.unpack(data);inputs[name]=(data,hdr,parts)
    normal,header,parts=inputs["boot"]
    recovery,recovery_header,recovery_parts=inputs["recovery"]
    bridge,bridge_report=build_bridge(source,out,ndk,run)
    combined_ramdisk,xnu_report=prepare_xnu(out,parts["ramdisk"],bridge,bridge_report,args.package)
    parts=dict(parts);parts["ramdisk"]=combined_ramdisk
    decompressor=zlib.decompressobj(31)
    linux=decompressor.decompress(parts["kernel"])
    if not decompressor.eof or decompressor.unused_data!=parts["dtb"]:
        raise ValueError("normal Image gzip/DTB arrangement changed")
    if parts["dtb"]!=recovery_parts["dtb"] or parts["second"]:
        raise ValueError("boot/recovery DTB mismatch or unexpected second stage")
    code0,code1=struct.unpack_from("<II",linux)
    text_offset,effective,flags=struct.unpack_from("<QQQ",linux,8)
    if linux[56:60]!=b"ARM\x64" or code0&0xfc000000!=0x14000000 or code1:
        raise ValueError("expected the measured non-EFI Linux B entry")
    if (text_offset,effective,flags)!=(0x80000,0x37f0000,0xa) or len(linux)!=0x2fb2810:
        raise ValueError("Linux geometry differs from the audited normal-boot baseline")
    if len(linux)>effective or effective&0xffff:
        raise ValueError("no aligned tail after the effective Linux Image")
    # P07 includes the complete RX gate patch table and VM witnesses.
    # Preserve the independent64KiB stack and separately audit the expanded Image.
    tail_prefix=0x23000
    dtb_offset=effective+tail_prefix
    dtb_capacity=0x100000
    image_size=dtb_offset+dtb_capacity
    if image_size>=0x8000000 or image_size>=0x100000000:
        raise ValueError("tail cannot be reached/restored with the admitted instructions")
    for key in ("kernel_addr","ramdisk_addr","tags_addr","dtb_addr","page_size","header_version"):
        if header[key]!=recovery_header[key]:raise ValueError("carrier load geometry mismatch: "+key)
    (out/"original-linux.Image").write_bytes(linux)
    build_id=sha((P11_MODE+json.dumps(source_hashes,sort_keys=True)+sha(Path(__file__).read_bytes())+sha(linux)+XNU_SHA+sha(combined_ramdisk)+json.dumps(xnu_report["patches"],sort_keys=True,separators=(",",":"))+xnu_report["ADT"]["sha256"]+xnu_report["boot_args"]["sha256"]+sha(bridge)).encode())[:16]
    constants={"LINUX_EFFECTIVE_SIZE":effective,"LINUX_TEXT_OFFSET":text_offset,
               "LINUX_ORIGINAL_CODE0":code0,"DTB_OFFSET":dtb_offset,
               "DTB_CAPACITY":dtb_capacity,"CHAIN_IMAGE_SIZE":image_size,
               "NORMAL_RAMDISK_SIZE":len(parts["ramdisk"]), "XNU_PHYS_BASE":0x180004000, "XNU_WINDOW_SIZE":0x10000000}
    (out/"layout.h").write_text("\n".join(f"#define {k} 0x{v:x}" for k,v in constants.items())+f'\n#define CHAIN_BUILD_ID "{build_id}"\n')
    (out/"layout.ld").write_text("\n".join(f"{k} = 0x{v:x};" for k,v in constants.items())+"\n")
    if args.prepare_only:
        if source_snapshot()!=source_hashes:raise ValueError("source changed during prepare; rerun")
        (out/"prepare.json").write_text(json.dumps({"status":"P11 headers prepared; main C not compiled by this invocation","mode":P11_MODE,
            "build_id":build_id,"builder_sha256":sha(Path(__file__).read_bytes()),"source_hashes":source_hashes,"xnu":xnu_report,"commands":commands,
            "package_gate":"BLOCKED until dedicated P07 instruction and integration gates are independently accepted","hardware_tested":False},indent=2)+"\n")
        print("Prepared P07 pinned layout, ABI3 bridge with three resume fixups, independently validated identity ADT and witness headers; no main Image/package built")
        return
    common=[tool(ndk, "clang"),"--target=aarch64-none-elf","-mcpu=cortex-a55","-O2","-ffreestanding",
            "-nostdlib","-fno-builtin","-fno-pic","-fno-pie","-fno-stack-protector","-fno-jump-tables",
            "-fno-asynchronous-unwind-tables","-mgeneral-regs-only","-mstrict-align","-Wall","-Wextra","-Werror","-I",out]
    objects=[]
    for path in (source/"start.S",source/"probe.c",source/"xnu_control.c",out/"bridge_payload.S"):
        obj=out/(path.stem+".o");run(common+["-c",path,"-o",obj]);objects.append(obj)
    for obj in objects:
        reloc=run([tool(ndk, "llvm-readelf"),"-r",obj])
        if "R_AARCH64_ABS" in reloc:raise ValueError("absolute relocation in "+obj.name)
    elf=out/"probe.elf"
    run([tool(ndk, "ld.lld"),"-static","-nostdlib","-T",source/"probe.ld","--build-id=none","-N",*objects,"-o",elf])
    if run([tool(ndk, "llvm-nm"),"-u",elf]).strip():raise ValueError("unresolved symbols")
    if source_snapshot()!=source_hashes:raise ValueError("source changed during compile; rerun")
    symbol_text=run([tool(ndk, "llvm-nm"),"-n",elf]);symbols={}
    for line in symbol_text.splitlines():
        fields=line.split()
        if len(fields)==3 and re.fullmatch("[0-9a-fA-F]+",fields[0]):symbols[fields[2]]=int(fields[0],16)
    if symbols["chain_entry"]!=effective or symbols["_chain_end"]!=image_size or symbols["_dtb_buffer"]!=dtb_offset:
        raise ValueError("linked tail geometry mismatch")
    if symbols["_stack_top"]>dtb_offset or symbols["_bss_end"]>symbols["_stack_top"]-0x10000:
        raise ValueError("tail stack overlaps code/data or FDT")
    tailpath=out/"tail.bin";run([tool(ndk, "llvm-objcopy"),"-O","binary",elf,tailpath])
    tail=tailpath.read_bytes()
    if len(tail)>tail_prefix-0x10000:raise ValueError("tail file leaves insufficient independent stack space")
    image=bytearray(linux)+bytearray(image_size-len(linux))
    image[effective:effective+len(tail)]=tail
    struct.pack_into("<I",image,0,0x14000000|(effective//4))
    struct.pack_into("<Q",image,16,image_size)
    original_prefix=bytearray(image[:len(linux)])
    struct.pack_into("<I",original_prefix,0,code0);struct.pack_into("<Q",original_prefix,16,effective)
    if original_prefix!=linux:raise ValueError("Linux bytes changed outside code0/image_size")
    (out/"Image").write_bytes(image)
    kernel=gzip.compress(image,mtime=0)+parts["dtb"]
    d=zlib.decompressobj(31)
    if d.decompress(kernel)!=image or d.unused_data!=parts["dtb"]:
        raise ValueError("kernel roundtrip failed")
    (out/"Image.gz-dtb").write_bytes(kernel)
    dis=run([tool(ndk, "llvm-objdump"),"-d",elf]);(out/"disassembly.txt").write_text(dis)
    instructions=[]
    for line in dis.splitlines():
        match=re.match(r"\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)",line)
        if match:instructions.append(match.group(3))
    if any(re.match(r"(?:smc|hvc|svc)\b",s) for s in instructions):raise ValueError("unexpected firmware/system call")
    report={"status":"offline P11 fiq_context_init return checkpoint candidate with timer recovery; compiled zero-base source fix; hardware-untested; NOT iOS boot","mode":P11_MODE,"builder_sha256":sha(Path(__file__).read_bytes()),
            "hardware_tested":False,"build_id":build_id,"constants":constants,"symbols":symbols,
            "original_linux_sha256":sha(linux),"image_sha256":sha(image),"image_bytes":len(image),
            "kernel_payload_sha256":sha(kernel),"source_hashes":source_hashes,"commands":commands,
            "entry_contract":"EL1 or EL2, M=C=0, Image text_offset congruence and loader-owned expanded allocation",
            "refusal":"FDT/bank/carveout/initrd validation refusal restores original Linux header and original DT; unsupported EL/MMU/cache state parks",
            "linux_changes_before_entry":["code0 redirects to tail","Image image_size covers emitted tail arena"],
            "restoration":"both modified fields restored before branch to original Linux entry",
            "unknowns":["hardware acceptance of enlarged Image","Android normal boot through recovery carrier","actual native CPU feature values","real cache/interconnect behavior","exclusive EFI ownership of every selected kernel-window byte is not established by a captured memory map"],
            "instruction_model":"not yet executed by this build command"}
    report["package_gate"]="BLOCKED pending P07 full-arm_vm_init instruction/model, SIMD restoration, primitive and independent integration gates; P04/P05 evidence cannot satisfy this milestone"
    report["pre_guard_writes"]="P02 substrate's early context/stack writes use the loader-owned Image; high XNU window writes occur only after complete runtime FDT overlap checks"
    report["xnu"]=xnu_report
    if args.package:
        evidence=p07_package_evidence(out,source)
        require(evidence["image_sha256"]==sha(image) and evidence["build_id"]==build_id,"recompiled Image differs from reviewed P07 candidate")
        report["instruction_model"]=evidence["model"]
        report["package_evidence"]=evidence
        report["package_gate"]="matched P07 MAX native full-VM positive and eight refusals/fault peers, strict raw VM records, caller/32-Q/FP/CNTKCTL restoration, 16-slot gate units, independent review, 190 primitives and fresh input/ABL evidence; hardware execution remains separate"
        (out/"package-evidence.json").write_text(json.dumps(evidence,indent=2)+"\n")
        aosp=ROOT/"references/aosp-tools";pins=json.loads((aosp/"sources.json").read_text())
        for name in ("mkbootimg-v2.py","avbtool.py"):
            if sha((aosp/name).read_bytes())!=pins[name]["sha256"]:raise ValueError("AOSP tool pin mismatch")
        legacy=(aosp/"mkbootimg-v2.py").read_text();old="return (image_size + page_size - 1) / page_size"
        if legacy.count(old)!=1:raise ValueError("legacy packer division fix mismatch")
        packer=out/"mkbootimg-python3.py";packer.write_text(legacy.replace(old,old.replace(" / "," // ")))
        for name,data in (("ramdisk",parts["ramdisk"]),("dtb",parts["dtb"]),("recovery_dtbo",recovery_parts["recovery_dtbo"])):
            (out/name).write_bytes(data)
        proposed=out/"recovery.img"
        run([sys.executable,packer,"--header_version","2","--pagesize","4096","--base","0",
             "--kernel_offset",header["kernel_addr"],"--ramdisk_offset",header["ramdisk_addr"],"--tags_offset",header["tags_addr"],
             "--dtb_offset",header["dtb_addr"],"--kernel",out/"Image.gz-dtb","--ramdisk",out/"ramdisk",
             "--recovery_dtbo",out/"recovery_dtbo","--dtb",out/"dtb","--output",proposed])
        result=bytearray(proposed.read_bytes());keep=bytearray(normal[:4096])
        for a,b in ((8,12),(16,20),(576,608),(1632,1644)):
            keep[a:b]=result[a:b]
        result[:4096]=keep;proposed.write_bytes(result)
        _,new=pack.unpack(result)
        expected={"kernel":kernel,"ramdisk":parts["ramdisk"],"second":b"","recovery_dtbo":recovery_parts["recovery_dtbo"],"dtb":parts["dtb"]}
        if new!=expected:raise ValueError("carrier part roundtrip mismatch")
        if result[64:576]+result[608:1632]!=normal[64:576]+normal[608:1632]:raise ValueError("normal command line changed")
        run([sys.executable,aosp/"avbtool.py","add_hash_footer","--image",proposed,"--partition_name","recovery",
             "--partition_size",len(recovery),"--algorithm","NONE","--salt","00"*32])
        avb=run([sys.executable,aosp/"avbtool.py","verify_image","--image",proposed]);(out/"avb-check.txt").write_text(avb)
        final=proposed.read_bytes();pack.unpack(final)
        report["carrier"]={"file":"recovery.img","sha256":sha(final),"bytes":len(final),
                           "normal_boot_ramdisk_sha256":xnu_report["normal_ramdisk_sha256"],
                           "combined_ramdisk_sha256":sha(parts["ramdisk"]),"restore_sha256":sha(recovery),
                           "untested":"normal Linux/header and exact normal ramdisk prefix + second newc XNU member + current recovery DTBO + fresh unsigned recovery AVB"}
    (out/"build.json").write_text(json.dumps(report,indent=2)+"\n")
    print(f"OFFLINE model-review payload: {out/'Image.gz-dtb'}")
    print(f"Linux bytes preserved except two restored header fields; tail offset={effective:#x}, Image size={image_size:#x}.")
    print("Hardware tested: false. No phone tool was invoked.")


if __name__=="__main__":main()
