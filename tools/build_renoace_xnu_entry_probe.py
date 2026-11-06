#!/usr/bin/env python3
"""Build the P03 bounded XNU-entry control OFFLINE. Never operates a phone.

Default output is an experimental kernel payload for instruction-model review.
--package requires matching owning-ABL bounds evidence and instruction tests.
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

ROOT=Path(__file__).resolve().parents[1]
NDK=Path("C:/Users/123/AppData/Local/Android/Sdk/ndk/30.0.14904198/toolchains/llvm/prebuilt/windows-x86_64/bin")
sha=lambda data:hashlib.sha256(data).hexdigest()
XNU_SHA="c973fe6cf1f039781972b580a9423613effd08806e66bd88ac5a2d2a9e3ef0fb"


def newc_entry(name,data,mode=0o100444):
    filename=name.encode()+b"\0"
    fields=[1,mode,0,0,1,0,len(data),0,0,0,0,len(filename),0]
    header=b"070701"+b"".join(f"{n:08x}".encode() for n in fields)+filename
    header+=bytes((-len(header))%4)
    return header+data+bytes((-len(data))%4),len(header)


def prepare_xnu(out,normal_ramdisk):
    path=ROOT/"out/analysis/xnu-candidate/extracted/zeta/kernel/mach.development.bcm2837.unstripped.noctf"
    data=path.read_bytes()
    if sha(data)!=XNU_SHA:raise ValueError("pinned XNU source changed")
    if struct.unpack_from("<4I",data)!=(0xfeedfacf,0x100000c,0,2):raise ValueError("unexpected Mach-O identity")
    ncmds,command_bytes=struct.unpack_from("<II",data,16);at=32;segments=[];entry=None
    for _ in range(ncmds):
        cmd,size=struct.unpack_from("<II",data,at)
        if size<8 or at+size>32+command_bytes:raise ValueError("bad Mach-O command")
        if cmd==0x19:
            name=data[at+8:at+24].split(b"\0")[0].decode()
            va,mem,off,fil=struct.unpack_from("<4Q",data,at+24)
            if mem:segments.append(dict(name=name,va=va,mem=mem,off=off,fil=fil))
        if cmd==5:
            flavor,count=struct.unpack_from("<II",data,at+8)
            if flavor!=6 or count!=68:raise ValueError("unexpected ARM thread state")
            entry=struct.unpack_from("<Q",data,at+16+32*8)[0]
        at+=size
    base=min(s["va"] for s in segments)
    if base!=0xfffffff007004000 or entry-base!=0x538518:raise ValueError("unexpected XNU entry/base")
    ordered=sorted(segments,key=lambda s:s["va"])
    for i,s in enumerate(ordered):
        if s["fil"]>s["mem"] or s["off"]+s["fil"]>len(data) or (s["va"]|s["mem"]|s["off"]|s["fil"])&7:
            raise ValueError("unsafe segment extent")
        if i and ordered[i-1]["va"]+ordered[i-1]["mem"]>s["va"]:raise ValueError("segment memory overlap")
        s["relative"]=s["va"]-base;s["crc"]=zlib.crc32(data[s["off"]:s["off"]+s["fil"]])
    end=max(s["relative"]+s["mem"] for s in ordered)
    args_offset=(end+0x3fff)&~0x3fff
    if args_offset+0x4000>0x10000000:raise ValueError("kernel exceeds owned window")
    if data[0x538518:0x53851c]!=bytes.fromhex("da060014") or data[0x53a080:0x53a09c]!=bytes.fromhex("9f1010d5df4f03d5f40300aa150080d2e0fffff00000009100c018d5"):
        raise ValueError("XNU original entry/gate bytes mismatch")
    member,body_offset=newc_entry(".renoace-xnu-p03.macho",data)
    trailer,_=newc_entry("TRAILER!!!",b"",0)
    padding=bytes((-len(normal_ramdisk))%4)
    archive_offset=len(normal_ramdisk)+len(padding)
    source_offset=archive_offset+body_offset
    ramdisk=normal_ramdisk+padding+member+trailer
    ramdisk+=bytes((-len(ramdisk))%4)
    if ramdisk[:len(normal_ramdisk)]!=normal_ramdisk or ramdisk[source_offset:source_offset+len(data)]!=data:
        raise ValueError("appended newc payload changed")
    # Independent parser roundtrip of the appended raw archive.
    cursor=archive_offset;files={}
    while ramdisk[cursor:cursor+6]==b"070701":
        fields=[int(ramdisk[cursor+6+8*i:cursor+14+8*i],16) for i in range(13)]
        name=ramdisk[cursor+110:cursor+110+fields[11]-1].decode();cursor=(cursor+110+fields[11]+3)&~3
        files[name]=ramdisk[cursor:cursor+fields[6]];cursor=(cursor+fields[6]+3)&~3
        if name=="TRAILER!!!":break
    if files!={".renoace-xnu-p03.macho":data,"TRAILER!!!":b""} or any(ramdisk[cursor:]):
        raise ValueError("newc roundtrip failed")
    constants=dict(XNU_LINK_BASE=base,XNU_ENTRY_OFFSET=0x538518,XNU_FIRST_CPU_OFFSET=0x53a080,
                   XNU_GATE_OFFSET=0x53a098,XNU_GATE_FILE_OFFSET=0x53a098,XNU_VECTOR_OFFSET=0x539000,
                   XNU_FILE_SIZE=len(data),XNU_FILE_CRC32=zlib.crc32(data),XNU_INITRD_OFFSET=source_offset,
                   XNU_ARGS_OFFSET=args_offset,XNU_SEGMENT_COUNT=len(ordered))
    lines=[f"#define {k} 0x{v:x}UL" for k,v in constants.items()]
    lines += ["static const struct xnu_segment xnu_segments[] = {"]
    for s in ordered:lines.append("    {0x%x,0x%x,0x%x,0x%x,0x%x},"%(s["relative"],s["mem"],s["off"],s["fil"],s["crc"]))
    lines += ["};","static const uint32_t xnu_original_prefix[] = {0xd510109f,0xd5034fdf,0xaa0003f4,0xd2800015,0xf0ffffe0,0x91000000};","static const uint32_t xnu_crc_table[256] = {"]
    for i in range(256):
        v=i
        for _ in range(8):v=(v>>1)^((0-(v&1))&0xedb88320)
        lines.append(f"0x{v:08x}U,")
    lines.append("};")
    (out/"xnu_layout.h").write_text("\n".join(lines)+"\n")
    report={"source":str(path.relative_to(ROOT)),"source_sha256":XNU_SHA,"source_bytes":len(data),
            "source_crc32":f"{zlib.crc32(data):08x}","normal_ramdisk_bytes":len(normal_ramdisk),
            "normal_ramdisk_sha256":sha(normal_ramdisk),"combined_ramdisk_bytes":len(ramdisk),"combined_ramdisk_sha256":sha(ramdisk),
            "archive_offset":archive_offset,"member_data_offset":source_offset,"constants":constants,"segments":ordered,
            "gate":"loaded private copy only: MSR VBAR_EL1,x0 -> RET; original file unchanged",
            "diagnostics_version":1,"budget_ms":15000}
    (out/"ramdisk").write_bytes(ramdisk);(out/"xnu-layout.json").write_text(json.dumps(report,indent=2)+"\n")
    return ramdisk,report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ndk-bin",type=Path,default=NDK)
    ap.add_argument("--package",action="store_true")
    args=ap.parse_args()
    source=ROOT/"device/renoace/xnu_entry_probe"
    out=ROOT/"out/xnu-entry-probe";out.mkdir(parents=True,exist_ok=True)
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
    combined_ramdisk,xnu_report=prepare_xnu(out,parts["ramdisk"])
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
    dtb_offset=effective+0x20000
    dtb_capacity=0x100000
    image_size=dtb_offset+dtb_capacity
    if image_size>=0x8000000 or image_size>=0x100000000:
        raise ValueError("tail cannot be reached/restored with the admitted instructions")
    for key in ("kernel_addr","ramdisk_addr","tags_addr","dtb_addr","page_size","header_version"):
        if header[key]!=recovery_header[key]:raise ValueError("carrier load geometry mismatch: "+key)
    (out/"original-linux.Image").write_bytes(linux)
    source_hashes={p.name:sha(p.read_bytes()) for p in source.iterdir() if p.suffix in (".S",".c",".h",".ld")}
    build_id=sha((json.dumps(source_hashes,sort_keys=True)+sha(linux)+XNU_SHA+sha(combined_ramdisk)).encode())[:16]
    constants={"LINUX_EFFECTIVE_SIZE":effective,"LINUX_TEXT_OFFSET":text_offset,
               "LINUX_ORIGINAL_CODE0":code0,"DTB_OFFSET":dtb_offset,
               "DTB_CAPACITY":dtb_capacity,"CHAIN_IMAGE_SIZE":image_size,
               "NORMAL_RAMDISK_SIZE":len(parts["ramdisk"]), "XNU_PHYS_BASE":0x180004000, "XNU_WINDOW_SIZE":0x10000000}
    (out/"layout.h").write_text("\n".join(f"#define {k} 0x{v:x}" for k,v in constants.items())+f'\n#define CHAIN_BUILD_ID "{build_id}"\n')
    (out/"layout.ld").write_text("\n".join(f"{k} = 0x{v:x};" for k,v in constants.items())+"\n")
    ndk=args.ndk_bin;commands=[]
    def run(command):
        command=[str(x) for x in command];commands.append(command)
        r=subprocess.run(command,cwd=out,capture_output=True,text=True,timeout=120)
        if r.returncode:raise RuntimeError(r.stdout+r.stderr)
        return r.stdout
    common=[ndk/"clang.exe","--target=aarch64-none-elf","-mcpu=cortex-a55","-O2","-ffreestanding",
            "-nostdlib","-fno-builtin","-fno-pic","-fno-pie","-fno-stack-protector","-fno-jump-tables",
            "-fno-asynchronous-unwind-tables","-mgeneral-regs-only","-mstrict-align","-Wall","-Wextra","-Werror","-I",out]
    objects=[]
    for name in ("start.S","probe.c","xnu_control.c","xnu_call.S"):
        obj=out/(Path(name).stem+".o");run(common+["-c",source/name,"-o",obj]);objects.append(obj)
    for obj in objects:
        reloc=run([ndk/"llvm-readelf.exe","-r",obj])
        if "R_AARCH64_ABS" in reloc:raise ValueError("absolute relocation in "+obj.name)
    elf=out/"probe.elf"
    run([ndk/"ld.lld.exe","-static","-nostdlib","-T",source/"probe.ld","--build-id=none","-N",*objects,"-o",elf])
    if run([ndk/"llvm-nm.exe","-u",elf]).strip():raise ValueError("unresolved symbols")
    symbol_text=run([ndk/"llvm-nm.exe","-n",elf]);symbols={}
    for line in symbol_text.splitlines():
        fields=line.split()
        if len(fields)==3 and re.fullmatch("[0-9a-fA-F]+",fields[0]):symbols[fields[2]]=int(fields[0],16)
    if symbols["chain_entry"]!=effective or symbols["_chain_end"]!=image_size or symbols["_dtb_buffer"]!=dtb_offset:
        raise ValueError("linked tail geometry mismatch")
    if symbols["_stack_top"]>dtb_offset or symbols["_bss_end"]>symbols["_stack_top"]-0x10000:
        raise ValueError("tail stack overlaps code/data or FDT")
    tailpath=out/"tail.bin";run([ndk/"llvm-objcopy.exe","-O","binary",elf,tailpath])
    tail=tailpath.read_bytes()
    if len(tail)>0x20000-0x10000:raise ValueError("tail file leaves insufficient independent stack space")
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
    dis=run([ndk/"llvm-objdump.exe","-d",elf]);(out/"disassembly.txt").write_text(dis)
    instructions=[]
    for line in dis.splitlines():
        match=re.match(r"\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)",line)
        if match:instructions.append(match.group(3))
    if any(re.match(r"(?:smc|hvc|svc)\b",s) for s in instructions):raise ValueError("unexpected firmware/system call")
    report={"status":"offline bounded XNU-entry control; seven original instructions then return; hardware-untested",
            "hardware_tested":False,"build_id":build_id,"constants":constants,"symbols":symbols,
            "original_linux_sha256":sha(linux),"image_sha256":sha(image),"image_bytes":len(image),
            "kernel_payload_sha256":sha(kernel),"source_hashes":source_hashes,"commands":commands,
            "entry_contract":"EL1 or EL2, M=C=0, Image text_offset congruence and loader-owned expanded allocation",
            "refusal":"FDT/bank/carveout/initrd validation refusal restores original Linux header and original DT; unsupported EL/MMU/cache state parks",
            "linux_changes_before_entry":["code0 redirects to tail","Image image_size covers emitted tail arena"],
            "restoration":"both modified fields restored before branch to original Linux entry",
            "unknowns":["hardware acceptance of enlarged Image","Android normal boot through recovery carrier","actual native CPU feature values","real cache/interconnect behavior","exclusive EFI ownership of every selected kernel-window byte is not established by a captured memory map"],
            "instruction_model":"not yet executed by this build command"}
    report["package_gate"]="requires matching owning-ABL bounds audit and independent instruction-model results"
    report["pre_guard_writes"]="P02 substrate's early context/stack writes use the loader-owned Image; high XNU window writes occur only after complete runtime FDT overlap checks"
    report["xnu"]=xnu_report
    if args.package:
        model_path=out/"instruction-tests.json"
        audit_path=ROOT/"out/analysis/abl-chainprobe-load-bounds.json"
        model=json.loads(model_path.read_text());audit=json.loads(audit_path.read_text())
        if not model.get("passed") or model.get("image_sha256")!=sha(image) or model.get("source_hashes")!=source_hashes:
            raise ValueError("instruction-model results do not cover this exact payload/source")
        if model.get("test_source_sha256")!=sha((source/"test_instructions.py").read_bytes()):
            raise ValueError("instruction-model test source changed; rerun the model")
        required={"complete-loader-and-seven-instruction-entry","source-CRC-refusal","high-window-refusal",
                  "private-gate-not-patched","OSLK-refusal","budget-refusal","CRC-ISA-refusal",
                  "budget-during-BSS","BSS-readback-corruption"}
        if not required.issubset({case["name"] for case in model["cases"]}):raise ValueError("model coverage incomplete")
        wrapper_path=ROOT/"out/xnu-wrapper-tests/results.json"
        cpio_path=ROOT/"out/xnu-wrapper-tests/cpio-review.json"
        crc_path=ROOT/"out/xnu-memory-primitive-tests/results.json"
        wrapper=json.loads(wrapper_path.read_text());cpio=json.loads(cpio_path.read_text());crc=json.loads(crc_path.read_text())
        wrapper_bytes=image[symbols["xnu_gate_call"]:symbols["xnu_gate_call"]+wrapper["wrapper_bytes"]]
        if wrapper.get("passed")!=5 or wrapper.get("failed")!=0 or sha(wrapper_bytes)!=wrapper["wrapper_sha256"]:
            raise ValueError("independent wrapper instruction evidence does not cover these bytes")
        if wrapper["xnu_source_sha256"]!=XNU_SHA or not cpio["result"].startswith("PASS") or cpio["combined_ramdisk_sha256"]!=sha(combined_ramdisk):
            raise ValueError("independent XNU/CPIO review mismatch")
        if (crc["image_sha256"]!=sha(image) or crc.get("source_hashes")!=source_hashes or
            crc.get("failed")!=0 or crc.get("passed")!=190 or not crc["cases"] or
            not all(case["passed"] for case in crc["cases"]) or
            crc.get("test_sha256")!=sha((source/"test_primitives.py").read_bytes())):
            raise ValueError("compiled memory primitive evidence mismatch")
        backup_name=(ROOT/"local-device/bootchain-backup-latest.txt").read_text().strip()
        abl_path=(ROOT/"local-device"/backup_name/"abl.img").resolve()
        if ROOT/"local-device" not in abl_path.parents or sha(abl_path.read_bytes())!=audit["abl_sha256"]:
            raise ValueError("owning-ABL audit identity mismatch")
        # Recalculate the owning ABL's observed formula for this larger initrd.
        # The prior audit's candidate hash was P02 and is not reused as a P03 pin.
        constants_audit=audit["fallback_constants"]
        if constants_audit["0x47a60"]!="0x80000" or constants_audit["0x47a64"]!="0x5600000":
            raise ValueError("owning ABL fallback constants changed")
        calculations=[]
        for label,selected_base,window_bytes in (("audited-64bit-fallback",0x80000000,0x5600000),
                                                 ("P02-observed-queried-window",0xa8800000,0x8000000)):
            load=selected_base+0x80000;end=selected_base+window_bytes
            ramdisk_load=end-((len(combined_ramdisk)+4095)&~4095)-4096
            dtb_load=ramdisk_load-0x200000-4096;capacity=dtb_load-load
            if capacity<=0 or len(image)>capacity:raise ValueError("P03 exceeds owning ABL gzip/runtime bound")
            calculations.append({"basis":label,"kernel":hex(load),"initrd":hex(ramdisk_load),"dtb":hex(dtb_load),
                                 "gzip_capacity":hex(capacity),"image_size":hex(len(image)),"gap_to_dtb":hex(capacity-len(image))})
        report["instruction_model"]={"passed":True,"cases":len(model["cases"]),"report_sha256":sha(model_path.read_bytes())}
        report["owning_abl_audit"]={"report_sha256":sha(audit_path.read_bytes()),"abl_sha256":audit["abl_sha256"],
                                   "result":"gzip avail_out and image_size checked against DTBLoad-KernelLoad before handoff",
                                   "P03_recalculated_windows":calculations,"remaining_unknowns":audit["remaining_unknowns"]}
        report["independent_reviews"]={"wrapper_report_sha256":sha(wrapper_path.read_bytes()),"wrapper_bytes_sha256":sha(wrapper_bytes),
                                       "cpio_report_sha256":sha(cpio_path.read_bytes()),"memory_primitives_report_sha256":sha(crc_path.read_bytes())}
        report["package_gate"]="matched static/model evidence satisfied; hardware test and parent review remain separate"
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
