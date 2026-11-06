#!/usr/bin/env python3
"""Build the P02 no-reset Linux logging bridge OFFLINE. Never operates a phone.

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


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ndk-bin",type=Path,default=NDK)
    ap.add_argument("--package",action="store_true")
    args=ap.parse_args()
    source=ROOT/"device/renoace/chainprobe"
    out=ROOT/"out/chainprobe";out.mkdir(parents=True,exist_ok=True)
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
    dtb_offset=effective+0x10000
    dtb_capacity=0x100000
    image_size=dtb_offset+dtb_capacity
    if image_size>=0x8000000 or image_size>=0x100000000:
        raise ValueError("tail cannot be reached/restored with the admitted instructions")
    for key in ("kernel_addr","ramdisk_addr","tags_addr","dtb_addr","page_size","header_version"):
        if header[key]!=recovery_header[key]:raise ValueError("carrier load geometry mismatch: "+key)
    (out/"original-linux.Image").write_bytes(linux)
    source_hashes={p.name:sha(p.read_bytes()) for p in source.iterdir() if p.suffix in (".S",".c",".ld")}
    build_id=sha((json.dumps(source_hashes,sort_keys=True)+sha(linux)).encode())[:16]
    constants={"LINUX_EFFECTIVE_SIZE":effective,"LINUX_TEXT_OFFSET":text_offset,
               "LINUX_ORIGINAL_CODE0":code0,"DTB_OFFSET":dtb_offset,
               "DTB_CAPACITY":dtb_capacity,"CHAIN_IMAGE_SIZE":image_size,
               "NORMAL_RAMDISK_SIZE":len(parts["ramdisk"])}
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
    for name in ("start.S","chainprobe.c"):
        obj=out/(Path(name).stem+".o");run(common+["-c",source/name,"-o",obj]);objects.append(obj)
    for obj in objects:
        reloc=run([ndk/"llvm-readelf.exe","-r",obj])
        if "R_AARCH64_ABS" in reloc:raise ValueError("absolute relocation in "+obj.name)
    elf=out/"chainprobe.elf"
    run([ndk/"ld.lld.exe","-static","-nostdlib","-T",source/"chainprobe.ld","--build-id=none","-N",*objects,"-o",elf])
    if run([ndk/"llvm-nm.exe","-u",elf]).strip():raise ValueError("unresolved symbols")
    symbol_text=run([ndk/"llvm-nm.exe","-n",elf]);symbols={}
    for line in symbol_text.splitlines():
        fields=line.split()
        if len(fields)==3 and re.fullmatch("[0-9a-fA-F]+",fields[0]):symbols[fields[2]]=int(fields[0],16)
    if symbols["chain_entry"]!=effective or symbols["_chain_end"]!=image_size or symbols["_dtb_buffer"]!=dtb_offset:
        raise ValueError("linked tail geometry mismatch")
    if symbols["_stack_top"]>dtb_offset or symbols["_bss_end"]>symbols["_stack_top"]-0x8000:
        raise ValueError("tail stack overlaps code/data or FDT")
    tailpath=out/"tail.bin";run([ndk/"llvm-objcopy.exe","-O","binary",elf,tailpath])
    tail=tailpath.read_bytes()
    if len(tail)>0x10000-0x8000:raise ValueError("tail file leaves insufficient independent stack space")
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
    report={"status":"offline experimental Linux logging bridge for review; hardware-untested; NOT XNU",
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
    report["pre_guard_writes"]="assembly context and tail-stack stores precede the C memory-map guard; gzip output is written by ABL before any probe instruction"
    if args.package:
        model_path=out/"instruction-tests.json"
        audit_path=ROOT/"out/analysis/abl-chainprobe-load-bounds.json"
        model=json.loads(model_path.read_text());audit=json.loads(audit_path.read_text())
        if not model.get("passed") or model.get("image_sha256")!=sha(image) or model.get("source_hashes")!=source_hashes:
            raise ValueError("instruction-model results do not cover this exact payload/source")
        if model.get("test_source_sha256")!=sha((source/"test_instructions.py").read_bytes()):
            raise ValueError("instruction-model test source changed; rerun the model")
        required={"EL1-SP1-relocated","EL1-SP0-fallback-base","EL2-SP1-relocated","EL2-SP0-relocated",
                  "input-DTB-overlap","initrd-overlap","reserved-memory-overlap","memreserve-overlap",
                  "wrong-SoC","preexisting-log","malformed-structure-offset","no-memory-bank",
                  "MMU-on-parks","D-cache-on-parks","exception-fallback","second-exception-parks"}
        if not required.issubset({case["name"] for case in model["cases"]}):raise ValueError("model coverage incomplete")
        backup_name=(ROOT/"local-device/bootchain-backup-latest.txt").read_text().strip()
        abl_path=(ROOT/"local-device"/backup_name/"abl.img").resolve()
        if ROOT/"local-device" not in abl_path.parents or sha(abl_path.read_bytes())!=audit["abl_sha256"]:
            raise ValueError("owning-ABL audit identity mismatch")
        candidate=audit["current_chain_candidate"]
        if candidate["image_sha256"]!=sha(image) or candidate["build_id"]!=build_id:
            raise ValueError("ABL capacity audit targets a different candidate")
        for calc in (candidate["fallback64_calculation"],candidate["captured_android_inferred_window_calculation"]):
            if int(calc["expanded_image_bytes"],0)!=len(image) or int(calc["gzip_capacity"],0)<len(image):
                raise ValueError("candidate does not fit an audited loader window")
        report["instruction_model"]={"passed":True,"cases":len(model["cases"]),"report_sha256":sha(model_path.read_bytes())}
        report["owning_abl_audit"]={"report_sha256":sha(audit_path.read_bytes()),"abl_sha256":audit["abl_sha256"],
                                   "result":"gzip avail_out and image_size checked against DTBLoad-KernelLoad before handoff",
                                   "remaining_unknowns":audit["remaining_unknowns"]}
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
                           "normal_boot_ramdisk_sha256":sha(parts["ramdisk"]),"restore_sha256":sha(recovery),
                           "untested":"normal boot kernel/ramdisk and header + current recovery DTBO + fresh unsigned recovery AVB"}
    (out/"build.json").write_text(json.dumps(report,indent=2)+"\n")
    print(f"OFFLINE model-review payload: {out/'Image.gz-dtb'}")
    print(f"Linux bytes preserved except two restored header fields; tail offset={effective:#x}, Image size={image_size:#x}.")
    print("Hardware tested: false. No phone tool was invoked.")


if __name__=="__main__":main()
