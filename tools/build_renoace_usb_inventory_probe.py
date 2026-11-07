#!/usr/bin/env python3
"""Compile the P09 original-ml_io_map GCC-read-only OFFLINE prototype.

Never runs adb/fastboot/SSH and never emits a recovery image. Reuses pinned P07
loader/bridge/ADT functions unchanged, and stages an explicit derived source tree.
P07 packaging gates are not invoked, modified, or substituted by this builder.
"""
import argparse, gzip, hashlib, importlib.util, json, re, shutil, struct, subprocess, sys, zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
MODE="full-arm-vm-init-return-original-ml-io-map-gcc-gated-dwc-inventory-p09-inventory-v1"
sha=lambda data:hashlib.sha256(data).hexdigest()
P07_BUILDER_SHA="1aa657a6ed4d7067854c856aebdaea93140c1b01aea3c0092bbd477978b06d76"
P07_SOURCE=ROOT/"device/renoace/xnu_vm_probe"
SOURCE=ROOT/"device/renoace/xnu_usb_inventory_probe"
def require(ok,msg):
    if not ok:raise ValueError(msg)
def snapshot(source):
    return {p.name:sha(p.read_bytes()) for p in sorted(source.iterdir()) if p.suffix in (".S",".c",".h",".ld")}
def all_symbols(data):
    at=32;command=None
    for _ in range(struct.unpack_from("<I",data,16)[0]):
        cmd,size=struct.unpack_from("<II",data,at)
        if cmd==2:command=struct.unpack_from("<4I",data,at+8)
        at+=size
    require(command,"Mach-O symbols absent")
    so,ns,st,ss=command;result={}
    for n in range(ns):
        index,typ,sec,desc,value=struct.unpack_from("<IBBHQ",data,so+16*n)
        if value and typ&0xe and index<ss:
            end=data.find(b"\0",st+index,st+ss)
            require(end>=0,"unterminated symbol")
            result[data[st+index:end].decode(errors="replace")]=value
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out",type=Path,default=ROOT/"out/xnu-usb-inventory-probe")
    parser.add_argument("--package",action="store_true",help="always refuses: no P09 packaging implementation")
    args=parser.parse_args()
    if args.package:parser.error("P09 packaging is unconditionally blocked pending root fresh model and independent review acceptance")
    out=args.out.resolve();require(out.is_relative_to((ROOT/"out/xnu-usb-inventory-probe").resolve()),"P09 output must stay in owned out/xnu-usb-inventory-probe")
    out.mkdir(parents=True,exist_ok=True)
    p07_file=ROOT/"tools/build_renoace_vm_probe.py";p07_hash=sha(p07_file.read_bytes())
    require(p07_hash==P07_BUILDER_SHA,"pinned P07 builder changed; review before reuse")
    spec=importlib.util.spec_from_file_location("p07_shared_builder",p07_file)
    p07=importlib.util.module_from_spec(spec);spec.loader.exec_module(p07)
    pinned=json.loads((ROOT/"out/xnu-vm-probe/build.json").read_text())
    inherited_hashes=snapshot(P07_SOURCE)
    require(inherited_hashes==pinned["source_hashes"],"P07 inherited source no longer matches reviewed P07 build")
    source=out/"compiled-source";source.mkdir(exist_ok=True)
    for name in inherited_hashes:shutil.copyfile(P07_SOURCE/name,source/name)
    for name in ("vm_gate.S","vm_gate.ld","io_snapshot.h","probe.c","xnu_control.c","xnu_control.h"):shutil.copyfile(SOURCE/name,source/name)
    data=p07.kernel_bytes();symbols_io=all_symbols(data)
    (out/"kernel-symbols.json").write_text(json.dumps({k:hex(symbols_io[k]) for k in ["_ml_io_map","_io_map","_pmap_map_bd","_pmap_map_bd_with_options","_virtual_space_start","_startup_phase"]},indent=2)+"\n")
    names={"IO_ML_IO_MAP_VA":"_ml_io_map","IO_VIRTUAL_SPACE_START_VA":"_virtual_space_start","IO_STARTUP_PHASE_VA":"_startup_phase"}
    layout={k:symbols_io[v] for k,v in names.items()}
    layout["IO_ARM_INIT_FRAME_BYTES"]=0xd0
    (source/"io_gate_layout.h").write_text("\n".join(f"#define {k} 0x{v:x}" for k,v in layout.items())+"\n")
    # Cross-check exact ml_io_map ABI wrapper and source-independent symbol VA.
    segments,_=p07.kernel_symbols(data)
    va=symbols_io["_ml_io_map"]
    off=next(s["off"]+va-s["va"] for s in segments if s["va"]<=va<s["va"]+s["fil"])
    require(data[off:off+12]==bytes.fromhex("e20080526300805204008052"),"original ml_io_map flags/prot/unmappable ABI changed")
    arm=symbols_io["_arm_init"];armoff=next(s["off"]+arm-s["va"] for s in segments if s["va"]<=arm<s["va"]+s["fil"])
    require(struct.unpack_from("<I",data,armoff)[0]==0xd10343ff,"original arm_init SUB SP,#0xd0 changed")
    source_hashes=snapshot(source);ndk=p07.NDK;commands=[]
    def run(cmd):
        args2=list(map(str,cmd));commands.append(args2)
        result=subprocess.run(args2,capture_output=True,text=True,cwd=out)
        if result.returncode:raise RuntimeError(result.stderr or result.stdout)
        return result.stdout
    bridge,bridge_report=p07.build_bridge(source,out,ndk,run)
    pack_spec=importlib.util.spec_from_file_location("p08_pack_reader",ROOT/"tools/build_renoace_probe.py")
    pack=importlib.util.module_from_spec(pack_spec);pack_spec.loader.exec_module(pack)
    private=ROOT/"local-device/20261106T115059Z";manifest=json.loads((private/"manifest.json").read_text());inputs={}
    for name in ("boot","recovery"):
        raw=(private/(name+".img")).read_bytes();require(sha(raw)==manifest["files"][name+".img"]["sha256"],"baseline carrier changed")
        hdr,parts=pack.unpack(raw);inputs[name]=(raw,hdr,parts)
    normal,header,parts=inputs["boot"];recovery,recovery_header,recovery_parts=inputs["recovery"]
    combined_ramdisk,xnu_report=p07.prepare_xnu(out,parts["ramdisk"],bridge,bridge_report,False)
    (out/"xnu_layout.h").write_text((out/"xnu_layout.h").read_text()+f"#define XNU_IO_SNAPSHOT_GATE_VA 0x{bridge_report['gate']['symbols']['mmu_io_snapshot']:x}UL\n")
    xnu_report["diagnostics_version"]=5
    xnu_report["mode"]=MODE;xnu_report["scope"]="original full VM, original ml_io_map/pmap Device map, eight GCC LDR W reads, original bootstrap-root recovery; OFFLINE ONLY"
    parts=dict(parts);parts["ramdisk"]=combined_ramdisk
    decoder=zlib.decompressobj(31);linux=decoder.decompress(parts["kernel"])
    require(decoder.eof and decoder.unused_data==parts["dtb"] and parts["dtb"]==recovery_parts["dtb"],"original gzip/DTB identity mismatch")
    code0,code1=struct.unpack_from("<II",linux);text_offset,effective,flags=struct.unpack_from("<QQQ",linux,8)
    require((text_offset,effective,flags,len(linux),code1)==(0x80000,0x37f0000,0xa,0x2fb2810,0),"Linux baseline changed")
    tail_prefix=0x23000;dtb_offset=effective+tail_prefix;dtb_capacity=0x100000;image_size=dtb_offset+dtb_capacity
    (out/"original-linux.Image").write_bytes(linux)
    build_id=sha((MODE+json.dumps(source_hashes,sort_keys=True)+sha(Path(__file__).read_bytes())+sha(linux)+p07.XNU_SHA+sha(combined_ramdisk)+json.dumps(xnu_report["patches"],sort_keys=True,separators=(",",":"))+xnu_report["ADT"]["sha256"]+sha(bridge)).encode())[:16]
    constants={"LINUX_EFFECTIVE_SIZE":effective,"LINUX_TEXT_OFFSET":text_offset,"LINUX_ORIGINAL_CODE0":code0,"DTB_OFFSET":dtb_offset,"DTB_CAPACITY":dtb_capacity,"CHAIN_IMAGE_SIZE":image_size,"NORMAL_RAMDISK_SIZE":len(parts["ramdisk"]),"XNU_PHYS_BASE":0x180004000,"XNU_WINDOW_SIZE":0x10000000}
    (out/"layout.h").write_text("\n".join(f"#define {k} 0x{v:x}" for k,v in constants.items())+f'\n#define CHAIN_BUILD_ID "{build_id}"\n')
    (out/"layout.ld").write_text("\n".join(f"{k} = 0x{v:x};" for k,v in constants.items())+"\n")
    common=[ndk/"clang.exe","--target=aarch64-none-elf","-mcpu=cortex-a55","-O2","-ffreestanding",
            "-nostdlib","-fno-builtin","-fno-pic","-fno-pie","-fno-stack-protector","-fno-jump-tables",
            "-fno-asynchronous-unwind-tables","-mgeneral-regs-only","-mstrict-align","-Wall","-Wextra","-Werror","-I",out]
    objects=[]
    for path in (source/"start.S",source/"probe.c",source/"xnu_control.c",out/"bridge_payload.S"):
        obj=out/(path.stem+".o");run(common+["-c",path,"-o",obj]);objects.append(obj)
    for obj in objects:
        reloc=run([ndk/"llvm-readelf.exe","-r",obj])
        if "R_AARCH64_ABS" in reloc:raise ValueError("absolute relocation in "+obj.name)
    elf=out/"probe.elf"
    run([ndk/"ld.lld.exe","-static","-nostdlib","-T",source/"probe.ld","--build-id=none","-N",*objects,"-o",elf])
    if run([ndk/"llvm-nm.exe","-u",elf]).strip():raise ValueError("unresolved symbols")
    if snapshot(source)!=source_hashes:raise ValueError("source changed during compile; rerun")
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
    dis=run([ndk/"llvm-objdump.exe","-d",elf]);(out/"disassembly.txt").write_text(dis)
    instructions=[]
    for line in dis.splitlines():
        match=re.match(r"\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)",line)
        if match:instructions.append(match.group(3))
    if any(re.match(r"(?:smc|hvc|svc)\b",s) for s in instructions):raise ValueError("unexpected firmware/system call")
    report={"status":"OFFLINE P09 original ml_io_map GCC read-only snapshot prototype; hardware-untested; packaging unconditionally blocked","mode":MODE,"builder_sha256":sha(Path(__file__).read_bytes()),
            "hardware_tested":False,"build_id":build_id,"constants":constants,"symbols":symbols,
            "original_linux_sha256":sha(linux),"image_sha256":sha(image),"image_bytes":len(image),
            "kernel_payload_sha256":sha(kernel),"source_hashes":source_hashes,"commands":commands,
            "source_root":str(source.relative_to(ROOT)),"inherited_p07_source_hashes":inherited_hashes,"p07_builder_sha256":p07_hash,
            "entry_contract":"EL1 or EL2, M=C=0, Image text_offset congruence and loader-owned expanded allocation",
            "refusal":"FDT/bank/carveout/initrd validation refusal restores original Linux header and original DT; unsupported EL/MMU/cache state parks",
            "linux_changes_before_entry":["code0 redirects to tail","Image image_size covers emitted tail arena"],
            "restoration":"both modified fields restored before branch to original Linux entry",
            "unknowns":["hardware acceptance of enlarged Image","Android normal boot through recovery carrier","actual native CPU feature values","real cache/interconnect behavior","exclusive EFI ownership of every selected kernel-window byte is not established by a captured memory map"],
            "instruction_model":"not yet executed by this build command"}
    report["package_gate"]="BLOCKED UNCONDITIONALLY: P09 prototype emits no recovery image and does not implement packaging. Root fresh native-model and independent review acceptance are required before separate integration."
    report["pre_guard_writes"]="P02 substrate's early context/stack writes use the loader-owned Image; high XNU window writes occur only after complete runtime FDT overlap checks"
    report["xnu"]=xnu_report
    report["io_probe"]={"physical_aperture":[0x100000,0x2f0000],"read_only":True,"whitelist_offsets":[0xf004,0xf010,0xf014,0xf018,0xf078,0xf07c,0xf050,0x8c028],"original_ml_io_map":symbols_io["_ml_io_map"],"model_fixture_is_not_hardware":True}
    report["usb_inventory_probe"]={"physical_page":0xa60c000,"page_bytes":0x1000,"register_offsets":[0x120,0x140,0x110,0x704,0x70c],"GCC_BCR_offset":0xf000,"conditional_only":True,"read_only":True}
    (out/"build.json").write_text(json.dumps(report,indent=2)+"\n")
    print("OFFLINE P09 prototype built:",build_id,"gate bytes",bridge_report["gate"]["bytes"])
    print(report["package_gate"])

if __name__=="__main__":main()
