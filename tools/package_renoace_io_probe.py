#!/usr/bin/env python3
"""Fresh reviewed P08 GCC-read-only packaging. Never operates a phone.

The prototype builder remains unable to package. This separate integration
requires native P08 cases, actual wire records, primitive tests and independent
reviews of this packager and the immutable compiled candidate.
"""
import argparse,hashlib,importlib.util,json,re,struct,subprocess,sys,zlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
IO_BUILDER=ROOT/"tools/build_renoace_io_probe.py"
def sha(data):return hashlib.sha256(data).hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)
def read_json(path):return json.loads(path.read_text(encoding="utf-8"))
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
BASE_BUILDER=ROOT/"tools/build_renoace_vm_probe.py"
require(sha(BASE_BUILDER.read_bytes())=="1aa657a6ed4d7067854c856aebdaea93140c1b01aea3c0092bbd477978b06d76","reviewed P07 shared builder changed")
base=module("p08_package_shared",BASE_BUILDER)
XNU_SHA=base.XNU_SHA;GATE_OFFSET=base.GATE_OFFSET
kernel_bytes=base.kernel_bytes;kernel_symbols=base.kernel_symbols
branch_word=base.branch_word;validate_adt=base.validate_adt;cpio_entries=base.cpio_entries


def validate_prepared(out,source):
    """Bind a compiled P08 candidate to current inputs; no model claims."""
    build=read_json(out/"build.json")
    image=(out/"Image").read_bytes();layout=build["xnu"];constants=layout["constants"]
    current={p.name:sha(p.read_bytes()) for p in source.iterdir() if p.suffix in (".S",".c",".h",".ld")}
    require(current==build["source_hashes"],"current P08 source differs from build")
    require(build["builder_sha256"]==sha(IO_BUILDER.read_bytes()),"P08 builder differs from compiled candidate")
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
    require(seed==frozen.read_bytes(),"P08 seed differs from frozen P04 seed")
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
    require(decoder.eof and payload==image and decoder.unused_data==normal["dtb"],"P08 gzip/appended-DTB mismatch")
    rd=(out/"ramdisk").read_bytes();prefix=normal["ramdisk"]
    require(rd[:len(prefix)]==prefix and sha(rd)==layout["combined_ramdisk_sha256"],"normal initrd prefix or combined identity changed")
    gz=zlib.decompressobj(31);normal_cpio=gz.decompress(prefix)
    require(gz.eof and not gz.unused_data,"normal ramdisk must be one complete gzip stream")
    normal_entries,normal_end=cpio_entries(normal_cpio)
    require(not any(normal_cpio[normal_end:]),"unexpected data after original cpio trailer")
    archive=layout["archive_offset"]
    require(archive==(len(prefix)+3)&~3 and not any(rd[len(prefix):archive]),"raw archive alignment/padding changed")
    appended,end=cpio_entries(rd,archive)
    require([e["name"] for e in appended]==[".renoace-xnu-p07.macho","TRAILER!!!"] and not any(rd[end:]),"unexpected appended archive contents")
    member=appended[0]
    require(member["name"] not in {e["name"] for e in normal_entries},"appended file replaces an original initrd entry")
    require(member["mode"]==0o100444 and member["nlink"]==1,"appended member mode/link count changed")
    require(member["data_offset"]==layout["member_data_offset"]==constants["XNU_INITRD_OFFSET"] and member["bytes"]==len(macho),"Mach-O member layout mismatch")
    embedded=rd[member["data_offset"]:member["data_offset"]+member["bytes"]]
    require(embedded==macho and member["sha256"]==XNU_SHA and zlib.crc32(embedded)==constants["XNU_FILE_CRC32"],"Mach-O payload CRC/SHA mismatch")
    cpio={"passed":True,"scope":"fresh offline parse of actual P08 inputs; no initramfs execution",
          "build_id":build["build_id"],"image_sha256":build["image_sha256"],"combined_ramdisk_sha256":sha(rd),
          "normal_gzip_sha256":sha(prefix),"normal_gzip_bytes":len(prefix),"normal_entries":len(normal_entries),
          "archive_offset":archive,"padding_bytes":archive-len(prefix),"appended_entries":appended,
          "kernel_sha256":XNU_SHA,"base_DTB_sha256":sha(normal["dtb"]),"base_DTB_copies_identical":True}
    (out/"cpio-validation.json").write_text(json.dumps(cpio,indent=2)+"\n")
    prep={"passed":True,"hardware_tested":False,"scope":"fresh static P08 input/layout binding; not instruction-model or device execution",
          "build_id":build["build_id"],"image_sha256":sha(image),"source_hashes":current,"kernel_sha256":XNU_SHA,
          "bridge_sha256":sha(bridge),"bridge_resume_count":3,"kernel_patch_count":len(layout["patches"]),"vector_slots":16,
          "ADT_sha256":sha(adt),"cpio_validation_sha256":sha((out/"cpio-validation.json").read_bytes()),
          "package_gate":"BLOCKED: static validation alone cannot authorize P08 packaging"}
    (out/"prepare-validation.json").write_text(json.dumps(prep,indent=2)+"\n")
    return build,prep,cpio


def evidence(out):
    build,prep,cpio=validate_prepared(out,out/"compiled-source")
    require(build["xnu"]["diagnostics_version"]==4 and build.get("io_probe",{}).get("read_only") is True,"P08 schema or operation changed")
    require(build["io_probe"]["whitelist_offsets"]==[0xf004,0xf010,0xf014,0xf018,0xf078,0xf07c,0xf050,0x8c028],"GCC whitelist changed")
    inherited={p.name:sha(p.read_bytes()) for p in (ROOT/"device/renoace/xnu_vm_probe").iterdir() if p.suffix in (".S",".c",".h",".ld")}
    require(inherited==build["inherited_p07_source_hashes"] and build["p07_builder_sha256"]==sha(BASE_BUILDER.read_bytes()),"P07 inherited inputs changed")
    own=ROOT/"device/renoace/xnu_io_probe"
    for name in ("vm_gate.S","vm_gate.ld","io_snapshot.h","probe.c","xnu_control.c","xnu_control.h"):
        require(sha((own/name).read_bytes())==build["source_hashes"][name],"P08 source override changed: "+name)
    native=read_json(out/"native-io-tests.json")
    require(native.get("passed") is True and native.get("build_id")==build["build_id"] and native.get("image_sha256")==build["image_sha256"] and native.get("source_hashes")==build["source_hashes"] and native.get("builder_sha256")==build["builder_sha256"],"P08 native model identity mismatch")
    require(native.get("test_source_sha256")==sha((own/"test_instructions.py").read_bytes()) and native.get("p07_test_source_sha256")==sha((ROOT/"device/renoace/xnu_vm_probe/test_instructions.py").read_bytes()),"P08 model/helper changed")
    require(native.get("native_mmu") is True and native.get("translation_register_hooks") is False and native.get("virtual_alias_api_mappings") is False,"P08 native translation coverage missing")
    require(native.get("dependency_hashes"),"native dependencies absent")
    for rel,digest in native["dependency_hashes"].items():
        path=(ROOT/rel).resolve();require(path.is_relative_to(ROOT.resolve()) and sha(path.read_bytes())==digest,"native dependency changed: "+rel)
    names={"positive_native_io_snapshot","zero_map","invalid_par","bad_stack","synthetic_map_fault","synthetic_first_read_fault","synthetic_partial_read_fault"}
    cases=native.get("cases",[])
    require(len(cases)==len(names) and {x.get("name") for x in cases}==names,"P08 required cases absent")
    reader=module("p08_package_reader",ROOT/"tools/capture_renoace_chainprobe.py")
    for case in cases:
        require(case.get("passed") is True and case.get("errors")==[] and case.get("native_faults")==[],"P08 model failure: "+case.get("name","?"))
        require(case.get("caller_state_exact") is True and case.get("FP_SIMD_exact") is True and case.get("CNTKCTL_exact") is True,"P08 caller restoration incomplete")
        require(case.get("mmio_write_attempts")==[],"P08 model wrote a peripheral")
        raw=(out/"model-tests/max"/(case["name"]+".bin")).read_bytes();parsed=reader.parse_record(raw,build["build_id"],build)
        require(sha(raw)==case["record"]["sha256"] and len(raw)==case["record"]["bytes"] and parsed["registers"]==case["record"]["fields"],"P08 raw model record binding mismatch")
        expected_status=0 if case["name"]=="positive_native_io_snapshot" else 14 if case["name"]=="bad_stack" else 18 if case["name"].startswith("synthetic_") else 25
        require(int(parsed["registers"]["xnu_status"],0)==expected_status,"P08 raw refusal status differs")
        if case["name"]=="positive_native_io_snapshot":
            require(parsed.get("xnu_io_verified") is True and parsed.get("xnu_verification_failures")==[] and case.get("injections")==[],"P08 positive wire/injection checks failed")
            require(case.get("original_ml_io_map_executed") is True,"original ml_io_map not executed")
            require(case.get("original_io_map_device_pages")==496,"original Device-page mapping not fully checked")
            reads=case.get("mmio_reads",[]);require(len(reads)==8,"positive MMIO read count differs")
            for i,(read,offset) in enumerate(zip(reads,build["io_probe"]["whitelist_offsets"])):
                require(int(read["pa"],0)==0x100000+offset and int(read["offset"],0)==offset and read["bytes"]==4 and int(read["pc"],0)==build["xnu"]["bridge"]["gate"]["symbols"]["mmu_io_read"] and int(read["value"],0)==int(parsed["registers"][f"io_value_{i}"],0) and "NOT hardware" in read["origin"],"P08 physical read provenance mismatch")
        else:
            require(parsed.get("xnu_io_verified") is False and case.get("negative_refusal_verified") is True and case.get("injections"),"P08 negative not honestly refused")
            if case["name"].startswith("synthetic_"):
                f=parsed["registers"];require(int(f["mmu_state_verified"],0)==1 and int(f["c_fp_verified"],0)==1 and int(f["mmu_status"],0)==2,"fault caller restoration unverified")
    primitive_path=ROOT/"out/xnu-io-primitive-tests/results.json";primitive=read_json(primitive_path)
    require(primitive.get("passed")==190 and primitive.get("failed")==0 and primitive.get("build_id")==build["build_id"] and primitive.get("image_sha256")==build["image_sha256"] and primitive.get("source_hashes")==build["source_hashes"] and primitive.get("test_sha256")==sha((own/"test_primitives.py").read_bytes()),"P08 compiled primitive evidence absent/stale")
    reviews=[]
    for name in ("p08-independent-integration-review.json","p08-io-asm-review.json"):
        path=ROOT/"out/analysis"/name;review=read_json(path)
        require(review.get("passed") is True and review.get("build_id")==build["build_id"] and review.get("image_sha256")==build["image_sha256"] and review.get("code_blockers")==[],"P08 independent review absent/stale: "+name)
        if name=="p08-independent-integration-review.json":
            require(review.get("builder_sha256")==build["builder_sha256"] and review.get("packager_sha256")==sha(Path(__file__).read_bytes()) and all(review.get(k) is True for k in ("all_patches_checked","ABL_and_carrier_bounds","Device_page_checks","MMIO_readonly_whitelist","source_pins")),"P08 integration/packager review incomplete")
        reviews.append({"name":name,"sha256":sha(path.read_bytes())})
    return {"passed":True,"build_id":build["build_id"],"image_sha256":build["image_sha256"],"builder_sha256":build["builder_sha256"],"packager_sha256":sha(Path(__file__).read_bytes()),"native_model_sha256":sha((out/"native-io-tests.json").read_bytes()),"primitive_sha256":sha(primitive_path.read_bytes()),"reader_sha256":sha((ROOT/"tools/capture_renoace_chainprobe.py").read_bytes()),"reviews":reviews,"hardware_tested":False}


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument("--package",action="store_true");args=ap.parse_args()
    out=ROOT/"out/xnu-io-probe";accepted=evidence(out)
    (out/"package-evidence.json").write_text(json.dumps(accepted,indent=2)+"\n",encoding="utf-8",newline="\n")
    if not args.package:print("P08 fresh integration gates passed; no carrier emitted");return
    build=read_json(out/"build.json");pack=module("p08_boot_parts",ROOT/"tools/build_renoace_probe.py")
    private=ROOT/"local-device/20261106T115059Z";normal=(private/"boot.img").read_bytes();recovery=(private/"recovery.img").read_bytes()
    header,parts=pack.unpack(normal);recovery_header,recovery_parts=pack.unpack(recovery)
    aosp=ROOT/"references/aosp-tools";pins=read_json(aosp/"sources.json")
    for name in ("mkbootimg-v2.py","avbtool.py"):require(sha((aosp/name).read_bytes())==pins[name]["sha256"],"AOSP tool pin mismatch")
    legacy=(aosp/"mkbootimg-v2.py").read_text();old="return (image_size + page_size - 1) / page_size";require(legacy.count(old)==1,"legacy division fix mismatch")
    packer=out/"mkbootimg-python3.py";packer.write_text(legacy.replace(old,old.replace(" / "," // ")),encoding="utf-8",newline="\n")
    for name,data in (("dtb",parts["dtb"]),("recovery_dtbo",recovery_parts["recovery_dtbo"])):(out/name).write_bytes(data)
    commands=[]
    def run(cmd):
        command=list(map(str,cmd));commands.append(command);p=subprocess.run(command,cwd=out,capture_output=True,text=True,timeout=120);require(p.returncode==0,p.stdout+p.stderr);return p.stdout
    proposed=out/"recovery.img"
    run([sys.executable,packer,"--header_version","2","--pagesize","4096","--base","0","--kernel_offset",header["kernel_addr"],"--ramdisk_offset",header["ramdisk_addr"],"--tags_offset",header["tags_addr"],"--dtb_offset",header["dtb_addr"],"--kernel",out/"Image.gz-dtb","--ramdisk",out/"ramdisk","--recovery_dtbo",out/"recovery_dtbo","--dtb",out/"dtb","--output",proposed])
    result=bytearray(proposed.read_bytes());keep=bytearray(normal[:4096])
    for a,b in ((8,12),(16,20),(576,608),(1632,1644)):keep[a:b]=result[a:b]
    result[:4096]=keep;proposed.write_bytes(result)
    _,actual=pack.unpack(result);expected={"kernel":(out/"Image.gz-dtb").read_bytes(),"ramdisk":(out/"ramdisk").read_bytes(),"second":b"","recovery_dtbo":recovery_parts["recovery_dtbo"],"dtb":parts["dtb"]}
    require(actual==expected and result[64:576]+result[608:1632]==normal[64:576]+normal[608:1632],"P08 carrier parts/command line mismatch")
    run([sys.executable,aosp/"avbtool.py","add_hash_footer","--image",proposed,"--partition_name","recovery","--partition_size",len(recovery),"--algorithm","NONE","--salt","00"*32])
    (out/"avb-check.txt").write_text(run([sys.executable,aosp/"avbtool.py","verify_image","--image",proposed]),encoding="utf-8")
    final=proposed.read_bytes();pack.unpack(final)
    build["carrier"]={"file":"recovery.img","sha256":sha(final),"bytes":len(final),"restore_sha256":sha(recovery),"scope":"temporary read-only GCC snapshot through original XNU VM and Device mapping; no USB/controller/PHY/SMMU/DMA writes"}
    build["package_evidence"]=accepted;build["package_gate"]="Fresh P08 native IO, refusal/fault, Device mapping, raw wire, primitives and independent integration gates passed; phone proof separate"
    build["package_commands"]=commands;(out/"build.json").write_text(json.dumps(build,indent=2)+"\n",encoding="utf-8",newline="\n")
    print("P08 gated recovery carrier emitted",build["carrier"]["sha256"])


if __name__=="__main__":main()
