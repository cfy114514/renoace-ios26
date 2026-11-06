#!/usr/bin/env python3
"""Build the P05 controlled arm_init BRK exception candidate OFFLINE. Never operates a phone.

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
XNU_SHA="1295a653bc235d0c11d18ea7a0fc155209fd87396118196ecc8b87e8096f68b8"
P04_FROZEN=ROOT/"out/xnu-mmu-probe-attempt1"
P04_BUILD_ID="6941903d95f8c58a"
P04_IMAGE_SHA="55e55529997728dbc9ad5f44d1b313c15cd9c7d688cc0e141fd5573c52846c49"
FAULT_MODE="native-BRK-trigger"
FAULT_IMMEDIATE=0x505
FAULT_WORD=0xd420a0a0
EXPECTED_EXCEPTION={"immediate":FAULT_IMMEDIATE,"esr":0xf2000505,
                    "elr_va":0xfffffff007b334b8,"slot":0,"checkpoint":"arm_init_brk_return"}
MODEL_DEPENDENCY="device/renoace/xnu_mmu_probe/test_instructions.py"
MODEL_DEPENDENCY_SHA="e4ebd1c5c78066c101f9d111143a93087491f7323819881ce2312226bbcaba67"
P05_CASES={"positive_native_brk","private_patch_refusal","source_crc_refusal","reserved_window_refusal",
           "bad_table_descriptor","bounded_time_refusal","table_guard_deadline","injected_pre_mmu_fault",
           "crc_feature_refusal"}


def require(condition,message):
    if not condition:raise ValueError(message)


def read_json(path):
    if not path.is_file():raise ValueError("required evidence missing: "+str(path))
    return json.loads(path.read_text())


def p04_baseline():
    """Pin the completed P04 comparison artifact; never mutate it."""
    baseline=read_json(P04_FROZEN/"build.json")
    require(baseline.get("build_id")==P04_BUILD_ID and baseline.get("image_sha256")==P04_IMAGE_SHA,
            "frozen P04 comparison identity changed")
    require(baseline["xnu"]["source_sha256"]==XNU_SHA,"frozen P04 kernel generation changed")
    return baseline


def validate_p05_variant(layout,bridge,seed):
    """Bind the sole private BRK patch and unchanged bridge/ADT seed to P04."""
    baseline=p04_baseline();original=baseline["xnu"]
    require(layout.get("mode")==FAULT_MODE and layout.get("expected_exception")==EXPECTED_EXCEPTION,
            "P05 exception variant/expectations changed")
    require(layout["constants"].get("XNU_EXPECTED_EXCEPTION_ESR")==EXPECTED_EXCEPTION["esr"],
            "P05 expected ESR macro changed")
    require(bridge==(P04_FROZEN/"mmu_bridge.bin").read_bytes() and sha(bridge)==original["bridge"]["sha256"],
            "P05 bridge differs from completed P04")
    require(seed==(P04_FROZEN/"build-seed.bin").read_bytes() and len(seed)==256 and sha(seed)==original["ADT"]["seed_sha256"],
            "P05 must retain the frozen 256-byte P04 seed")
    expected_patches=original["patches"];patches=layout["patches"]
    require(len(patches)==len(expected_patches)==37,"P05 kernel patch count changed")
    arm=layout["constants"]["XNU_ARM_INIT_OFFSET"]
    require(layout["constants"]["XNU_LINK_BASE"]+arm==EXPECTED_EXCEPTION["elr_va"],"P05 BRK ELR changed")
    for current,prior in zip(patches,expected_patches):
        require(current["offset"]==prior["offset"],"P05 patch order/site changed")
        if current["offset"]==arm:
            require(current["original"]==prior["original"]==0xd10343ff and
                    current["file_offset"]==prior["file_offset"] and current["replacement"]==FAULT_WORD and
                    current["bridge_symbol"] is None,"P05 arm_init must be exactly private BRK #0x505")
        else:require(current==prior,"P05 changed a non-arm_init P04 patch")


def compute_build_id(source_hashes,linux,ramdisk,layout,bridge):
    variant={"mode":FAULT_MODE,"immediate":FAULT_IMMEDIATE,"patches":layout["patches"]}
    inputs=json.dumps(source_hashes,sort_keys=True)+sha(linux)+XNU_SHA+sha(ramdisk)+layout["ADT"]["sha256"]+sha(bridge)
    return sha((inputs+json.dumps(variant,sort_keys=True,separators=(",",":"))).encode())[:16]


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
    """Freshly bind existing inputs/layout to the current Image; no compilation."""
    build=read_json(out/"build.json")
    image=(out/"Image").read_bytes();layout=build["xnu"];constants=layout["constants"]
    current={p.name:sha(p.read_bytes()) for p in source.iterdir() if p.suffix in (".S",".c",".h",".ld")}
    require(current==build["source_hashes"],"current P05 source differs from build")
    require(sha(image)==build["image_sha256"],"current Image identity mismatch")
    require(layout["source_sha256"]==XNU_SHA,"wrong XNU generation")
    kernel_path=ROOT/"out/cloud-kernel/42271869198/extracted/build/renoace/kernel/mach.development.bcm2837.unstripped.noctf"
    macho=kernel_path.read_bytes();require(sha(macho)==XNU_SHA,"pinned fresh Mach-O changed")
    spec=importlib.util.spec_from_file_location("p05_validation_pack",ROOT/"tools/build_renoace_probe.py")
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
    require(decoder.eof and payload==image and decoder.unused_data==normal["dtb"],"P05 gzip/appended-DTB mismatch")
    rd=(out/"ramdisk").read_bytes();prefix=normal["ramdisk"]
    require(rd[:len(prefix)]==prefix and sha(rd)==layout["combined_ramdisk_sha256"],"normal initrd prefix or combined identity changed")
    gz=zlib.decompressobj(31);normal_cpio=gz.decompress(prefix)
    require(gz.eof and not gz.unused_data,"normal ramdisk must be one complete gzip stream")
    normal_entries,normal_end=cpio_entries(normal_cpio)
    require(not any(normal_cpio[normal_end:]),"unexpected data after original cpio trailer")
    archive=layout["archive_offset"]
    require(archive==(len(prefix)+3)&~3 and not any(rd[len(prefix):archive]),"raw archive alignment/padding changed")
    appended,end=cpio_entries(rd,archive)
    require([e["name"] for e in appended]==[".renoace-xnu-p05.macho","TRAILER!!!"] and not any(rd[end:]),"unexpected appended archive contents")
    member=appended[0]
    require(member["name"] not in {e["name"] for e in normal_entries},"appended file replaces an original initrd entry")
    require(member["mode"]==0o100444 and member["nlink"]==1,"appended member mode/link count changed")
    require(member["data_offset"]==layout["member_data_offset"]==constants["XNU_INITRD_OFFSET"] and member["bytes"]==len(macho),"Mach-O member layout mismatch")
    embedded=rd[member["data_offset"]:member["data_offset"]+member["bytes"]]
    require(embedded==macho and member["sha256"]==XNU_SHA and zlib.crc32(embedded)==constants["XNU_FILE_CRC32"],"Mach-O payload CRC/SHA mismatch")
    cpio={"passed":True,"scope":"fresh offline parse of actual P05 inputs; no initramfs execution",
          "build_id":build["build_id"],"image_sha256":build["image_sha256"],"combined_ramdisk_sha256":sha(rd),
          "normal_gzip_sha256":sha(prefix),"normal_gzip_bytes":len(prefix),"normal_entries":len(normal_entries),
          "archive_offset":archive,"padding_bytes":archive-len(prefix),"appended_entries":appended,
          "kernel_sha256":XNU_SHA,"base_DTB_sha256":sha(normal["dtb"]),"base_DTB_copies_identical":True}
    (out/"cpio-validation.json").write_text(json.dumps(cpio,indent=2)+"\n")
    bridge=(out/"mmu_bridge.bin").read_bytes();raw=(out/"mmu_bridge.raw.bin").read_bytes();br=layout["bridge"]
    require(sha(bridge)==br["sha256"] and sha(raw)==br["raw_sha256"],"bridge input identity mismatch")
    repaired=bytearray(raw)
    def branch_target(word,pc):
        require(word&0xfc000000==0x14000000,"expected immediate B")
        delta=word&0x3ffffff
        if delta&0x2000000:delta-=0x4000000
        return pc+delta*4
    require(len(br["resume_patches"])==2,"bridge must have two resume patches")
    for item in br["resume_patches"]:
        off=item["blob_offset"]
        require(struct.unpack_from("<I",raw,off)[0]==item["original"],"bridge resume original mismatch")
        require(branch_target(item["replacement"],constants["XNU_BLOB_OFFSET"]+off)==item["target_kernel_offset"],"wrong bridge resume target")
        struct.pack_into("<I",repaired,off,item["replacement"])
    require(repaired==bridge,"unexpected bridge mutation beyond two resumes")
    for name in ("mmu_bridge_start","mmu_bridge_vectors"):require(br["symbols"][name]==0,"bridge vector origin changed")
    for n in range(16):require(br["symbols"][f"mmu_bridge_fault_{n}"]==n*0x80,"bridge vector stride changed")
    require(br["symbols"]["mmu_bridge_context"]+0x800==len(bridge)==br["symbols"]["mmu_bridge_end"]<=0x10000,"bridge context/end bounds changed")
    require(len(layout["patches"])==37 and len({p["offset"] for p in layout["patches"]})==37,"kernel patch count/overlap")
    for patch in layout["patches"]:
        require(struct.unpack_from("<I",macho,patch["file_offset"])[0]==patch["original"],"kernel patch original mismatch")
        if patch["bridge_symbol"]:
            require(branch_target(patch["replacement"],patch["offset"])==constants["XNU_BLOB_OFFSET"]+br["symbols"][patch["bridge_symbol"]],"kernel branch target mismatch")
        elif patch["offset"]==constants["XNU_ARM_INIT_OFFSET"]:
            require(patch["original"]==0xd10343ff and patch["replacement"]==FAULT_WORD,"private arm_init BRK changed")
        else:require(patch["offset"]==0x501348 and patch["replacement"]==0xd503201f,"unexpected non-branch patch")
    adt=(out/"renoace.adt").read_bytes();args=(out/"boot-args.bin").read_bytes();seed=(out/"build-seed.bin").read_bytes()
    require(sha(adt)==layout["ADT"]["sha256"] and sha(args)==layout["boot_args"]["sha256"],"ADT/boot_args identity mismatch")
    require(len(seed)==256 and sha(seed)==layout["ADT"]["seed_sha256"],"persisted ADT seed changed")
    validate_p05_variant(layout,bridge,seed)
    require(build.get("mode")==FAULT_MODE and build.get("expected_exception")==EXPECTED_EXCEPTION,"build variant identity changed")
    require(compute_build_id(current,linux,rd,layout,bridge)==build["build_id"] and build["build_id"]!=P04_BUILD_ID,
            "P05 build identity does not bind mode, immediate and serialized patch table")
    require(len(args)==0x480 and struct.unpack_from("<HH",args)==(2,2),"boot_args ABI mismatch")
    require(struct.unpack_from("<Q",args,0x60)[0]==constants["XNU_LINK_BASE"]+constants["XNU_ADT_OFFSET"] and struct.unpack_from("<I",args,0x68)[0]==len(adt),"boot_args ADT pointer/size mismatch")
    prep={"passed":True,"hardware_tested":False,"scope":"fresh static P05 input/layout binding; not native-MMU or device execution",
          "build_id":build["build_id"],"image_sha256":sha(image),"source_hashes":current,"kernel_sha256":XNU_SHA,
          "bridge_sha256":sha(bridge),"bridge_resume_count":2,"kernel_patch_count":37,"vector_slots":16,
          "mode":FAULT_MODE,"expected_exception":EXPECTED_EXCEPTION,"P04_reference_build_id":P04_BUILD_ID,
          "ADT_sha256":sha(adt),"cpio_validation_sha256":sha((out/"cpio-validation.json").read_bytes())}
    (out/"prepare-validation.json").write_text(json.dumps(prep,indent=2)+"\n")
    return build,prep,cpio


def validate_instruction_model(model_path,build,source,cpu):
    model=read_json(model_path)
    require(model.get("passed") is True and model.get("partial") is False,"complete P05 all-case model has not passed")
    require(model.get("cpu_model")==cpu.upper(),"P05 model CPU profile mismatch")
    require(model.get("variant")==FAULT_MODE and model.get("expected_exception")==EXPECTED_EXCEPTION,
            "model targets a different controlled exception variant")
    require(model.get("native_brk_trigger") is True and model.get("synthetic_exception_frame") is True and
            model.get("synthetic_handler_return") is True and model.get("native_exception_vector_delivery") is False,
            "P05 requires a native BRK trigger with explicitly synthetic exception-frame/handler-return model")
    require(model.get("native_mmu") is True and model.get("virtual_alias_api_mappings") is False and model.get("translation_register_hooks") is False,"model does not establish the required native-MMU path")
    require(model.get("build_id")==build["build_id"] and model.get("image_sha256")==build["image_sha256"] and model.get("source_hashes")==build["source_hashes"],"P05 model identity/source mismatch")
    require(model.get("test_source_sha256")==sha((source/"test_instructions.py").read_bytes()),"P05 model source changed")
    dependencies={str(name).replace("\\","/"):digest for name,digest in model.get("dependencies",{}).items()}
    require(dependencies=={MODEL_DEPENDENCY:MODEL_DEPENDENCY_SHA} and
            sha((ROOT/MODEL_DEPENDENCY).read_bytes())==MODEL_DEPENDENCY_SHA,
            "P05 instruction model dependency changed or is unbound")
    cases=model.get("cases",[])
    require(len(cases)==len(P05_CASES) and {c.get("name") for c in cases}==P05_CASES and all(c.get("passed") is True for c in cases),"P05 native-MMU case coverage incomplete")
    limitations=" ".join(str(x).lower() for x in model.get("modeled_not_verified",[]))
    require("synthetic" in limitations and "exception" in limitations and "vector" in limitations and "return" in limitations,
            "model must label synthetic architecture vector/frame delivery and handler return")
    positive=next(c for c in cases if c["name"]=="positive_native_brk")
    events={e.get("event") for e in positive.get("events",[])}
    require({"native_brk_detected_no_vector_dispatch","explicit_synthetic_delivery","actual_high_vector_slot0",
             "actual_blob_fault_slot0","actual_fault_common"}<=events,"P05 native trigger/synthetic delivery/handler checkpoints missing")
    fields=positive.get("record",{}).get("fields",{})
    def field(name):
        value=fields.get(name)
        return int(value,0) if isinstance(value,str) else value
    require(field("xnu_status")==0 and field("mmu_status")==2 and field("mmu_exception_slot")==EXPECTED_EXCEPTION["slot"] and
            field("mmu_fault_depth")==1 and field("mmu_esr")==EXPECTED_EXCEPTION["esr"] and
            field("mmu_elr")==EXPECTED_EXCEPTION["elr_va"],"P05 positive exception record differs")
    return model


def p05_package_evidence(out,source):
    build,prep,cpio=validate_prepared(out,source)
    model_path=out/"instruction-tests.json"
    model_paths={cpu:out/("instruction-tests-"+cpu+".json") for cpu in ("max","a72")}
    models={cpu:validate_instruction_model(path,build,source,cpu) for cpu,path in model_paths.items()}
    require(model_path.is_file() and model_path.read_bytes()==model_paths["max"].read_bytes(),
            "canonical P05 instruction-tests.json must exactly match the complete MAX report")
    model=models["max"]
    require(models["max"]["test_source_sha256"]==models["a72"]["test_source_sha256"] and
            models["max"]["dependencies"]==models["a72"]["dependencies"],"P05 CPU reports do not share test/dependency identities")
    review_path=ROOT/"out/analysis/p05-independent-integration-review.json";review=read_json(review_path)
    require(review.get("build_id")==build["build_id"] and review.get("image_sha256")==build["image_sha256"],"independent P05 review is stale")
    require(review.get("variant")==FAULT_MODE and review.get("expected_exception")==EXPECTED_EXCEPTION and
            review.get("source_hashes")==build["source_hashes"],"independent P05 review variant/source binding missing")
    require(review.get("reviewer")=="root" and review.get("independent_of_builder") is True,
            "P05 requires an independent root integration review")
    require(review.get("code_blockers")==[] and review.get("checks") and all(v is True for v in review["checks"].values()),"independent integration checks have unresolved findings")
    require(len(review.get("kernel_patch_checks",[]))==37 and all(p.get("ok") is True for p in review["kernel_patch_checks"]),"independent kernel-patch review incomplete")
    require(len(review.get("resume_checks",[]))==2 and all(p.get("ok") is True for p in review["resume_checks"]),"independent bridge-resume review incomplete")
    abi_path=ROOT/"out/mmu-bridge/build.json";abi=read_json(abi_path);br=build["xnu"]["bridge"]
    require(abi.get("sha256")==br["raw_sha256"] and abi.get("bytes")==br["bytes"],"bridge ABI report targets other code")
    require(abi.get("field_offset_assertions")==131 and abi.get("relocations","").strip()=="There are no relocations in this file.","bridge ABI/no-relocation check missing")
    require(all(build["source_hashes"].get(n)==v for n,v in abi.get("sources",{}).items()) and set(abi.get("sources",{}))=={"mmu_bridge.S","mmu_bridge.h","mmu_bridge.ld"},"bridge ABI source binding mismatch")
    for name,value in abi["symbols"].items():
        if name.startswith("mmu_bridge_"):
            require(br["symbols"].get(name)==(int(value,0) if isinstance(value,str) else value),"bridge export layout mismatch")
    primitive_path=ROOT/"out/xnu-fault-primitive-tests/results.json";primitive=read_json(primitive_path)
    require(primitive.get("build_id")==build["build_id"] and primitive.get("image_sha256")==build["image_sha256"] and primitive.get("source_hashes")==build["source_hashes"],"P05 primitive evidence identity mismatch")
    require(primitive.get("passed")==190 and primitive.get("failed")==0 and len(primitive.get("cases",[]))==190 and all(c.get("passed") is True for c in primitive["cases"]),"P05 primitive cases incomplete")
    require(primitive.get("test_sha256")==sha((source/"test_primitives.py").read_bytes()),"P05 primitive test source changed")
    require(primitive.get("elf_sha256")==sha((out/"probe.elf").read_bytes()),"P05 primitive ELF identity mismatch")
    image=(out/"Image").read_bytes()
    for desc in primitive["functions"].values():
        offset=int(desc["offset"],0) if isinstance(desc["offset"],str) else desc["offset"]
        require(sha(image[offset:offset+desc["bytes"]])==desc["sha256"],"primitive compiled-byte binding mismatch")
    audit_path=ROOT/"out/analysis/abl-chainprobe-load-bounds.json";audit=read_json(audit_path)
    backup_name=(ROOT/"local-device/bootchain-backup-latest.txt").read_text().strip();abl=(ROOT/"local-device"/backup_name/"abl.img").resolve()
    require(ROOT/"local-device" in abl.parents and sha(abl.read_bytes())==audit["abl_sha256"],"owning ABL identity mismatch")
    require(audit["fallback_constants"]["0x47a60"]=="0x80000" and audit["fallback_constants"]["0x47a64"]=="0x5600000","owning ABL formula constants changed")
    windows=[];rdsize=build["xnu"]["combined_ramdisk_bytes"]
    for label,base,span in (("audited-64bit-fallback",0x80000000,0x5600000),("P02-observed-queried-window",0xa8800000,0x8000000)):
        kernel=base+0x80000;ramdisk=base+span-((rdsize+4095)&~4095)-4096;dtb=ramdisk-0x200000-4096;capacity=dtb-kernel
        require(0<len(image)<=capacity,"P05 exceeds owning ABL gzip/runtime bound")
        windows.append({"basis":label,"kernel":hex(kernel),"initrd":hex(ramdisk),"dtb":hex(dtb),"capacity":hex(capacity),"image_bytes":len(image),"gap":hex(capacity-len(image))})
    return {"passed":True,"build_id":build["build_id"],"image_sha256":build["image_sha256"],
            "variant":FAULT_MODE,"expected_exception":EXPECTED_EXCEPTION,
            "model":{"sha256":sha(model_path.read_bytes()),"cases":sorted(P05_CASES),"native_mmu":True,"virtual_alias_api_mappings":False,"translation_register_hooks":False,
                     "native_brk_trigger":True,"synthetic_exception_frame":True,"synthetic_handler_return":True,"native_exception_vector_delivery":False,
                     "test_source_sha256":model["test_source_sha256"],"dependencies":model["dependencies"],
                     "cpu_reports":{cpu:{"sha256":sha(path.read_bytes()),"cpu_model":models[cpu]["cpu_model"]} for cpu,path in model_paths.items()}},
            "fault_scope":"BRK #0x505 trigger is native in Unicorn; architectural vector delivery, exception-frame injection and handler return are synthetic model evidence; real native exception-vector delivery is NOT established",
            "integration_review_sha256":sha(review_path.read_bytes()),"bridge_ABI_report_sha256":sha(abi_path.read_bytes()),
            "primitive_report_sha256":sha(primitive_path.read_bytes()),"primitive_passed":190,
            "prepare_validation_sha256":sha((out/"prepare-validation.json").read_bytes()),"cpio_validation_sha256":sha((out/"cpio-validation.json").read_bytes()),
            "owning_ABL_audit_sha256":sha(audit_path.read_bytes()),"ABL_sha256":audit["abl_sha256"],"P05_loader_windows":windows,
            "hardware_tested":False}


def newc_entry(name,data,mode=0o100444):
    filename=name.encode()+b"\0"
    fields=[1,mode,0,0,1,0,len(data),0,0,0,0,len(filename),0]
    header=b"070701"+b"".join(f"{n:08x}".encode() for n in fields)+filename
    header+=bytes((-len(header))%4)
    return header+data+bytes((-len(data))%4),len(header)


def import_pinned(name,path,expected):
    if sha(path.read_bytes())!=expected:raise ValueError("pinned ADT helper changed: "+str(path))
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def make_adt(out,package=False):
    adt=import_pinned("p05_adt",ROOT/"references/ios-flame/tools/adt.py","43d91d2e4fb0a78190a610b4bab7c206489cdede797bfc37175fb2f18367ac00")
    zeta=import_pinned("p05_nvram",ROOT/"references/UniXNU-zeta/scripts/make-zeta-adt.py","0e8fd0343e7f15faacd0ea39b1547117e68ea0258431f37c5a5b79e5340ecf40")
    seed_path=out/"build-seed.bin"
    baseline=p04_baseline()
    frozen_seed=(P04_FROZEN/"build-seed.bin").read_bytes()
    require(len(frozen_seed)==256 and sha(frozen_seed)==baseline["xnu"]["ADT"]["seed_sha256"],"frozen P04 ADT seed changed")
    if not seed_path.exists():
        if package:raise ValueError("package requires the persisted build seed")
        with seed_path.open("xb") as stream:stream.write(frozen_seed)
    seed=seed_path.read_bytes()
    if len(seed)!=256 or not any(seed) or seed!=frozen_seed:raise ValueError("P05 seed differs from the frozen 256-byte P04 seed")
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
        ("ranges",struct.pack("<QQQ",0,0x17000000,0x08000000))],[node("intc",[("compatible",b"arm,gic-v3\0"),
        ("reg",struct.pack("<4Q",0xa00000,0x10000,0xa60000,0x100000)),("redistributor-stride",u64(0x20000))])])])
    data=adt.serialize(tree);again,end=adt.parse(data)
    if end!=len(data) or adt.serialize(again)!=data:raise ValueError("ADT roundtrip failed")
    if len(next(n for n in again.children if n.name=="chosen").prop("random-seed"))!=256:raise ValueError("ADT seed missing")
    (out/"renoace.adt").write_bytes(data)
    return data,command,sha(seed)


def branch_word(source,target):
    delta=target-source
    if delta%4 or not -0x8000000<=delta<0x8000000:raise ValueError("branch out of range")
    return 0x14000000|((delta//4)&0x3ffffff)


def build_bridge(source,out,ndk,run):
    obj=out/"mmu_bridge.o";elf=out/"mmu_bridge.elf";raw=out/"mmu_bridge.raw.bin"
    run([ndk/"clang.exe","--target=aarch64-none-elf","-mcpu=cortex-a55","-ffreestanding","-nostdlib","-I",source,
         "-c",source/"mmu_bridge.S","-o",obj])
    if "R_AARCH64_ABS" in run([ndk/"llvm-readelf.exe","-r",obj]):raise ValueError("bridge absolute relocation")
    run([ndk/"ld.lld.exe","-static","-nostdlib","-T",source/"mmu_bridge.ld","--build-id=none",obj,"-o",elf])
    if run([ndk/"llvm-nm.exe","-u",elf]).strip():raise ValueError("bridge unresolved symbols")
    symbols={}
    for line in run([ndk/"llvm-nm.exe","-n",elf]).splitlines():
        fields=line.split()
        if len(fields)==3 and re.fullmatch("[0-9a-fA-F]+",fields[0]):symbols[fields[2]]=int(fields[0],16)
    required=["start","end","entry","observer","guard","guard_resume","after_mmu","after_mmu_resume","bootstrap_fatal","vectors","context","identity","park"]+[f"fault_{n}" for n in range(16)]
    if any("mmu_bridge_"+name not in symbols for name in required):raise ValueError("bridge exports missing")
    if symbols["mmu_bridge_start"]!=0 or symbols["mmu_bridge_end"]>0x10000:raise ValueError("bridge layout is not within64KiB")
    run([ndk/"llvm-objcopy.exe","-O","binary",elf,raw]);blob=bytearray(raw.read_bytes())
    if len(blob)!=symbols["mmu_bridge_end"] or symbols["mmu_bridge_context"]+0x800>len(blob):raise ValueError("bridge context not emitted")
    resume_patches=[]
    for name,target in (("mmu_bridge_guard_resume",0x501298),("mmu_bridge_after_mmu_resume",0x501368)):
        at=symbols[name];original=struct.unpack_from("<I",blob,at)[0]
        if original!=branch_word(at,symbols["mmu_bridge_park"]):raise ValueError(f"{name} placeholder changed: {original:#x}")
        replacement=branch_word(0x1800000+at,target);struct.pack_into("<I",blob,at,replacement)
        resume_patches.append({"symbol":name,"blob_offset":at,"original":original,"replacement":replacement,"target_kernel_offset":target})
    final=out/"mmu_bridge.bin";final.write_bytes(blob)
    baseline=p04_baseline()
    require(bytes(blob)==(P04_FROZEN/"mmu_bridge.bin").read_bytes() and sha(blob)==baseline["xnu"]["bridge"]["sha256"],
            "P05 bridge must remain byte-identical to completed P04")
    (out/"bridge_payload.S").write_text('.section .rodata.bridge_payload,"a"\n.balign 16\n.global bridge_payload_start, bridge_payload_end\nbridge_payload_start:\n.incbin "'+final.as_posix()+'"\nbridge_payload_end:\n')
    dis=run([ndk/"llvm-objdump.exe","-d",elf]);(out/"mmu_bridge.disassembly.txt").write_text(dis)
    report={"bytes":len(blob),"sha256":sha(blob),"crc32":zlib.crc32(blob),"raw_sha256":sha(raw.read_bytes()),"symbols":symbols,
            "resume_patch":resume_patches[0],"resume_patches":resume_patches,
            "elf_note":"linked ELF retains original resume placeholders; embedded mmu_bridge.bin contains the two recorded B patches"}
    (out/"bridge-layout.json").write_text(json.dumps(report,indent=2)+"\n")
    return bytes(blob),report


def prepare_xnu(out,normal_ramdisk,bridge,bridge_report,package=False):
    path=ROOT/"out/cloud-kernel/42271869198/extracted/build/renoace/kernel/mach.development.bcm2837.unstripped.noctf"
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
    wanted={"_arm_init","_start_first_cpu","common_start","_bootstrap_pagetables","_LowExceptionVectorBase","_ExceptionVectorsBase","_intstack_top","_excepstack_top"};symbols={}
    so,ns,st,ss=symbol_command
    if so+ns*16>len(data) or st+ss>len(data):raise ValueError("Mach-O symbol bounds")
    for i in range(ns):
        index,typ,section,desc,address=struct.unpack_from("<IBBHQ",data,so+i*16)
        if index>=ss:continue
        end=data.find(b"\0",st+index,st+ss)
        if end<0:raise ValueError("unterminated Mach-O symbol")
        name=data[st+index:end].decode(errors="replace")
        if name in wanted:symbols[name]=address
    if set(symbols)!=wanted:raise ValueError("required fresh kernel symbols missing")
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
    arm_init=symbols["_arm_init"]-base;arm_file=file_offset(arm_init)
    require(struct.unpack_from("<I",data,arm_file)[0]==0xd10343ff,"original arm_init instruction changed")
    patches.append({"offset":arm_init,"file_offset":arm_file,"original":0xd10343ff,"replacement":FAULT_WORD,
                    "label":"arm_init controlled BRK #0x505","bridge_symbol":None})
    patch(0x501294,0x14000001,"mmu_bridge_guard","page tables ready")
    patch(0x50128c,0x14000000,"mmu_bridge_bootstrap_fatal","bootstrap table overflow loop")
    if struct.unpack_from("<I",data,file_offset(0x501348))[0]!=0xd518c000:raise ValueError("original high VBAR instruction changed")
    patches.append({"offset":0x501348,"file_offset":file_offset(0x501348),"original":0xd518c000,"replacement":0xd503201f,
                    "label":"defer high VBAR until MMU enabled","bridge_symbol":None})
    patch(0x501364,0xf2e00001,"mmu_bridge_after_mmu","install high VBAR after original SCTLR/ISB")
    high_words=[0x14000400,0x14000425,0x1400041d,0x14000415,0x14000407,0x14000411,0x14000402,0x140003f3,0x140003e4,0x140003d9,0x140003cf,0x140003c5]+[0xd503201f]*4
    for i in range(16):
        patch(symbols["_LowExceptionVectorBase"]-base+i*0x80,0x14000000,f"mmu_bridge_fault_{i}",f"low vector {i}")
        patch(symbols["_ExceptionVectorsBase"]-base+i*0x80,high_words[i],f"mmu_bridge_fault_{i}",f"high vector {i}")
    if len({p["offset"] for p in patches})!=37:raise ValueError("overlapping kernel patches")
    member,body_offset=newc_entry(".renoace-xnu-p05.macho",data);trailer,_=newc_entry("TRAILER!!!",b"",0)
    padding=bytes((-len(normal_ramdisk))%4);archive_offset=len(normal_ramdisk)+len(padding);source_offset=archive_offset+body_offset
    ramdisk=normal_ramdisk+padding+member+trailer;ramdisk+=bytes((-len(ramdisk))%4)
    if ramdisk[:len(normal_ramdisk)]!=normal_ramdisk or ramdisk[source_offset:source_offset+len(data)]!=data or source_offset&7:raise ValueError("newc source integrity/alignment")
    cursor=archive_offset;files={}
    while ramdisk[cursor:cursor+6]==b"070701":
        fields=[int(ramdisk[cursor+6+8*i:cursor+14+8*i],16) for i in range(13)]
        name=ramdisk[cursor+110:cursor+110+fields[11]-1].decode();cursor=(cursor+110+fields[11]+3)&~3
        files[name]=ramdisk[cursor:cursor+fields[6]];cursor=(cursor+fields[6]+3)&~3
        if name=="TRAILER!!!":break
    if files!={".renoace-xnu-p05.macho":data,"TRAILER!!!":b""} or any(ramdisk[cursor:]):raise ValueError("newc roundtrip failed")
    constants=dict(XNU_LINK_BASE=base,XNU_ENTRY_OFFSET=entry-base,XNU_FIRST_CPU_OFFSET=symbols["_start_first_cpu"]-base,
        XNU_FILE_SIZE=len(data),XNU_FILE_CRC32=zlib.crc32(data),XNU_INITRD_OFFSET=source_offset,XNU_ARGS_OFFSET=args_offset,
        XNU_BOOT_ARGS_SIZE=0x480,XNU_ADT_OFFSET=adt_offset,XNU_ADT_SIZE=len(adt),XNU_ADT_CRC32=zlib.crc32(adt),
        XNU_SEGMENT_COUNT=len(ordered),XNU_PATCH_COUNT=len(patches),XNU_BLOB_OFFSET=blob_offset,XNU_BLOB_RESERVE=blob_reserve,
        XNU_TOP_DATA_OFFSET=top_data,XNU_MAPPED_CLEAN_START=0x180004000,XNU_MAPPED_CLEAN_END=0x190000000,
        XNU_ARM_INIT_OFFSET=symbols["_arm_init"]-base,XNU_LOW_VECTORS_OFFSET=symbols["_LowExceptionVectorBase"]-base,
        XNU_HIGH_VECTORS_OFFSET=symbols["_ExceptionVectorsBase"]-base,XNU_COMMON_START_OFFSET=symbols["common_start"]-base,
        XNU_BOOTSTRAP_OFFSET=symbols["_bootstrap_pagetables"]-base,XNU_BOOTSTRAP_BYTES=0x10000,
        XNU_SP0_VA=symbols["_intstack_top"],XNU_SP1_VA=symbols["_excepstack_top"],
        XNU_EXPECTED_TCR=0x22a51a251a,XNU_EXPECTED_MAIR=0x0c0804ff00bb44ff,XNU_EXPECTED_EXCEPTION_ESR=EXPECTED_EXCEPTION["esr"],
        XNU_BRIDGE_BYTES=len(bridge),XNU_BRIDGE_CRC32=zlib.crc32(bridge),XNU_BRIDGE_PAYLOAD_SIZE=len(bridge),XNU_BRIDGE_PAYLOAD_CRC32=zlib.crc32(bridge))
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
        "ADT":{"bytes":len(adt),"sha256":sha(adt),"seed_sha256":seed_hash,"seed_bytes":256,"profile":"minimal native Reno Ace startup; CPU0/19.2MHz, CHRP NVRAM, no storage or USB activation"},
        "boot_args":{"bytes":len(args),"sha256":sha(args),"device_tree_va":hex(base+adt_offset),"top_of_kernel_data_pa":hex(0x180004000+top_data)},
        "bridge":bridge_report,"diagnostics_version":1,"budget_ms":15000,"mode":FAULT_MODE,
        "expected_exception":EXPECTED_EXCEPTION,"P04_reference_build_id":P04_BUILD_ID,
        "model_scope":"native BRK trigger; architecture vector delivery, exception frame and handler return are explicitly synthetic in the instruction model",
        "scope":"original MMU bootstrap to private arm_init BRK #0x505, exception-handler identity return; no arm_init C body or iOS startup"}
    phys=0x180004000;pool=phys+constants["XNU_BOOTSTRAP_OFFSET"]
    clean_end=phys+top_data;clean_blocks=((clean_end+0x1fffff)&~0x1fffff)-(phys&~0x1fffff)
    if clean_end>constants["XNU_MAPPED_CLEAN_END"]:raise ValueError("used data leaves identity mapping")
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
        "assumptions":"physBase/headerPA180004000; linked virtBase; memSize10000000; original startup before arm_init body"}
    validate_p05_variant(report,bridge,(out/"build-seed.bin").read_bytes())
    (out/"ramdisk").write_bytes(ramdisk);(out/"xnu-layout.json").write_text(json.dumps(report,indent=2)+"\n")
    return ramdisk,report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ndk-bin",type=Path,default=NDK)
    ap.add_argument("--package",action="store_true")
    ap.add_argument("--prepare-only",action="store_true",help="generate bridge, ADT and headers without compiling main C")
    ap.add_argument("--validate-only",action="store_true",help="refresh input evidence and check package gates without compiling or packaging")
    args=ap.parse_args()
    if sum((args.package,args.prepare_only,args.validate_only))>1:
        ap.error("select only one of --package, --prepare-only, --validate-only")
    source=ROOT/"device/renoace/xnu_fault_probe"
    out=ROOT/"out/xnu-fault-probe";out.mkdir(parents=True,exist_ok=True)
    if args.validate_only or args.package:
        evidence=p05_package_evidence(out,source)
        if args.validate_only:
            (out/"package-evidence.json").write_text(json.dumps(evidence,indent=2)+"\n")
            print("P05 evidence gates passed; no compilation or package created")
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
    dtb_offset=effective+0x20000
    dtb_capacity=0x100000
    image_size=dtb_offset+dtb_capacity
    if image_size>=0x8000000 or image_size>=0x100000000:
        raise ValueError("tail cannot be reached/restored with the admitted instructions")
    for key in ("kernel_addr","ramdisk_addr","tags_addr","dtb_addr","page_size","header_version"):
        if header[key]!=recovery_header[key]:raise ValueError("carrier load geometry mismatch: "+key)
    (out/"original-linux.Image").write_bytes(linux)
    build_id=compute_build_id(source_hashes,linux,combined_ramdisk,xnu_report,bridge)
    require(build_id!=P04_BUILD_ID,"P05 must never reuse the P04 build identity")
    constants={"LINUX_EFFECTIVE_SIZE":effective,"LINUX_TEXT_OFFSET":text_offset,
               "LINUX_ORIGINAL_CODE0":code0,"DTB_OFFSET":dtb_offset,
               "DTB_CAPACITY":dtb_capacity,"CHAIN_IMAGE_SIZE":image_size,
               "NORMAL_RAMDISK_SIZE":len(parts["ramdisk"]), "XNU_PHYS_BASE":0x180004000, "XNU_WINDOW_SIZE":0x10000000}
    (out/"layout.h").write_text("\n".join(f"#define {k} 0x{v:x}" for k,v in constants.items())+f'\n#define CHAIN_BUILD_ID "{build_id}"\n')
    (out/"layout.ld").write_text("\n".join(f"{k} = 0x{v:x};" for k,v in constants.items())+"\n")
    if args.prepare_only:
        if source_snapshot()!=source_hashes:raise ValueError("source changed during prepare; rerun")
        (out/"prepare.json").write_text(json.dumps({"build_id":build_id,"mode":FAULT_MODE,"expected_exception":EXPECTED_EXCEPTION,"source_hashes":source_hashes,"xnu":xnu_report,"commands":commands},indent=2)+"\n")
        print("Prepared pinned fresh-kernel layout, bridge payload, nonempty ADT and headers; no main Image/package built")
        return
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
    if source_snapshot()!=source_hashes:raise ValueError("source changed during compile; rerun")
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
    report={"status":"offline P05 native-BRK trigger candidate with synthetic exception-delivery model; hardware-untested; NOT iOS boot",
            "hardware_tested":False,"build_id":build_id,"mode":FAULT_MODE,"expected_exception":EXPECTED_EXCEPTION,"constants":constants,"symbols":symbols,
            "original_linux_sha256":sha(linux),"image_sha256":sha(image),"image_bytes":len(image),
            "kernel_payload_sha256":sha(kernel),"source_hashes":source_hashes,"commands":commands,
            "entry_contract":"EL1 or EL2, M=C=0, Image text_offset congruence and loader-owned expanded allocation",
            "refusal":"FDT/bank/carveout/initrd validation refusal restores original Linux header and original DT; unsupported EL/MMU/cache state parks",
            "linux_changes_before_entry":["code0 redirects to tail","Image image_size covers emitted tail arena"],
            "restoration":"both modified fields restored before branch to original Linux entry",
            "unknowns":["hardware acceptance of enlarged Image","Android normal boot through recovery carrier","actual native CPU feature values","real cache/interconnect behavior","exclusive EFI ownership of every selected kernel-window byte is not established by a captured memory map"],
            "instruction_model":"not yet executed by this build command"}
    report["package_gate"]="BLOCKED pending matching native-BRK-trigger model with explicitly synthetic exception frame/handler return, independent root review, 190 primitives, fresh CPIO/input validation, bridge ABI and owning-ABL bounds"
    report["pre_guard_writes"]="P02 substrate's early context/stack writes use the loader-owned Image; high XNU window writes occur only after complete runtime FDT overlap checks"
    report["xnu"]=xnu_report
    if args.package:
        evidence=p05_package_evidence(out,source)
        require(evidence["image_sha256"]==sha(image) and evidence["build_id"]==build_id,"recompiled Image differs from reviewed P05 candidate")
        report["instruction_model"]=evidence["model"]
        report["package_evidence"]=evidence
        report["package_gate"]="matched P05 native-BRK-trigger/synthetic frame/handler-return model, independent root review, bridge ABI, 190 primitives, fresh CPIO/input evidence and owning-ABL bounds passed; hardware execution remains separate"
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
