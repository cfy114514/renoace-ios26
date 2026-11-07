#!/usr/bin/env python3
"""P08 OFFLINE original-VM + original-ml_io_map + actual RX-gate model.

Physical GCC backing is a labelled synthetic read-only fixture. No hardware
measurement, high-VA API map, translation-register hook, or runtime code injection.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, re, struct, sys, zlib
from dataclasses import dataclass
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
sp=importlib.util.spec_from_file_location("p07_io_substrate",ROOT/"device/renoace/xnu_vm_probe/test_instructions.py")
p=importlib.util.module_from_spec(sp);sys.modules[sp.name]=p;sp.loader.exec_module(p)
un,ar=p.un,p.ar
GCC_PA,GCC_BYTES=0x100000,0x1f0000
OFFSETS=[0xf004,0xf010,0xf014,0xf018,0xf078,0xf07c,0xf050,0x8c028]
VALUES=[0xa5800000+i*0x101 for i in range(8)]
sha=p.sha

def parse_message(message,build_id):
    p.require(message.endswith(b"\0") and b"\0" not in message[:-1],"bad P08 wire termination")
    data=message[:-1];at=data.rfind(b"crc32=");p.require(at>0,"P08 CRC absent")
    check=re.fullmatch(rb"crc32=0x([0-9a-f]{16})\n",data[at:])
    p.require(check and zlib.crc32(data[:at])==int(check[1],16),"P08 wire CRC mismatch")
    lines=data[:at].splitlines();p.require(lines[:2]==[b"RENOACE-XNU-IO-P08",("build="+build_id).encode()],"wrong P08 wire identity")
    fields={}
    for line in lines[2:]:
        m=re.fullmatch(rb"([a-z0-9_]+)=0x([0-9a-f]{16})",line);p.require(m is not None,"malformed P08 field")
        name=m[1].decode();p.require(name not in fields,"duplicate P08 field");fields[name]=int(m[2],16)
    p.require(fields.get("io_schema")==1,"P08 IO schema absent")
    return fields
p.parse_message=parse_message

@dataclass(frozen=True)
class IOCase(p.VMCase):
    io_negative: str=""

def load_fixture(directory):
    b=json.loads((directory/"build.json").read_text())
    source=ROOT/b["source_root"]
    for name in ["vm_gate.S","vm_gate.ld","io_snapshot.h","probe.c","xnu_control.c","xnu_control.h"]:p.require((Path(__file__).parent/name).read_bytes()==(source/name).read_bytes(),"owned P08 source changed since build: "+name)
    for name,digest in b["source_hashes"].items():p.require(sha((source/name).read_bytes())==digest,"staged source changed: "+name)
    for name,digest in b["inherited_p07_source_hashes"].items():p.require(sha((ROOT/"device/renoace/xnu_vm_probe"/name).read_bytes())==digest,"P07 inherited source changed: "+name)
    p.require(sha((ROOT/"tools/build_renoace_vm_probe.py").read_bytes())==b["p07_builder_sha256"],"P07 builder changed")
    p.require(sha((ROOT/"tools/build_renoace_io_probe.py").read_bytes())==b["builder_sha256"],"P08 builder changed")
    image=(directory/"Image").read_bytes();linux=(directory/"original-linux.Image").read_bytes();initrd=(directory/"ramdisk").read_bytes();macho=(ROOT/b["xnu"]["source"]).read_bytes()
    p.require(sha(image)==b["image_sha256"] and sha(linux)==b["original_linux_sha256"] and sha(initrd)==b["xnu"]["combined_ramdisk_sha256"] and sha(macho)==b["xnu"]["source_sha256"],"compiled input identity changed")
    h=p.definitions(source/"mmu_bridge.h")
    return p.Fixture(directory,b,image,linux,initrd,macho,(ROOT/"local-device/20261106T115059Z/live.dtb").read_bytes(),h)

def io_definitions():
    result={}
    for line in (Path(__file__).parent/"io_snapshot.h").read_text().splitlines():
        m=re.fullmatch(r"#define\s+(IO_[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+|[0-9]+)",line.strip())
        if m:result[m[1]]=int(m[2],0)
    return result

class IOModel(p.VMProduction):
    def __init__(self,fixture,case,report_dir):
        self.io_reads=[];self.ml_io_seen=False;self.map_return_seen=False;self.device_mappings=[];self.stack_low=None;self.io_fp_before=None;self.io_fp_after=None;self.io_write_attempts=[];self.io_injected=False;self.empty_device_pages=0
        self.ih=io_definitions();self.io_symbols=json.loads((fixture.directory/"kernel-symbols.json").read_text())
        super().__init__(fixture,case,report_dir)
        # This is synthetic hardware backing only; it cannot change translation.
        p.physical_map(self.uc,GCC_PA,GCC_BYTES,un.UC_PROT_READ)
        for off,value in zip(OFFSETS,VALUES):self.uc.mem_write(GCC_PA+off,struct.pack("<I",value))
        self.uc.hook_add(un.UC_HOOK_MEM_READ,self.mmio_read,begin=GCC_PA,end=GCC_PA+GCC_BYTES-1)
        self.uc.hook_add(un.UC_HOOK_MEM_WRITE,self.mmio_write,begin=GCC_PA,end=GCC_PA+GCC_BYTES-1)
    def io_values(self):
        return {key:int.from_bytes(self.uc.mem_read(self.context+off,8),"little") for key,off in self.ih.items() if key.startswith("IO_REC_") and key!="IO_REC_VALUES"}
    def mmio_read(self,engine,access,address,size,value,_):
        try:
            pc=engine.reg_read(ar.UC_ARM64_REG_PC)
            p.require(self.map_return_seen,"GCC read before original ml_io_map returned")
            p.require(size==4 and address-GCC_PA in OFFSETS,"GCC read not in width/offset whitelist")
            p.require(pc==self.gate_symbols["mmu_io_read"],"GCC read from unexpected code")
            self.io_reads.append({"pa":hex(address),"offset":hex(address-GCC_PA),"bytes":size,"pc":hex(pc),"value":hex(int.from_bytes(engine.mem_read(address,size),"little")),"origin":"synthetic physical MMIO fixture, NOT hardware"})
        except Exception as exc:self.fail(str(exc))
    def mmio_write(self,engine,access,address,size,value,_):
        self.io_write_attempts.append({"pa":hex(address),"bytes":size,"value":hex(value)})
        self.fail("forbidden MMIO store")
    def _kernel_code(self,engine,address,size):
        super()._kernel_code(engine,address,size)
        if self.arm_init_seen:
            sp=engine.reg_read(ar.UC_ARM64_REG_SP)
            if self.full_vm_return and engine.cpr_read(*p.SYSTEM_REGISTERS["ttbr1_el1"])==self.xc["XNU_VM_CPU_ROOT_PA"]:self.stack_low=sp if self.stack_low is None else min(self.stack_low,sp)
        negative=self.case.io_negative
        if negative=="bad_stack" and address==self.link+self.xc["XNU_CHECKPOINT_OFFSET"] and not self.io_injected:
            old=engine.reg_read(ar.UC_ARM64_REG_SP);engine.reg_write(ar.UC_ARM64_REG_SP,old+16);self.io_injected=True
            self.injections.append({"kind":"negative_corrupted_active_XNU_SP","before":hex(old),"after":hex(old+16)})
        if address==self.gate_symbols["mmu_io_snapshot"]:
            self.io_fp_before=p.fp_state(engine)
            self.io_entry_state=p.registers(engine)
            self.io_entry_inputs={str(i):engine.reg_read(getattr(ar,"UC_ARM64_REG_X"+str(i))) for i in (0,19,20,21,29,30)}
        elif address==int(self.io_symbols["_ml_io_map"],0):
            p.require(self.full_vm_return,"ml_io_map called before full original VM")
            p.require(engine.reg_read(ar.UC_ARM64_REG_X0)==GCC_PA and engine.reg_read(ar.UC_ARM64_REG_X1)==GCC_BYTES,"original ml_io_map bounds differ")
            state=p.registers(engine);sp=engine.reg_read(ar.UC_ARM64_REG_SP)
            mapped=self.walk(state["ttbr1_el1"],sp)
            p.require(mapped["valid"] and not mapped["ap"]&2,"real XNU call stack is not writable")
            self.ml_io_seen=True
            start=(self.io_values()["IO_REC_VSS_BEFORE"]+4095)&~4095
            for delta in range(0,GCC_BYTES,4096):
                empty=self.walk(state["ttbr1_el1"],start+delta)
                p.require(not empty["valid"] and empty["descriptors"][-1]["level"]==3 and int(empty["descriptors"][-1]["value"],0)==0,"original io_map would overwrite an existing mapping")
                self.empty_device_pages+=1
            self.events.append({"event":"original_ml_io_map_entry","pc":hex(address),"sp":hex(sp),"stack_walk":mapped,"ttbr1":hex(state["ttbr1_el1"])})
        elif address==int(self.io_symbols["_io_map"],0)+0x1c and negative=="synthetic_map_fault" and not self.io_injected:
            self.synthetic_fault(address,"inside_original_io_map_after_stack_prologue");return
        elif address==self.gate_symbols["mmu_io_map_return"]:
            p.require(self.ml_io_seen,"map return without original function")
            va=engine.reg_read(ar.UC_ARM64_REG_X0);state=p.registers(engine)
            for delta in range(0,GCC_BYTES,4096):
                item=self.walk(state["ttbr1_el1"],va+delta)
                p.require(item["valid"] and item["pa"]==GCC_PA+delta and item["level"]==3 and (item["leaf"]>>2)&7==3 and item["pxn"] and item["uxn"] and item["ap"]==0,"original io_map Device page mapping differs")
                p.require((state["mair_el1"]>>24)&255==0,"Device AttrIndx3 MAIR is not nGnRnE")
                self.device_mappings.append({"va":hex(va+delta),"pa":hex(item["pa"]),"pte":hex(item["leaf"]),"descriptor_pa":item["descriptors"][-1]["pa"]})
            self.map_return_seen=True
            if negative=="zero_map":
                engine.reg_write(ar.UC_ARM64_REG_X0,0);self.io_injected=True
                self.injections.append({"kind":"negative_ml_io_map_return_value_peer","actual_return":hex(va),"injected_return":"0x0","original_function_executed":True})
            elif negative=="invalid_par":
                item=self.walk(state["ttbr1_el1"],va);pte_pa=int(item["descriptors"][-1]["pa"],0)
                engine.mem_write(pte_pa,bytes(8));self.io_injected=True
                self.injections.append({"kind":"negative_invalidated_first_Device_leaf_before_native_AT","pte_pa":hex(pte_pa),"old_leaf":hex(item["leaf"]),"new_leaf":"0x0","translation_register_hook":False})
        elif address==self.gate_symbols["mmu_io_read"] and not self.io_injected and negative in {"synthetic_first_read_fault","synthetic_partial_read_fault"} and len(self.io_reads)==(0 if negative=="synthetic_first_read_fault" else 2):
            self.synthetic_fault(address,"before_first_GCC_read" if not self.io_reads else "after_two_GCC_reads");return
        elif address==self.gate_symbols["mmu_io_snapshot_return"] and not (negative.startswith("synthetic_") and self.io_injected):
            self.io_fp_after=p.fp_state(engine)
            p.require(self.io_fp_after==self.io_fp_before,"snapshot call changed XNU FP/SIMD state")
            state=p.registers(engine)
            p.require(all(state[k]==self.io_entry_state[k] for k in p.SYSTEM_REGISTERS) and state["sp_el0"]==self.io_entry_state["sp_el0"] and state["sp_el1"]==self.io_entry_state["sp_el1"],"snapshot did not restore XNU system registers/stack banks")
            after={str(i):engine.reg_read(getattr(ar,"UC_ARM64_REG_X"+str(i))) for i in (0,19,20,21,29,30)}
            p.require(after==self.io_entry_inputs,"snapshot changed original observer inputs")
    def synthetic_fault(self,pc,where):
        state=p.registers(self.uc);vector=state["vbar_el1"]+(0x200 if state["pstate"]&1 else 0)
        far=(self.uc.reg_read(ar.UC_ARM64_REG_X0)+self.uc.reg_read(ar.UC_ARM64_REG_X14)) if "GCC" in where else state["sp_el0"]-8
        for name,value in (("esr_el1",0x96000004),("far_el1",far),("elr_el1",pc),("spsr_el1",state["pstate"])):self.uc.cpr_write(*p.SYSTEM_REGISTERS[name],value)
        self.uc.reg_write(ar.UC_ARM64_REG_PSTATE,(state["pstate"]&~15)|5|0x3c0)
        p.set_stack_banks(self.uc,state["sp_el0"],state["sp_el1"]);self.uc.reg_write(ar.UC_ARM64_REG_PC,vector)
        self.io_injected=True
        self.injections.append({"kind":"synthetic_architectural_IO_fault","native_delivery":False,"where":where,"pc":hex(pc),"far":hex(far),"fault_sp_el0":hex(state["sp_el0"]),"fault_sp_el1":hex(state["sp_el1"]),"native_XNU_root_retained":hex(state["ttbr1_el1"])})
    def verify(self,result):
        if self.case.io_negative:
            self.verify_negative(result);return
        super().verify(result)
        fields=self.io_values();pairs=[struct.unpack("<II",self.uc.mem_read(self.context+self.ih["IO_REC_VALUES"]+8*i,8)) for i in range(8)]
        p.require(self.ml_io_seen and self.map_return_seen,"original ml_io_map did not execute/return")
        p.require(fields["IO_REC_STATUS"]==self.ih["IO_STATUS_COMPLETE"] and fields["IO_REC_COUNT"]==8,"GCC snapshot incomplete: "+str(fields))
        p.require(pairs==list(zip(OFFSETS,VALUES)),"actual RAM snapshot differs from synthetic fixture")
        p.require([int(item["offset"],0) for item in self.io_reads]==OFFSETS and len(self.io_reads)==8,"MMIO read count/order differs")
        p.require(not self.io_write_attempts,"MMIO writes observed")
        pool=bytes(self.uc.mem_read(self.kbase+self.xc["XNU_BOOTSTRAP_OFFSET"],self.xc["XNU_BOOTSTRAP_BYTES"]))
        p.require(pool==self.bootstrap_pool_guard,"original io_map altered guarded bootstrap roots")
        wire={k:int(v,0) for k,v in result["record"]["fields"].items()}
        p.require(wire["io_verified"]==1 and wire["io_pages_verified"]==496 and wire["io_status"]==2 and wire["io_read_count"]==8,"compiled C did not verify P08 snapshot")
        p.require([(wire["io_offset_"+str(i)],wire["io_value_"+str(i)]) for i in range(8)]==pairs,"compiled C wire differs from RAM snapshot")
        p.require(self.io_fp_after==self.io_fp_before and self.bridge_returned,"FP/SIMD/caller restoration missing")
        result.update(original_ml_io_map_executed=True,original_io_map_device_pages=len(self.device_mappings),original_io_map_empty_pages_before=self.empty_device_pages,io_snapshot={k:hex(v) for k,v in fields.items()},mmio_reads=self.io_reads,mmio_write_attempts=self.io_write_attempts,device_mappings=self.device_mappings,actual_xnu_stack_low=hex(self.stack_low),snapshot_FP_SIMD_exact=True,snapshot_stack_and_observer_inputs_exact=True)
        context=bytes(self.uc.mem_read(self.context,self.h["MMU_BRIDGE_CONTEXT_BYTES"]))
        (self.report_dir/"io-context.bin").write_bytes(context)
        result["io_context_sha256"]=sha(context)

    def verify_negative(self,result):
        p.require(not self.errors and self.stop_reason=="restored-linux-entry","negative did not recover: "+str(self.errors))
        p.require(self.full_vm_return and self.bridge_returned and self.identity_seen,"negative skipped full VM/native root/caller recovery")
        p.require(bytes(self.uc.mem_read(self.base,len(self.f.linux)))==self.f.linux,"negative changed original Linux")
        p.require(bytes(self.uc.mem_read(self.initrd_pa,len(self.initrd)))==self.initrd,"negative changed source initrd")
        p.require(bytes(self.uc.mem_read(self.dtb_pa,len(self.dtb)))==self.dtb,"negative changed incoming DT")
        final=p.registers(self.uc)
        for key in ["sp_el0","sp_el1","sctlr_el1","tcr_el1","ttbr0_el1","ttbr1_el1","mair_el1","vbar_el1","cntkctl_el1"]:p.require(final[key]==self.initial[key],"negative outer state differs: "+key)
        ptr=self.uc.reg_read(ar.UC_ARM64_REG_X0);size=struct.unpack(">I",self.uc.mem_read(ptr+4,4))[0];tree=bytes(self.uc.mem_read(ptr,size))
        before,after=p.tree_semantics(self.fdt_reader,self.dtb),p.tree_semantics(self.fdt_reader,tree)
        message=after["/chosen"].pop("renoace-probe-log");p.require(before==after,"negative changed unrelated DT properties")
        vals=parse_message(message,self.b["build_id"]);fields=self.io_values();kind=self.case.io_negative
        expected_status=14 if kind=="bad_stack" else 18 if kind.startswith("synthetic_") else 25
        p.require(vals["xnu_status"]==expected_status and vals["io_verified"]==0,"negative was reported successful or wrong refusal: "+str(vals["xnu_status"]))
        expected_reads=2 if kind=="synthetic_partial_read_fault" else 0
        p.require(len(self.io_reads)==expected_reads and vals["io_read_count"]==expected_reads and not self.io_write_attempts,"negative peripheral access count differs")
        if kind.startswith("synthetic_"):
            p.require(vals["mmu_status"]==self.h["MMU_STATUS_EXCEPTION"] and vals["mmu_fault_depth"]==1 and vals["mmu_esr"]==0x96000004,"synthetic IO exception missing")
            p.require(fields["IO_REC_STATUS"]==1 and fields["IO_REC_STAGE"]==(1 if kind=="synthetic_map_fault" else 2),"synthetic fault lost partial stage/status")
        else:p.require(fields["IO_REC_STATUS"]==3,"guard/map refusal status absent")
        p.require(self.io_injected and self.injections,"negative injection provenance absent")
        p.require(self.return_fp==self.pre_fp,"negative did not restore native caller FP/SIMD")
        p.require(p.reserve_entries(tree)==p.reserve_entries(self.dtb)+[(self.base+self.c["LINUX_EFFECTIVE_SIZE"],self.c["CHAIN_IMAGE_SIZE"]-self.c["LINUX_EFFECTIVE_SIZE"]),(self.kbase,self.kbytes)],"negative reservation map differs")
        (self.report_dir/(self.case.name+".bin")).write_bytes(message)
        context=bytes(self.uc.mem_read(self.context,0x1000));(self.report_dir/(self.case.name+"-context.bin")).write_bytes(context)
        result.update(record={"sha256":sha(message),"bytes":len(message),"fields":{k:hex(v) for k,v in vals.items()},"origin":"negative instruction model, NOT phone"},expected_xnu_status=expected_status,caller_state_exact=True,FP_SIMD_exact=True,CNTKCTL_exact=True,full_arm_vm_init_return=True,io_snapshot={k:hex(v) for k,v in fields.items()},mmio_reads=self.io_reads,mmio_write_attempts=self.io_write_attempts,negative_refusal_verified=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--build",type=Path,default=ROOT/"out/xnu-io-probe");parser.add_argument("--case");opts=parser.parse_args()
    start_sha=sha(Path(__file__).read_bytes());p07_test_sha=sha((ROOT/"device/renoace/xnu_vm_probe/test_instructions.py").read_bytes())
    p.CPU_MODEL=ar.UC_CPU_ARM64_MAX;p.CPU_NAME="MAX"
    fixture=load_fixture(opts.build)
    cases=[IOCase("positive_native_io_snapshot")]+[IOCase(name,io_negative=name) for name in ["zero_map","invalid_par","bad_stack","synthetic_map_fault","synthetic_first_read_fault","synthetic_partial_read_fault"]]
    if opts.case:cases=[case for case in cases if case.name==opts.case];p.require(cases,"unknown P08 case")
    results=[]
    for case in cases:
        print("RUN "+case.name,flush=True);model=IOModel(fixture,case,opts.build/"model-tests/max");result=model.run()
        result["io_fields_debug"]={k:hex(v) for k,v in model.io_values().items()};result["mmio_reads_debug"]=model.io_reads
        result.update(build_id=fixture.build["build_id"],image_sha256=fixture.build["image_sha256"],test_source_sha256=start_sha,hardware_tested=False,translation_register_hooks=False,virtual_alias_api_mappings=False,runtime_code_injections=False,package_gate="BLOCKED: offline prototype; requires root fresh independent acceptance")
        (opts.build/"model-tests/max"/(case.name+".json")).write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps({k:result.get(k) for k in ["name","passed","errors","verification_failure","stop","elapsed_host_seconds","original_ml_io_map_executed","original_io_map_device_pages","negative_refusal_verified"]}),flush=True)
        results.append(result);del model
    p.require(start_sha==sha(Path(__file__).read_bytes()) and p07_test_sha==sha((ROOT/"device/renoace/xnu_vm_probe/test_instructions.py").read_bytes()),"model source changed during tests")
    report={"passed":all(r.get("passed") for r in results),"build_id":fixture.build["build_id"],"image_sha256":fixture.build["image_sha256"],"test_source_sha256":start_sha,"p07_test_source_sha256":p07_test_sha,"source_hashes":fixture.build["source_hashes"],"builder_sha256":fixture.build["builder_sha256"],"dependency_hashes":p.dependency_hashes(),"native_mmu":True,"translation_register_hooks":False,"virtual_alias_api_mappings":False,"hardware_tested":False,"mmio_fixture":{"origin":"synthetic bounded labelled physical MMIO read fixture, NOT hardware","physical_base":hex(GCC_PA),"bytes":hex(GCC_BYTES),"values":{hex(k):hex(v) for k,v in zip(OFFSETS,VALUES)}},"cases":results,"package_gate":"BLOCKED: no packaging implementation; root fresh independent acceptance required"}
    path=opts.build/("partial-"+opts.case+".json" if opts.case else "native-io-tests.json");path.write_text(json.dumps(report,indent=2)+"\n")
    print("P08 "+str(sum(bool(r["passed"]) for r in results))+"/"+str(len(results))+" passed",flush=True)
    return 0 if report["passed"] else 1
if __name__=="__main__":raise SystemExit(main())
