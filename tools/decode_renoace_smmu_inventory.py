#!/usr/bin/env python3
"""Decode bounded future SMMU snapshots; this tool performs no device access.

Input: schema_version=1, aperture={base,bytes}, optional sid=0x140, and exactly
 two passes, each {idr0,idr1,scr0,rows:[{smr,s2cr},...]}. Words are unsigned
 integers or 0x hexadecimal strings. SMS0 captures IDs only and has empty rows.
Output describes visible raw routing metadata, never DMA permission/ownership.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
import zlib

U64_MAX=(1<<64)-1
SID=0x140
MAX_INPUT_BYTES=1<<20
MAX_ROWS=255
MAX_WIRE_MATCHES=8

class SnapshotError(ValueError):
    def __init__(self,code,detail):
        super().__init__(detail)
        self.code=code

def require(ok,code,detail):
    if not ok:
        raise SnapshotError(code,detail)

def uint(value,bits,name):
    if isinstance(value,str):
        require(re.fullmatch(r"0x[0-9a-fA-F]+",value) is not None,"INVALID_INTEGER",name+" requires 0x hexadecimal or an integer")
        value=int(value,16)
    require(type(value) is int and 0<=value<(1<<bits),"INVALID_INTEGER",name+" is outside unsigned "+str(bits)+"-bit range")
    return value

def keys(obj,required,optional,name):
    require(type(obj) is dict,"INVALID_SCHEMA",name+" must be an object")
    require(required<=obj.keys() and obj.keys()<=required|optional,"INVALID_SCHEMA",name+" has missing/unknown fields")

def parse_pass(obj,index,base,size):
    label="passes["+str(index)+"]"
    keys(obj,{"idr0","idr1","scr0","rows"},set(),label)
    a,b,c=[uint(obj[k],32,label+"."+k) for k in ("idr0","idr1","scr0")]
    require(a not in (0,0xffffffff) and b not in (0,0xffffffff),"INVALID_CAPABILITIES",label+" has zero/all-ones identification")
    sms=bool(a&(1<<27)); n=a&255
    rows=obj["rows"]
    require(type(rows) is list,"INVALID_SCHEMA",label+".rows must be an array")
    if sms:
        require(1<=n<=MAX_ROWS,"INVALID_COUNT","NUMSMRG must be exactly 1..255; zero is not 256")
        require(len(rows)==n,"ROW_COUNT_MISMATCH",label+" row count differs from NUMSMRG")
    else:
        require(not rows,"SMS0_ROWS_UNSUPPORTED","stream-index mode must stop at raw identification words")
        n=0
    require(0x800+4*n<=0x1000 and 0xc00+4*n<=0x1000,"REGISTER_BOUNDS","descriptor arrays leave the first GR0 page")
    pairs=[]
    for i,row in enumerate(rows):
        keys(row,{"smr","s2cr"},set(),label+".rows["+str(i)+"]")
        pairs.append((uint(row["smr"],32,"smr"),uint(row["s2cr"],32,"s2cr")))
    shift=16 if b&(1<<31) else 12
    global_bytes=(1<<(((b>>28)&7)+1))<<shift
    num_cb=b&255;num_s2cb=(b>>16)&255
    require(num_s2cb<=num_cb,"INVALID_CB_COUNTS","NUMS2CB exceeds NUMCB")
    cb_bytes=num_cb*(1<<shift)
    require(global_bytes<=size and cb_bytes<=size-global_bytes,"LAYOUT_BOUNDS","IDR1-derived global/context layout leaves declared aperture")
    require(base<=U64_MAX-global_bytes-cb_bytes,"ADDRESS_OVERFLOW","candidate context layout overflows uint64")
    raw=struct.pack("<III",a,b,c)+b"".join(struct.pack("<II",*pair) for pair in pairs)
    return {"idr0":a,"idr1":b,"scr0":c,"pairs":pairs,"sms":sms,"n":n,"sid_bits":(a>>9)&15,
            "exids_capable":bool(a&(1<<8)),"exids_active":bool(c&8),"num_cb":num_cb,"num_s2cb":num_s2cb,
            "page_shift":shift,"global_bytes":global_bytes,"cb_end":base+global_bytes+cb_bytes,
            "raw_sha256":hashlib.sha256(raw).hexdigest(),"raw_crc32":hex(zlib.crc32(raw)),"raw_bytes":len(raw)}

def decode_snapshot(snapshot):
    keys(snapshot,{"schema_version","aperture","passes"},{"sid"},"snapshot")
    require(type(snapshot["schema_version"]) is int and snapshot["schema_version"]==1,"INVALID_SCHEMA","schema_version must be 1")
    aperture=snapshot["aperture"];keys(aperture,{"base","bytes"},set(),"aperture")
    base=uint(aperture["base"],64,"aperture.base");size=uint(aperture["bytes"],64,"aperture.bytes")
    require(base==0x15000000 and size==0x100000,"APERTURE_MISMATCH","Reno Ace apps-SMMU aperture must be 0x15000000/0x100000")
    require(base<=U64_MAX-size and base%4096==0,"APERTURE_BOUNDS","invalid/overflowing aperture")
    sid=uint(snapshot.get("sid",SID),32,"sid");require(sid==SID,"TARGET_SID_MISMATCH","this contract targets SID 0x140")
    scans=snapshot["passes"];require(type(scans) is list and len(scans)==2,"INVALID_PASSES","exactly two complete passes are required")
    p,q=[parse_pass(item,i,base,size) for i,item in enumerate(scans)]
    stable=(p["idr0"],p["idr1"],p["scr0"],p["pairs"])==(q["idr0"],q["idr1"],q["scr0"],q["pairs"])
    require(not p["exids_active"] or p["exids_capable"],"INCONSISTENT_EXIDS","EXIDENABLE is active without EXIDS capability")
    require(not q["exids_active"] or q["exids_capable"],"INCONSISTENT_EXIDS","second pass EXIDENABLE lacks EXIDS capability")
    result={"valid":True,"schema_version":1,"stable":stable,"format":"raw_only","status":"RAW_ONLY",
            "semantic_supported":False,"sid":hex(sid),"count":p["n"],"matches":None,"match_count":None,
            "raw_passes":[{"sha256":x["raw_sha256"],"crc32":x["raw_crc32"],"bytes":x["raw_bytes"]} for x in (p,q)],
            "raw":{"idr0":hex(p["idr0"]),"idr1":hex(p["idr1"]),"scr0":hex(p["scr0"]),"rows":[{"smr":hex(a),"s2cr":hex(b)} for a,b in p["pairs"]]},
            "capabilities":{"sms":p["sms"],"sid_bits":p["sid_bits"],"exids_capable":p["exids_capable"],"exids_active":p["exids_active"],"num_cb":p["num_cb"],"num_s2cb":p["num_s2cb"]},
            "policy":{"clientpd":bool(p["scr0"]&1),"usfcfg":bool(p["scr0"]&(1<<10))},
            "layout":{"page_shift":p["page_shift"],"global_bytes":hex(p["global_bytes"]),"candidate_cb_base":hex(base+p["global_bytes"]),"candidate_cb_end":hex(p["cb_end"]),"vendor_half_matches":p["global_bytes"]==size//2,"context_banks_read":False},
            "hardware_capture_verified":False,"dma_access_verified":False,"input_only_decode":True,
            "dma_proof":False,"ownership_proof":False,"free_bank_claim":False}
    if not stable:
        result["status"]="PASS_MISMATCH";return result
    if not p["sms"]:
        result.update(status="SMS0_RAW_IDS_ONLY",format="stream_indexing_raw_only");return result
    if p["exids_active"]:
        result.update(status="EXIDS_ACTIVE_RAW_ONLY",format="extended_raw_only");return result
    require(9<=p["sid_bits"]<=15 and sid<(1<<p["sid_bits"]),"SID_WIDTH_UNSUPPORTED","legacy advertised SID width must be 9..15 and contain SID 0x140")
    if not result["layout"]["vendor_half_matches"]:
        result.update(status="LAYOUT_MISMATCH_RAW_ONLY");return result
    matches=[];routing=[]
    names=("translate","bypass","fault","reserved")
    for i,(smr,s2cr) in enumerate(p["pairs"]):
        typ=(s2cr>>16)&3;cb=s2cr&255
        valid=bool(smr&(1<<31));ident=smr&0x7fff;mask=(smr>>16)&0x7fff
        matched=valid and ((sid^ident)&(~mask&0x7fff))==0
        require(not matched or typ!=0 or cb<p["num_cb"],"CB_INDEX_OUT_OF_RANGE","matched translation row "+str(i)+" references CB outside NUMCB")
        row={"index":i,"valid":valid,"id":hex(ident),"mask":hex(mask),"type":names[typ],"type_value":typ,"cb_index":cb,"privcfg":(s2cr>>24)&3,"matches_sid":matched}
        routing.append(row)
        if matched:matches.append(dict(row))
    overflow=len(matches)>MAX_WIRE_MATCHES
    result.update(format="legacy15",status="MATCH_OUTPUT_OVERFLOW" if overflow else "LEGACY15_STABLE",semantic_supported=not overflow,
                  matches=matches,match_count=len(matches),routing=routing,wire_match_capacity=MAX_WIRE_MATCHES,wire_output_overflow=overflow)
    return result

def no_duplicate_keys(items):
    obj={}
    for key,value in items:
        require(key not in obj,"DUPLICATE_JSON_KEY",key)
        obj[key]=value
    return obj

def run_cli(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("snapshot",nargs="?",default="-");args=parser.parse_args(argv)
    try:
        if args.snapshot=="-":raw=sys.stdin.buffer.read(MAX_INPUT_BYTES+1)
        else:
            with open(args.snapshot,"rb") as stream:raw=stream.read(MAX_INPUT_BYTES+1)
        require(len(raw)<=MAX_INPUT_BYTES,"INPUT_TOO_LARGE","snapshot exceeds 1 MiB")
        data=json.loads(raw.decode("utf-8"),object_pairs_hook=no_duplicate_keys)
        result=decode_snapshot(data)
    except (SnapshotError,ValueError,OSError) as exc:
        result={"valid":False,"error":getattr(exc,"code","INPUT_ERROR"),"detail":str(exc),"hardware_capture_verified":False,"dma_access_verified":False,"input_only_decode":True,"dma_proof":False}
        print(json.dumps(result,sort_keys=True,separators=(",",":")));return 2
    print(json.dumps(result,sort_keys=True,separators=(",",":")));return 0

if __name__=="__main__":raise SystemExit(run_cli())
