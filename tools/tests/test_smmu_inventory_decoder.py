import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location("decoder",ROOT/"tools/decode_renoace_smmu_inventory.py")
d=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(d)

def fixture(n=2,sid_bits=9):
    p={"idr0":(1<<27)|(sid_bits<<9)|n,"idr1":(6<<28)|8,"scr0":0,"rows":[{"smr":0,"s2cr":2<<16} for _ in range(n)]}
    return {"schema_version":1,"aperture":{"base":"0x15000000","bytes":"0x100000"},"passes":[p,copy.deepcopy(p)]}

def both(f,fn):
    for p in f["passes"]:fn(p)
    return f

class DecoderTests(unittest.TestCase):
    def error(self,f,code):
        with self.assertRaises(d.SnapshotError) as got:d.decode_snapshot(f)
        self.assertEqual(got.exception.code,code)
    def test_boundary_255(self):
        r=d.decode_snapshot(fixture(255));self.assertEqual(r['count'],255);self.assertEqual(len(r['routing']),255)
    def test_zero_is_not_256(self):self.error(fixture(0),'INVALID_COUNT')
    def test_exact_row_count(self):
        f=fixture();f['passes'][1]['rows'].pop();self.error(f,'ROW_COUNT_MISMATCH')
    def test_mask_ones_ignore_and_all_matches(self):
        f=fixture(3);both(f,lambda p:p.update(rows=[{'smr':0x80000140,'s2cr':0},{'smr':0x81400000,'s2cr':1<<16},{'smr':0x80000141,'s2cr':2<<16}]))
        r=d.decode_snapshot(f);self.assertEqual([x['index'] for x in r['matches']],[0,1]);self.assertEqual(r['matches'][1]['type'],'bypass')
    def test_invalid_row_never_matches(self):
        f=both(fixture(1),lambda p:p['rows'][0].update(smr=0x140));self.assertEqual(d.decode_snapshot(f)['match_count'],0)
    def test_sid_width_8(self):self.error(fixture(1,8),'SID_WIDTH_UNSUPPORTED')
    def test_sid_width_15(self):self.assertTrue(d.decode_snapshot(fixture(1,15))['semantic_supported'])
    def test_altered_row(self):
        f=fixture();f['passes'][1]['rows'][0]['smr']=1;r=d.decode_snapshot(f);self.assertFalse(r['stable']);self.assertIsNone(r['matches'])
    def test_altered_policy(self):
        f=fixture();f['passes'][1]['scr0']=1;self.assertEqual(d.decode_snapshot(f)['status'],'PASS_MISMATCH')
    def test_exids_raw_only(self):
        f=both(fixture(),lambda p:p.update(idr0=p['idr0']|256,scr0=8));r=d.decode_snapshot(f);self.assertEqual(r['status'],'EXIDS_ACTIVE_RAW_ONLY');self.assertIsNone(r['matches'])
    def test_exids_capability_without_active_legacy(self):
        f=both(fixture(),lambda p:p.update(idr0=p['idr0']|256));self.assertEqual(d.decode_snapshot(f)['format'],'legacy15')
    def test_exids_inconsistent(self):
        f=both(fixture(),lambda p:p.update(scr0=8));self.error(f,'INCONSISTENT_EXIDS')
    def test_sms0_raw_ids_only(self):
        f=both(fixture(),lambda p:p.update(idr0=9<<9,rows=[]));r=d.decode_snapshot(f);self.assertEqual(r['status'],'SMS0_RAW_IDS_ONLY');self.assertIsNone(r['matches'])
    def test_sms0_rows_rejected(self):
        f=both(fixture(),lambda p:p.update(idr0=9<<9));self.error(f,'SMS0_ROWS_UNSUPPORTED')
    def test_cb_index_bound_all_rows(self):
        f=both(fixture(),lambda p:p['rows'][0].update(smr=0x80000140,s2cr=8));self.error(f,'CB_INDEX_OUT_OF_RANGE')
    def test_inactive_unmatched_stale_cb_preserved(self):
        f=both(fixture(2),lambda p:p.update(rows=[{'smr':0,'s2cr':255},{'smr':0x80000141,'s2cr':255}]))
        r=d.decode_snapshot(f);self.assertTrue(r['semantic_supported']);self.assertEqual(r['match_count'],0);self.assertEqual([x['cb_index'] for x in r['routing']],[255,255])
    def test_num_s2cb_exceeds_cb(self):
        f=both(fixture(),lambda p:p.update(idr1=p['idr1']|(9<<16)));self.error(f,'INVALID_CB_COUNTS')
    def test_layout_exceeds_aperture(self):
        f=both(fixture(),lambda p:p.update(idr1=(1<<31)|(7<<28)|8));self.error(f,'LAYOUT_BOUNDS')
    def test_layout_mismatch_raw_only(self):
        f=both(fixture(),lambda p:p.update(idr1=(5<<28)|8));self.assertEqual(d.decode_snapshot(f)['status'],'LAYOUT_MISMATCH_RAW_ONLY')
    def test_invalid_hex(self):
        for value in ['0x','0xGG','123','-0x1','0x100000000',True,1.0,-1]:
            f=fixture();f['passes'][0]['idr0']=value;self.error(f,'INVALID_INTEGER')
    def test_aperture(self):
        f=fixture();f['aperture']['bytes']='0x200000';self.error(f,'APERTURE_MISMATCH')
    def test_wrong_target_sid(self):
        f=fixture();f['sid']='0x100';self.error(f,'TARGET_SID_MISMATCH')
    def test_overflow_not_silent_truncation(self):
        f=both(fixture(9),lambda p:p.update(rows=[{'smr':0x80000140,'s2cr':2<<16} for _ in range(9)]));r=d.decode_snapshot(f);self.assertEqual(len(r['matches']),9);self.assertEqual(r['status'],'MATCH_OUTPUT_OVERFLOW');self.assertFalse(r['semantic_supported'])
    def test_cli_stdin_and_invalid_hex(self):
        cmd=[sys.executable,str(ROOT/'tools/decode_renoace_smmu_inventory.py')]
        r=subprocess.run(cmd,input=json.dumps(fixture()),text=True,capture_output=True);self.assertEqual(r.returncode,0);self.assertTrue(json.loads(r.stdout)['stable'])
        f=fixture();f['passes'][0]['idr0']='0xZ';r=subprocess.run(cmd,input=json.dumps(f),text=True,capture_output=True);self.assertEqual(r.returncode,2);self.assertEqual(json.loads(r.stdout)['error'],'INVALID_INTEGER')
    def test_input_size_cap(self):
        r=subprocess.run([sys.executable,str(ROOT/'tools/decode_renoace_smmu_inventory.py')],input=' '*(d.MAX_INPUT_BYTES+1),text=True,capture_output=True)
        self.assertEqual(r.returncode,2);self.assertEqual(json.loads(r.stdout)['error'],'INPUT_TOO_LARGE')
    def test_file_input_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'fixture.json';path.write_text(json.dumps(fixture()),encoding='utf-8')
            r=subprocess.run([sys.executable,str(ROOT/'tools/decode_renoace_smmu_inventory.py'),str(path)],text=True,capture_output=True)
            self.assertEqual(r.returncode,0);self.assertTrue(json.loads(r.stdout)['input_only_decode'])
        r=subprocess.run([sys.executable,str(ROOT/'tools/decode_renoace_smmu_inventory.py')],input='{"schema_version":1,"schema_version":1}',text=True,capture_output=True)
        self.assertEqual(json.loads(r.stdout)['error'],'DUPLICATE_JSON_KEY')
    def test_mixed_hex_words_equal_and_reserved_type(self):
        f=fixture(1);both(f,lambda p:p['rows'][0].update(smr=0x80000140,s2cr=3<<16));f['passes'][1]['idr0']=hex(f['passes'][1]['idr0'])
        r=d.decode_snapshot(f);self.assertTrue(r['stable']);self.assertEqual(r['matches'][0]['type'],'reserved')
    def test_capability_and_pass_shape(self):
        f=fixture();f['passes'][0]['idr0']=0;self.error(f,'INVALID_CAPABILITIES')
        f=fixture();f['passes'].pop();self.error(f,'INVALID_PASSES')
    def test_unverified_input_flags(self):
        r=d.decode_snapshot(fixture());self.assertFalse(r['hardware_capture_verified']);self.assertFalse(r['dma_access_verified']);self.assertTrue(r['input_only_decode'])
    def test_no_dma_or_free_claim(self):
        r=d.decode_snapshot(fixture());self.assertFalse(r['dma_proof']);self.assertFalse(r['ownership_proof']);self.assertFalse(r['free_bank_claim'])

if __name__=='__main__':unittest.main()
