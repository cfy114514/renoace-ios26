# P10 SMMU read-only source stub

`smmu_snapshot.c` is the smallest source contract for a future P10 carrier. It reads only GR0 `sCR0`, `IDR0`, `IDR1`, and the bounded `SMR`/`S2CR` arrays. It performs no register writes, does not read context banks or TTBRs, and rejects invalid capability values and arrays that leave the first GR0 page.

The caller must map exactly the CPU Device page at `0x15000000` and run two complete passes, comparing them with `renoace_smmu_pass_equal`. A carrier, FDT binary record, and native instruction model are still required before this source can be used on the phone.

Run the host-only synthetic model with:

```powershell
python tools/test_renoace_smmu_probe.py
python -m unittest tools/tests/test_smmu_probe_source_model.py
```

The current phone has no `/dev/mem`, so this model does not authorize a carrier or USB/DMA experiment.
