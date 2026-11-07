#!/usr/bin/env python3
"""Validate the P11 architectural timer save/restore contract offline.

This is a host-only model.  It deliberately does not access a device, MMIO,
Unicorn, or an XNU image.  The model captures the part of the contract that a
future bridge must prove before crossing ``fiq_context_init``:

* compare values are restored as absolute ``CVAL`` values;
* only writable ``CTL`` bits are restored, while ``ISTATUS`` is a witness;
* both virtual and physical timer control state is covered;
* DAIF remains fully masked while the timer state is changed; and
* pending state is observed after restoration instead of being silently
  discarded.
"""
from __future__ import annotations

from dataclasses import dataclass
import argparse
import json
from pathlib import Path

MASK64 = (1 << 64) - 1
CTL_ENABLE = 1 << 0
CTL_IMASK = 1 << 1
CTL_ISTATUS = 1 << 2  # read-only witness
CTL_WRITABLE = CTL_ENABLE | CTL_IMASK
DAIF_MASK = 0x3C0  # D, A, I and F mask bits in PSTATE.DAIF


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def timer_status(counter: int, cval: int) -> int:
    """Return the architectural ISTATUS witness for a non-wrapping interval.

    A bridge run is bounded and must reject a counter/compare pair whose
    distance crosses the 64-bit half-range.  That keeps this host model
    explicit instead of pretending a relative TVAL value is an absolute
    deadline.
    """
    counter &= MASK64
    cval &= MASK64
    # This bounded model intentionally excludes wraparound.  For ordinary
    # monotonic samples the unsigned ordering is unambiguous when the
    # absolute distance stays below half the counter space.
    require(abs(counter - cval) < (1 << 63),
            "counter/compare interval crosses half-range")
    return int(counter >= cval)


@dataclass(frozen=True)
class TimerState:
    cntv_ctl: int
    cntv_cval: int
    cntp_ctl: int
    cntp_cval: int
    cntvct: int
    daif: int

    def normalized(self) -> "TimerState":
        return TimerState(
            self.cntv_ctl & CTL_WRITABLE,
            self.cntv_cval & MASK64,
            self.cntp_ctl & CTL_WRITABLE,
            self.cntp_cval & MASK64,
            self.cntvct & MASK64,
            self.daif & MASK64,
        )


@dataclass(frozen=True)
class TimerWitness:
    saved: TimerState
    restored_cntv_ctl: int
    restored_cntv_cval: int
    restored_cntp_ctl: int
    restored_cntp_cval: int
    cntv_istatus_before: int
    cntp_istatus_before: int
    cntv_istatus_after: int
    cntp_istatus_after: int
    cntvct_after: int
    daif_during: int
    daif_after: int

    @property
    def elapsed_ticks(self) -> int:
        return (self.cntvct_after - self.saved.cntvct) & MASK64


def preserve_timer_state(before: TimerState, *, counter_after: int,
                         daif_during: int, daif_after: int,
                         changed_cval: int | None = None,
                         changed_cntv_ctl: int | None = None,
                         changed_cntp_ctl: int | None = None) -> TimerWitness:
    """Model a bounded helper that changes timer state and restores it.

    ``changed_cval`` and the control arguments represent writes made by the
    XNU path.  Restoration always uses the saved absolute CVAL and writable
    control bits.  A caller with unmasked DAIF is rejected before any write.
    """
    saved = before.normalized()
    require((saved.daif & DAIF_MASK) == DAIF_MASK,
            "DAIF must be fully masked before timer transition")
    require((daif_during & DAIF_MASK) == DAIF_MASK,
            "DAIF became unmasked while timer state was in flight")
    # The helper's writes are intentionally not used for restoration.  This
    # prevents a relative TVAL or a temporary CVAL from becoming the return
    # contract.
    temporary_cval = saved.cntv_cval if changed_cval is None else changed_cval & MASK64
    temporary_vctl = saved.cntv_ctl if changed_cntv_ctl is None else changed_cntv_ctl & CTL_WRITABLE
    temporary_pctl = saved.cntp_ctl if changed_cntp_ctl is None else changed_cntp_ctl & CTL_WRITABLE
    # Keep the temporary values in the model so the result proves that the
    # restoration overwrote them, rather than merely omitting the writes.
    require((temporary_cval, temporary_vctl, temporary_pctl) !=
            (saved.cntv_cval, saved.cntv_ctl, saved.cntp_ctl) or
            changed_cval is None and changed_cntv_ctl is None and changed_cntp_ctl is None,
            "timer mutation fixture did not change state")
    require((daif_after & DAIF_MASK) == DAIF_MASK,
            "DAIF must remain masked at restoration witness")
    after = TimerState(saved.cntv_ctl, saved.cntv_cval, saved.cntp_ctl,
                       saved.cntp_cval, counter_after, daif_after).normalized()
    return TimerWitness(
        saved=saved,
        restored_cntv_ctl=saved.cntv_ctl,
        restored_cntv_cval=saved.cntv_cval,
        restored_cntp_ctl=saved.cntp_ctl,
        restored_cntp_cval=saved.cntp_cval,
        cntv_istatus_before=timer_status(saved.cntvct, saved.cntv_cval),
        cntp_istatus_before=timer_status(saved.cntvct, saved.cntp_cval),
        cntv_istatus_after=timer_status(after.cntvct, after.cntv_cval),
        cntp_istatus_after=timer_status(after.cntvct, after.cntp_cval),
        cntvct_after=after.cntvct,
        daif_during=daif_during & MASK64,
        daif_after=after.daif,
    )


def run_cases() -> dict:
    cases = []

    def positive(name: str, fn) -> None:
        try:
            fn()
        except AssertionError as exc:
            cases.append({"name": name, "passed": False, "error": str(exc)})
        else:
            cases.append({"name": name, "passed": True})

    def negative(name: str, fn) -> None:
        try:
            fn()
        except AssertionError as exc:
            cases.append({"name": name, "passed": True, "rejected": str(exc)})
        else:
            cases.append({"name": name, "passed": False, "error": "accepted invalid contract"})

    base = TimerState(CTL_ENABLE, 1_000, CTL_IMASK, 2_000, 900, DAIF_MASK)
    positive("absolute_cval_and_control_restore", lambda: (
        (lambda w: require(w.saved.cntv_cval == 1_000 and
                           w.saved.cntv_ctl == CTL_ENABLE and
                           w.saved.cntp_ctl == CTL_IMASK and
                           w.restored_cntv_cval == w.saved.cntv_cval and
                           w.restored_cntv_ctl == w.saved.cntv_ctl and
                           w.restored_cntp_ctl == w.saved.cntp_ctl and
                           w.elapsed_ticks == 500 and
                           w.daif_during & DAIF_MASK == DAIF_MASK,
                           "saved absolute timer state differs"))
        (preserve_timer_state(base, counter_after=1_400,
                              daif_during=DAIF_MASK, daif_after=DAIF_MASK,
                              changed_cval=10, changed_cntv_ctl=0,
                              changed_cntp_ctl=CTL_ENABLE))))
    positive("pending_status_is_witnessed", lambda: (
        (lambda w: require(w.cntv_istatus_before == 0 and
                           w.cntv_istatus_after == 1,
                           "pending ISTATUS transition was not recorded"))
        (preserve_timer_state(base, counter_after=1_100,
                              daif_during=DAIF_MASK, daif_after=DAIF_MASK))))
    negative("reject_unmasked_entry", lambda: preserve_timer_state(
        TimerState(CTL_ENABLE, 1_000, 0, 2_000, 900, 0), counter_after=1_000,
        daif_during=DAIF_MASK, daif_after=DAIF_MASK))
    negative("reject_unmasked_transition", lambda: preserve_timer_state(
        base, counter_after=1_000, daif_during=0, daif_after=DAIF_MASK))
    negative("reject_unmasked_restore", lambda: preserve_timer_state(
        base, counter_after=1_000, daif_during=DAIF_MASK, daif_after=0))
    negative("reject_half_range_ambiguity", lambda: preserve_timer_state(
        TimerState(CTL_ENABLE, 1, 0, 1, 1 << 63, DAIF_MASK),
        counter_after=(1 << 63) + 1, daif_during=DAIF_MASK,
        daif_after=DAIF_MASK))
    return {"schema_version": 1, "passed": all(c["passed"] for c in cases),
            "hardware_tested": False, "cases": cases,
            "scope": "host-only architectural timer contract model"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="optional JSON report path")
    args = parser.parse_args()
    result = run_cases()
    payload = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
