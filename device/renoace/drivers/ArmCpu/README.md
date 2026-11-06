# ArmCpu for Reno Ace

Device override of UniXNU/ArmCpu commit `1951cc8444b340d7d8879e9418220cf29eb711d7`.
The BSD-2-Clause-Patent license and upstream Info.plist are retained.

The measured Android DT `/soc/timer` gives the virtual timer as GIC PPI 3,
which maps to INTID 19. The shared driver used 27 for both redistributor
enablement and timer dispatch. This device copy uses one board constant, 19,
for both sites. It does not change SGIs, SPI routing, CPU topology or clocks.

The framework still applies its five XNU 12377 assembly/CPU-startup patches
to this source in the existing order. `unixnu status -D device/renoace` must
resolve `driver ArmCpu` to this device module before a fresh kernel build.

Validation: the complete upstream five-patch sequence applies to this source.
No fresh XNU kernel has yet been compiled with the override, and IRQ delivery
has not been tested on the phone. The downloaded candidate kernel is unchanged
and still contains the original INTID 27, so it remains an early-entry control.
