# Fixtures

Reserved for shared test inputs as parsers and boot tooling arrive.
Governance regression tests currently construct isolated repository copies in
temporary directories and mutate them, so canonical plans are not duplicated here.

Native parser traces are captured from preserved real attempts. They exercise
strict observer regressions; replaying them is not another guest-execution proof.
`native3-home-prefix.serial` is the unchanged first-Home trace from the fourth
Native3 owner attempt, whose owned VM was interrupted by the prefix-parser error.
`native3-picker-ready.serial` is the unchanged fifth-attempt trace: a live App
process remains present while the genuine picker hides its graphical surface.
It checks the reference image's visibility semantics, not successful permission
consent or READ delivery.
`native3-pre-gui-shell-fault.serial` preserves the exact second System attempt's
Bad boot: a genuine Shell fault before any GUI frame, actual failed health and
ordinary Root retirement. It exercises the narrowly scoped closed-parser case;
replaying it does not execute another recovery experiment.
