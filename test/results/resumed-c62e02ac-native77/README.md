# native77 — retention observe refused at input-fresh

`store.observe/observe-input-fresh`: f76a867e dropped the microsecond truncation
of the input bound while `observed` stays truncated, so the 5 s span check failed
for every nanosecond-precision LIST/guard observation. Fixed; the real-SQL test
now uses nanosecond inputs (fails without the fix, passes with it).
