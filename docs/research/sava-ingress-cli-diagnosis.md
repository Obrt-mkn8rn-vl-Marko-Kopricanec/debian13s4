# Private Sava ingress CLI phase diagnostic

The original expanded 22-test producer run remains FAILED (one error, 21 roots OK): its first full private-interpreter encoding child exceeded the unchanged 30-second timeout. Cause remains UNKNOWN; the second encoding and refused-mode checks were not reached. The final maintained 23-test module retains that same method, assertions and deadline. Neither the final 23-test suite nor the declared whole Applications178 suite was run.

On 2026-10-11, the Supervisor ran one separate instrumented private first-encoding child against accepted source `b23105c562ea18a51c7208d532c6a8fd0c268dec` (tree `9917595331859482a5044577adeb3124f23667fe`). The experiment records phases around source imports, the actual preparation call, each complete protected read and the binary `main()` output. It uses the maintained private fixture and its explicit path/trusted-UID/namespace substitutions; it performs no app, CLR, TLS, SQL, manager, account, package or target operation.

The child returned integer zero within the unchanged 30-second timeout. Its trace contains 19 matched import pairs and 296 matched protected-read pairs. Preparation returned 53,990 bytes; the final main marker reports zero. Driver and recorder also returned zero, and fixture cleanup returned. All 253 tracked source-file size/SHA commitments were equal before and after the experiment. This is PERSONAL SUPERVISOR PRODUCER evidence.

| Observation | Recorded value |
|---|---:|
| Child trace: remapping complete | 1.037511331960559 seconds |
| Child trace: preparation begins | 1.0375376660376787 seconds |
| Child trace: preparation returns | 3.4740463399793953 seconds |
| Child trace: main returns | 3.4741013320162892 seconds |
| Parent child wait | 3.8107043139170855 seconds |
| Driver including fixture setup and cleanup | 6.875035817967728 seconds |
| Recorder | 7.793441721005365 seconds |

These are separate measured points from this experiment, not a performance guarantee or a timing explanation for the earlier failure. Instrumentation changes execution; this diagnostic omits the ordinary test's parent expected-output preparation and runs only its first encoding child. It does not assert equality to the ordinary test's expected bytes, execute the second encoding/refused-mode steps, repair the original failure, or establish ordinary suite green. No stalled phase or historical timeout cause was established. No production change or deadline relaxation follows from this result.

The ignored retained corpus is under `docs/internal/codex/applications-sava-cli-diagnosis*`. Original and instrumented child programs, the complete consumed maintained sources, all 253 input commitments, binary stdout, the full 636-row phase trace, actual waits, cleanup and source guard are retained separately from the accepted checkpoint's immutable history.

| Retained evidence | Bytes | SHA256 |
|---|---:|---|
| Diagnostic driver `.py` | 5561 | b2fb455b55acce77344cb4ae7636acec4610854ecde6fe35ed3a6b7b747cf2dc |
| Recorder `-recorder.py` | 678 | c939c4c854c918bd9c867ff9397581938084a41782a308e020f3194df691ca8d |
| Original maintained child program `-original-program.py` | 815 | d66310cc06dac9314b7eed373b0ef99f3c6eeeb948964eadd08c50a4f332068c |
| Instrumented program `-instrumented-program.py` | 2405 | 9fe01425a3c7c7ec2bf735571de9c42d93c5bd9e0eea831d85100cb71b44dcfe |
| Binary stdout `-stdout.bin` | 53990 | 8811c192794e339f72e10013a846087468efef44c717b22b53bc567687ae77c6 |
| Phase trace `-stderr.ndjson` | 97426 | 505328af0d269daf153b7f1b8782b9187728424ced41f8cba28c0da140d94a1f |
| Driver result `-result.json` | 637 | a7333eca265c8b899876bebe4ae413262e2691daa8599c3aec7476120a32660d |
| Recorder result `-execution.json` | 115 | e0c0c49b38807f2787a19c155c171601fdef20462bad91687c574db901d1e509 |
| Source commitments `-inputs.json` | 35735 | dbf091f9357ddeea18b469d8e9f6bcd886a6feed652644a646f0432cfe31682e |

This checkpoint adds only this research report. Every maintained implementation, fixture, test and generated `setup.sh` remains unchanged. The output state is still `protected-sava-gateway-ingress-source-only`; public hashes, fake PEM, deliberately invalid app/CLR bytes and private ordinary-UID fixture observations do not attest native origin, usable credentials, valid configuration, authentication, ownership, ABI, health or physical durability.

All preceding FAILED, REJECTED, INCOMPLETE, UNKNOWN, absent and unexecuted dispositions remain intact. Bootstrap109 remains FAILED14 with old DEFAULT30 TimeoutExpired diagnostics and unknown causes. The narrow cached-main pipe pass remains narrower than full import/preparation/CLI verification. Full development, coexistence, four-app health, readiness and deployment maturity remain UNMET; the Monday deadline grants no waiver. ULA stays closed, unassigned, unrouted and unactivated. No downstream contact or operational authority follows.

The next source work must address the unfinished security/installer/app/coexistence backlog within existing authorization. Any further timeout investigation needs a distinct justified observation; this experiment grants no unchanged automatic retry-to-green, speculative production fix or guard relaxation.
