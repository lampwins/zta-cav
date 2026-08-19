# ZTA for CAV -- prototype evaluation results

Generated 2026-08-19 03:46 UTC on Darwin arm64, Python 3.14.6.


## 1. Time overhead of ZTA interactions (paper §IV-E)

- capture window: 5 s, **455 frames** per window
- **50 conditional checks** per window at the PDP
- windows measured: 200

| metric | value |
| --- | --- |
| mean added latency | **0.184 ms** |
| median | 0.183 ms |
| std. dev. | 0.014 ms |
| 95th percentile | 0.210 ms |
| max | 0.219 ms |
| share of the 5 s window | 0.00368 % |

Breakdown of the mean:

| stage | ms |
| --- | --- |
| PEP state reports -> CM | 0.081 |
| CM profiling of the capture | 0.075 |
| PDP conditional checks | 0.009 |
| PE compile + PEP enforce + ack | 0.020 |

## 2. Case study detection (paper §IV-A .. §IV-E)

| scenario | ZT policy | trials | detected | false positives | concurrent rules |
| --- | --- | --- | --- | --- | --- |
| normal | - | 50 | n/a | 0 | 0 |
| speeding | excessive-speeding | 50 | 100.0% | 0 | 0 |
| harsh_accel | harsh-acceleration | 50 | 100.0% | 0 | 0 |
| lane_change | abrupt-lane-change | 50 | 100.0% | 0 | 0 |
| collision | collision-response | 50 | 100.0% | 0 | 0 |
| door_unlock_accel | door-unlock-then-accelerate | 50 | 100.0% | 0 | 50 |

Detection rate vs manoeuvre severity:

| scenario | k=0.40 | k=0.53 | k=0.65 | k=0.78 | k=0.90 | k=1.02 | k=1.15 | k=1.27 | k=1.40 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| speeding | 0% | 0% | 0% | 40% | 100% | 100% | 100% | 100% | 100% |
| harsh_accel | 0% | 0% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| lane_change | 0% | 0% | 25% | 100% | 100% | 100% | 100% | 100% | 100% |
| collision | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| door_unlock_accel | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 100% |

## 3. IVN attack detection (paper §V)

| traffic | trials | detected | node isolated | policy condition tripped |
| --- | --- | --- | --- | --- |
| none | 50 | 0.0% | 0.0% | - |
| fabrication | 50 | 100.0% | 100.0% | rate_error_pct, skew_error_ppm |
| suspension | 50 | 100.0% | 100.0% | rate_error_pct |
| masquerade | 50 | 100.0% | 100.0% | skew_error_ppm |

Detection latency is one continuous context check (5 s) in every detected case.

Masquerade detection vs attacker transmit-clock stealth (impersonated ECU: 1400 ppm, policy tolerance: 4000 ppm):

| attacker skew (ppm) | 1500 | 2500 | 3500 | 4500 | 5500 | 7000 | 9200 | 12000 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| detected | 0% | 0% | 0% | 0% | 52% | 100% | 100% | 100% |

## 4. Blast radius under hub-and-spoke segmentation (paper §III-C)

- mean peers reachable by a compromised node, flat CAN bus: **7.00**
- mean peers reachable under this architecture: **0.25** (96.4% reduction)
- after the CM flags the node and the PE revokes its flows: **0**


Raw per-trial data is in the CSV files alongside this summary.
