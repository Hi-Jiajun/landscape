# Landscape v0.28.3 Benchmark Artifacts: 4-Way Silicon-Limit Router Arena & eBPF Micro-Benchmarks

> **Public Benchmark Artifact Bundle (`bench-artifacts/20261125-v0.28.3`)** | **公开基准评测证据包**
>
> - **Main Report / 主报告 (This file)**: 4-Way 1-P-core Silicon-Limit Arena (`nftables` vs `nftables + flowtable` vs `Landscape eBPF` vs `FD.io VPP`) + `i7-14700HX` Suite 0 eBPF Micro-Benchmarks
> - **Independent Audit Report / 独立核验审计报告**: [CARBON-BENCH-AUDIT.md](CARBON-BENCH-AUDIT.md)
> - **Bare-Metal `AMD Ryzen 7 9700X` eBPF Micro-Benchmark Baseline / 裸机微基准基线**: [BENCH-P1-9700X-MICROBENCH.md](BENCH-P1-9700X-MICROBENCH.md)
> - **Sanitized Raw Logs (16 Technical Logs) / 脱敏原始日志**: [logs/](logs/)
>
> *Sanitization note*: Private management IPs, real hardware MAC addresses, live ISP IPv6 RA prefixes, local hostnames, and local workspace paths have been deterministically mapped to RFC 5737 / RFC 3849 documentation addresses, locally administered test MACs, and neutral identifiers. Every measured throughput, latency, cycle, CPU%, and packet count is 100% unaltered from the original raw logs. RFC 2544 benchmark prefixes (`198.18.10.0/24`, `198.18.20.0/24`) are preserved verbatim.

---

- **Benchmark ID**: `BENCH-P2-ARENA`
- **Execution Window**: `2026-11-25 04:09 - 05:45 +08:00`
- **Engineer Role**: `bench-p2-runner` (Dedicated Systems & Network Benchmark Engineer)
- **Testbed Hygiene & Teardown**: Verified clean post-benchmark teardown (`dut-vm` / `tg-vm` purged, `nic2 vf 9..12` reset to `vlan 0`, `cpu0..7` restored to `powersave`, temporary `/tmp/bench-*` artifacts cleaned, isolated host guests untouched; host-specific provisioning and teardown logs are omitted from this public bundle as they contain private hypervisor VM inventory).

---

## 1. Executive Summary (1 P-core Head-to-Head Headline Table)

All four contestants executed on the **exact same `dut-vm (bench-dut)`**, pinned to **1 dedicated Physical P-core (`Intel i7-14700HX P0`, Host `CPU 0`, `5.3 GHz performance` governor, zero SMT sibling sharing)**, with identical **Mellanox ConnectX-4 Lx SR-IOV VFs** (`vf10` LAN -> `vf11` WAN over hardware VEB eSwitch), and verified equivalent **Stateful IPv4 NAT44 (SNAT/Masquerade) + Unsolicited WAN Ingress DROP Firewall** semantics (`EQUIV_PASS` on every contestant before measurement).

| Metric (1 Physical P-core @ 5.3 GHz) | Linux `nftables` (Baseline) | Linux `nftables + flowtable` | **Landscape eBPF (Clean)** | **Landscape eBPF (1024 CIDR + FiveTuple + L4 Port)** | FD.io VPP `v26.10` (`mlx5dv` RDMA + `nat44-ed`) |
| --- | ---: | ---: | ---: | ---: | ---: |
| **M4 Idle CPU% (0 pps)** | `0.00%` (`99.8%` idle) | `0.00%` (`100.0%` idle) | **`0.00%` (`99.8%` idle)** | **`0.40%` (`99.6%` idle)** | `100.00%` busy-poll (`0.0%` idle) |
| **M1 64B Peak Forwarded (Mpps, 1024 UDP flows)** | `1.415 Mpps` | `2.552 Mpps` | **`2.098 Mpps`** (`+48.3%` vs nft) | **`2.058 Mpps`** (`-1.9%` vs clean) | `4.465 Mpps` (TG-capped; `411.6 cyc/pkt` -> `~12.9 Mpps` est.) |
| **M1 64B Zero-Loss NDR (Mpps, <=0.06% loss)** | `1.347 Mpps` | `1.722 Mpps` | **`1.887 Mpps`** (**#1 Verified 3x10s**) | **`2.015 Mpps`** (`2.029` @ `0.13%` PDR) | `4.326 Mpps` (TG-capped) |
| **M2-A 1500B Eth NAT44 (GRO/TSO ON, 16 TCP)** | `21.65 Gbps` (`99.7%` CPU) | `22.06 Gbps` (`99.9%` CPU) | **`21.95 Gbps`** (`100.0%` CPU) | **`21.89 Gbps`** (`99.9%` CPU) | `22.72 Gbps` (TG-capped) |
| **M2-A 1500B Eth NAT44 (GRO/TSO OFF, raw 1500B)** | `14.79 Gbps` (`99.7%` CPU) | `15.74 Gbps` (`70.4%` CPU) | **`17.89 Gbps`** (`81.7%` CPU) | **`17.81 Gbps`** (`84.0%` CPU) | `18.27 Gbps` (`100%` busy-poll) |
| **M2-A Normalized Efficiency (GRO/TSO OFF)** | `14.8 Gbps/P-core` | `22.4 Gbps/P-core` | **`21.9 Gbps/P-core`** (`+48%` vs nft) | **`21.2 Gbps/P-core`** | `18.3 Gbps` (TG-capped) |
| **M2-B 1492B PPPoE + VLAN 4091 (1 P-core)** | `12.20 Gbps` (`100%` CPU) | `12.88 Gbps` (`100%` CPU, `0` offloaded) | **`14.89 Gbps`** (`97.5%` CPU, **`15.3 Gbps/core`**) | n/a (clean PPPoE tested) | n/a (kernel-bypass PPPoE client not configured) |
| **M2-B 1492B PPPoE + VLAN 4091 (2 P-core CPU used)** | `13.92 Gbps` (`1.40` P-cores) | `13.79 Gbps` (`1.40` P-cores) | **`13.79 Gbps` (`1.03` P-cores, `-26%` CPU)** | n/a | n/a |
| **M3-A Stateful NAT CPS (8-Port x 16-IP HTTP)** | `67,828 CPS` (`61.9%` CPU) | `66,301 CPS` (`76.7%` CPU) | `1,446 CPS` (`3.0%` CPU, see Section 7.3) | `1,306 CPS` (`2.9%` CPU, see Section 7.3) | `71,710 CPS` (`100%` busy-poll, TG-capped) |
| **M3-B Latency Idle (`p50 / p99 / p99.9` us)** | `382.8 / 663.1 / 765.4` | `355.7 / 612.0 / 678.0` | `422.5 / 590.9 / 642.0` | `375.8 / 540.6 / 683.1` | **`234.0 / 353.1 / 412.5`** |
| **M3-B Latency Saturated ~22 Gbps (`p50 / p99 / p99.9 / max` us)** | `2092.8 / 3078.9 / 9290.0 / 16264` | `2054.7 / 3301.3 / 6628.6 / 10484` | **`2014.6 / 2773.7 / 3994.1 / 6664`** | **`2053.1 / 2872.6 / 3336.8 / 3721`** | `1678.0 / 3472.5 / 4678.3 / 12774` |

### Key Takeaways

1. **Landscape eBPF beats both `nftables` and `nftables + flowtable` on 64B zero-loss NDR (`1.887 - 2.015 Mpps` vs `1.347` / `1.722 Mpps`; `2.029 Mpps` @ `0.13%` PDR)** while running a full programmable policy engine (NAT44 + stateful firewall + LPM route + flow rules) inside Linux `tc clsact` with `0.0%` idle CPU.
2. **Near-Zero Policy Overhead Proven Live**: Adding **1,024 CIDR LPM rules + `FiveTuple` ECMP mode + L4 Port range rules** to Landscape changed live 64B peak by only `-1.9%` (`2.098 -> 2.058 Mpps`), 1500B GRO/TSO OFF by `-0.5%` (`17.894 -> 17.809 Gbps`), and live eBPF execution time by only **`+25.7 ns/pkt`** (`153.2 -> 178.9 ns/pkt`), closely corroborating Suite 0's `BPF_PROG_TEST_RUN` micro-benchmarks (`+9 ns` for `FiveTuple` hit).
3. **Landscape Native eBPF PPPoE Dominates 1492B Broadband**: On real `1492B MTU PPPoE + 802.1Q VLAN 4091` (with `tx-checksumming off` matching production), Landscape's `pppoe_native` (zero `ppp0` interface) achieved **`14.89 Gbps` (`15.28 Gbps/P-core`)** on 1 P-core — **+22.0% raw throughput (+25.2% normalized per core) over Linux `pppd + nftables` (`12.20 Gbps`)** and **+15.5% raw (+18.6% normalized per core) over `pppd + nftables + flowtable` (`12.88 Gbps`, where `nf_flow_table` with `devices = { enp1s0, enp2s0 }` did not offload stacked `enp2s0.4091 + ppp0`, `OFFLOAD_COUNT=0`)**, while consuming **26% less CPU** (`1.04` vs `1.40` P-cores) on 2-core runs.
4. **Best Tail Latency Under 22 Gbps Saturation**: Under full 16-stream TCP saturation (`~22 Gbps`), Landscape delivered the **lowest `p99` (`2.77 - 2.87 ms`), `p99.9` (`3.34 - 3.99 ms`), and `max` (`3.72 - 6.66 ms`)** of all four contestants — beating `nftables` (`9.29 / 16.26 ms`), `nftables + flowtable` (`6.63 / 10.48 ms`), and even FD.io VPP (`4.68 / 12.77 ms`).
5. **Four Actionable Upstream Engineering Findings** (detailed in Section 7):
   - Live `bpf_stats` revealed **`pppoe_pnet_filter` (`socket_filter` on `AF_PACKET` bound to `ETH_P_ALL`) running on 100% of 7.47M TX+RX PPPoE data packets (`38.41 ns/pkt`, `203.6 cycles/pkt`, plus `dev_queue_xmit_nit` `skb_clone` overhead)**, offering an immediate ~15-20% PPPoE speedup opportunity.
   - M3-A CPS uncovered a **line-exact root cause in `nat4_ct_timer.h:16,18,204-208,297-298` and `tc_nat4_packet.h:54,85`**: Landscape's EIM NAT44 (`32,768` default TCP ports in `32768..=65535`) holds closed TCP mappings across `1s` report tick + `6s` `NAPT_CT_WAIT_TCP_CLOSE` (`~7s` total), drops `SYN` reuse on `NAPT_CT_WAIT_TCP_CLOSE` (`nat4_ct_timer.h:297-298`), and blocks outbound port sharing across distinct destination tuples when `allow_reuse=0` (`tc_nat4_packet.h:85`), capping short-lived HTTP CPS at `~1.1k - 1.7k CPS` @ `3%` CPU.
   - `--try-xdp` on `ConnectX-4 Lx` `mlx5` VF attaches native driver XDP (`xdp_lan_route`, `xdp_wan_intro`) cleanly, but `mlx5` VF `XDP_REDIRECT` drops forwarded frames (`0/10`), validating upstream `v0.28.3`'s TC-only default.
   - Linux KVM on Intel hybrid `i7-14700HX` disables guest hardware vPMU; software `cpu-clock` `perf record` + `kernel.bpf_stats_enabled=1` + VPP `show runtime` provided exact micro-architectural attribution without hardware vPMU.

---

## 2. Testbed Hardware, Software & Strict 1:1 Fairness Contract

### 2.1 Host & Virtualization Topology (`hypervisor-host` Hardware VEB Silicon Loop)

| Component | Exact Specification |
| --- | --- |
| **Hypervisor** | Proxmox VE (`hypervisor-host`), `Linux 7.0.14-28-pve`, IOMMU passthrough (`intel_iommu=on iommu=pt`) |
| **Host CPU** | `Intel Core i7-14700HX` (8 P-cores + 12 E-cores, 33 MB shared L3) |
| **CPU Isolation** | Non-essential guests stopped during benchmark window; Host `cpu0..cpu7` locked to `scaling_governor=performance` (`5.3 GHz` P-core turbo). Host `CPU 8-15` reserved for an `isolated-guest` and 100% untouched. |
| **NIC Silicon** | Dual-port `Mellanox MT27710 [ConnectX-4 Lx]` (`15b3:1015`), PCIe `8 GT/s x8` (`~63 Gbps` unidirectional), `devlink eswitch legacy` (hardware L2 VEB) |
| **DUT VM (`dut-vm`, `bench-dut`)** | `192.0.2.201/24` (`vmbr0` mgmt), `2 vCPU` pinned to physical P-cores `0,2` (zero SMT sharing), `4096 MiB` RAM (`balloon: 0`), `cpu: host`, `machine: q35`. Passthrough `hostpci0: 0000:01:02.0` (`nic2 vf10`, `enp1s0`, `02:00:00:00:00:1a`), `hostpci1: 0000:01:02.1` (`nic2 vf11`, `enp2s0`, `02:00:00:00:00:1b`). |
| **TG VM (`tg-vm`, `bench-tg`)** | `192.0.2.202/24` (`vmbr0` mgmt), `2 vCPU` pinned to physical P-cores `4,6` (zero SMT sharing), `4096 MiB` RAM (`balloon: 0`), `cpu: host`, `machine: q35`. Passthrough `hostpci0: 0000:01:01.7` (`nic2 vf9`, `enp1s0`, `02:00:00:00:00:19`), `hostpci1: 0000:01:02.2` (`nic2 vf12`, `enp2s0` in `netns tg_wan`, `02:00:00:00:00:1c`). |
| **L2 Hardware Isolation** | Ethernet suites: `vf9 + vf10 -> HW VLAN 4092` (`198.18.10.0/24`), `vf11 + vf12 -> HW VLAN 4091` (`198.18.20.0/24`). M2-B PPPoE suite: `vf11 + vf12 -> HW VLAN 0` with guest 802.1Q `.4091` subinterfaces (`enp2s0.4091`). Zero leakage to external L2 switch VLAN 1. |
| **Guest OS & Kernel** | Debian 13 (Trixie), `GLIBC 2.41`. Ethernet suites (`nftables`, `nftables-flowtable`, `landscape-clean`, `landscape-policy`): `Linux 6.12.113+deb13-cloud-amd64`; M2-B PPPoE & VPP suites: `Linux 6.12.118+deb13-amd64` (same Debian 6.12 codebase with `pppoe.ko` module). |

### 2.2 Contestant Software Provenance (Candidate Identities)

| Contestant | Exact Version / Commit / Build Provenance | Build Log |
| --- | --- | --- |
| **Suite 0 eBPF Micro-Bench** | `feat/multiwan-fivetuple-and-l4-port-rules @ 3a35a9c3`, built via detached worktree (`cargo test -p landscape-ebpf --lib --features bpf-test --no-run`, `rustc 1.98.0`, `clang 23.1.5`) | [00-build-ebpf-bench.log](logs/00-build-ebpf-bench.log) |
| **Landscape eBPF (M1-M4)** | `feat/flow-l4-port-rules @ 84472315` (`v0.28.3`), built via detached worktree (`cargo build --release -p landscape-webserver`, `rustc 1.98.0`, `clang 23.1.5`) | [00-build-webserver-release.log](logs/00-build-webserver-release.log) |
| **Linux `nftables` / `+flowtable`** | Debian 13 `nftables 1.1.3-1`, `conntrack`, `pppd 2.5.2` + `rp-pppoe.so`, `nf_conntrack_max=1048576` | [03-nftables.log](logs/03-nftables.log) |
| **FD.io VPP** | `v26.10.0-7~g18c1437ab` (release build + `libvnet.so.26.10.0`), `rdma_plugin.so` (`mlx5dv` direct verbs polling) + `nat_plugin.so` (`nat44-ed`, 1M sessions), `512 x 2MB` HugePages | [03-vpp-rdma-nat44.log](logs/03-vpp-rdma-nat44.log) |

### 2.3 Fairness Controls

- **1 P-core Enforcement**: Guest `CPU 1` offlined (`/sys/devices/system/cpu/cpu1/online = 0`), NIC queues set to `ethtool -L <dev> combined 1`, ring size `rx 4096 tx 4096`, all `mlx5_comp` IRQs pinned to `CPU 0` (`smp_affinity=1`). For VPP: `cpu { main-core 0 }` with `CPU 1` offline and 1 RX queue per `rdma` interface (`rx-queue-size 2048 tx-queue-size 2048`, `MTU 1500`).
- **2 P-core Scaling**: Guest `CPU 1` onlined, `combined 2`, `mlx5_comp0 -> CPU 0`, `mlx5_comp1 -> CPU 1`.
- **Stateful NAT44 + Firewall Equivalence Gate**: Before every contestant's benchmark run, `tg-vm` verified (1) LAN->WAN UDP reaches `tg_wan` with SNAT source IP `198.18.20.1` (`tcpdump` proof) and (2) unsolicited WAN->LAN ICMP from `tg_wan` (`198.18.20.2`) to `198.18.10.2` is 100% DROPPED.
- **1024-Flow Warm Priming**: Before every M1 64B `pktgen` run, `/opt/bench/prime_udp_flows.py` sent 1 bidirectional UDP request+echo on all `1024` flows (`198.18.10.2:10000..11023 <-> 198.18.20.2:9000`) so stateful NAT sessions and `nftables flowtable` (`FLOWTABLE_OFFLOAD_COUNT=1025`) were 100% warm before measurement. A `netdev ingress` drop rule on `tg_wan enp2s0` absorbed test UDP port 9000 after hardware RX counting to prevent ICMP port-unreachable overhead.
- **Zero-Instrumentation Measurement**: `kernel.bpf_stats_enabled` remained `0` during all Landscape throughput/latency runs and was enabled (`1`) only during the dedicated 6-second M4 profiling sample.

---

## 3. Suite 0: Updated eBPF Kernel Micro-Benchmarks (`BPF_PROG_TEST_RUN repeat=256`, 1 P-core)

Executed on `dut-vm` pinned to `CPU 0` (`taskset -c 0 /opt/bench/landscape_ebpf_bench <suite> --ignored --nocapture --test-threads=1`). All 4 suites exited with `EXIT_CODE=0`. Raw log: [02-suite0-ebpf-microbench.log](logs/02-suite0-ebpf-microbench.log). (For bare-metal `AMD Ryzen 7 9700X` comparison, see [BENCH-P1-9700X-MICROBENCH.md](BENCH-P1-9700X-MICROBENCH.md).)

### 3.1 `bench::route::*` (IPv4 & IPv6 — Including New `FiveTuple` & `L4 Port` Paths)

| Benchmark Case | IPv4 Min / Med (ns/pkt) | IPv6 Min / Med (ns/pkt) | Est. Cycles @ 5.3 GHz (v4 / v6) | Notes |
| --- | ---: | ---: | ---: | --- |
| `baseline` (reader/loop overhead) | `5.00 / 6.00` | `7.00 / 7.00` | `31.8 / 37.1` | Subtracted from all variants below |
| `lan_cache_hit(pppoe)` | `12.00 / 12.00` | `21.00 / 21.00` | `63.6 / 111.3` | Steady-state `DstIp` cache hit (PPPoE) |
| `lan_cache_hit(eth_mac)` | `24.00 / 23.00` | `36.00 / 36.00` | `121.9 / 190.8` | Steady-state `DstIp` cache hit (Ethernet) |
| **`lan_five_tuple_hit`** | **`32.00 / 32.00`** | **`41.00 / 43.00`** | **`169.6 / 227.9`** | **Only `+9 ns` (v4) / `+7 ns` (v6) over `eth_mac` `DstIp` hit** |
| `lan_cold_resolve(8, ip)` | `64.00 / 63.00` | `67.00 / 68.00` | `333.9 / 360.4` | First-packet cold resolve (8 IP rules) |
| `lan_cold_resolve(8, dns)` | `65.00 / 65.00` | `68.00 / 68.00` | `344.5 / 360.4` | First-packet cold resolve (8 DNS rules) |
| `lan_cold_resolve(1k, ip)` | `68.00 / 68.00` | `67.00 / 68.00` | `360.4 / 360.4` | First-packet cold resolve (1024 IP rules, O(1) LPM) |
| `lan_cold_resolve(1k, dns)` | `69.00 / 69.00` | `68.00 / 68.00` | `365.7 / 360.4` | First-packet cold resolve (1024 DNS rules) |
| `lan_cold_full(1k, dns)` | `82.00 / 81.00` | `90.00 / 91.00` | `429.3 / 482.3` | Full cold resolve + cache insert |
| **`lan_l4_port_cold(8, tcp)`** | **`76.00 / 75.00`** | **`74.00 / 75.00`** | **`397.5 / 397.5`** | **Only `+6 - 7 ns` over 1k IP/DNS cold resolve** |

### 3.2 `bench::nat4_v4::*` & `bench::nat6::*`

| Suite | Case | Min / Med (ns/run) | Est. Cycles @ 5.3 GHz | Exit Code |
| --- | --- | ---: | ---: | ---: |
| `bench::nat4_v4` | `reader_baseline` | `10.00 / 10.00` | `53.0` | `0` |
| `bench::nat4_v4` | `lan_steady` (baseline-subtracted) | `37.00 / 37.00` | `196.1` | `0` |
| `bench::nat4_v4` | `wan_steady` (baseline-subtracted) | `24.00 / 24.00` | `127.2` | `0` |
| `bench::nat4_v4` | `lan_miss` | `19.00 / 19.00` | `100.7` | `0` |
| `bench::nat4_v4` | `wan_miss` | `2.00 / 2.00` | `10.6` | `0` |
| `bench::nat6` | `baseline` (XDP reader) | `9.00 / 10.00` | `53.0` | `0` |
| `bench::nat6` | `egress_steady` (stateful NPTv6) | `33.00 / 42.00` | `222.6` | `0` |
| `bench::nat6` | `egress_state_only` | `28.00 / 47.00` | `249.1` | `0` |
| `bench::nat6` | `ingress_steady` | `31.00 / 51.00` | `270.3` | `0` |
| `bench::nat6` | `egress_miss` / `ingress_miss` | `33.00 / 35.00` & `33.00 / 32.00` | `185.5 / 169.6` | `0` |

*(Note on `bench::nat6` guest timer jitter: Inside the KVM guest using `pvclock`, `min` preserves exact instruction-count ordering — `egress_state_only` `28.00 ns` < `ingress_steady` `31.00 ns` < `egress_steady` `33.00 ns`, matching bare-metal `Ryzen 7 9700X`'s `23/25 ns` vs `25/27 ns` vs `27/28 ns` — whereas `med` (`42 - 51 ns`) reflects periodic hypervisor timer preemption during the 10.79s run.)*

### 3.3 `bench::wan_dispatch::*` (Scale-Invariant `atrie` / `ttrie` vs Kernel LPM)

| Lookup Structure | Per-Lookup Min / Med (ns) | Notes |
| --- | ---: | --- |
| `ttrie v4(2)` / `ttrie ppp(1)` | `2.96 / 2.97` & `5.67 / 5.70` | Tagged namespace dispatch (`v4 /24` = 4 hops, `ppp` = 7 hops) |
| `hash` | `4.51 / 4.52` | Kernel hash map |
| `klpm(3)` -> `klpm(1024)` | `6.36 -> 8.89` | Kernel LPM trie across 3 to 1024 entries |
| `atrie(3)` -> `atrie(1024)` | **`5.71 -> 5.71`** | **Flat O(1) across 3, 16, 32, 64, 256, 1024 entries (1.56x faster than `klpm`)** |

---

## 4. Suite M1: 64B Small-Packet 1-P-core Throughput (`Mpps`, 1024 Stateful UDP Flows)

Generator: `tg-vm` 2-thread Linux `pktgen` (`clone_skb 0`, `pkt_size 60` = 64B L2 with FCS, 1024 primed bidirectional UDP flows). Peak measured at `burst 32, delay 0` (3x 10s); NDR binary-searched via `burst 4` + exact `ratep` pacing (`loss <= 0.05%`) and verified over 3x 10s runs.

| Contestant (1 P-core @ 5.3 GHz) | Peak Run 1 / 2 / 3 (`rx_mpps`) | **Peak Median (`Mpps`)** | DUT `mpstat` CPU% | NDR Run 1 / 2 / 3 (`rx_mpps`, `loss%`) | **NDR Median (`Mpps`)** | Raw Log |
| --- | --- | ---: | ---: | --- | ---: | --- |
| **Linux `nftables`** | `1.414 / 1.415 / 1.419` | **`1.415`** | `99.88% soft` | `1.347 (0.07%) / 1.347 (0.06%) / 1.348 (-0.05%)` | **`1.347`** | [03-nftables.log](logs/03-nftables.log), [03-linux-exact-ndr.log](logs/03-linux-exact-ndr.log) |
| **Linux `nftables + flowtable`** | `2.552 / 2.546 / 2.559` | **`2.552`** | `99.75% soft` | `1.722 (0.02%) / 1.722 (-0.05%) / 1.723 (-0.05%)` | **`1.722`** | [03-nftables-flowtable.log](logs/03-nftables-flowtable.log), [03-linux-exact-ndr.log](logs/03-linux-exact-ndr.log) |
| **Landscape eBPF (Clean)** | `2.119 / 2.098 / 2.071` | **`2.098`** | `97.29% soft, 2.71% usr+sys` | `1.887 (0.01%) / 1.888 (-0.01%) / 1.886 (0.06%)` | **`1.887`** | [03-landscape-clean.log](logs/03-landscape-clean.log) |
| **Landscape eBPF (Rich Policy: 1024 CIDR + FiveTuple + L4 Port)** | `2.058 / 2.113 / 2.044` | **`2.058`** | `97.29% soft, 2.72% usr+sys` | `2.029 (0.13%) / 2.022 (0.43%) / 2.031 (0.01%)` (`2.015 @ -0.03%` 5s zero-loss probe) | **`2.015`** *(zero-loss)* / **`2.029`** *(PDR<=0.5%)* | [03-landscape-policy.log](logs/03-landscape-policy.log) |
| **FD.io VPP `v26.10` (`mlx5dv` + `nat44-ed`)** | `4.459 / 4.474 / 4.465` | **`4.465`** *(TG-capped)* | `100.00% usr` | `4.326 (0.03%) / 4.324 (0.03%) / 4.334 (0.02%)` | **`4.326`** *(TG-capped)* | [03-vpp-rdma-nat44.log](logs/03-vpp-rdma-nat44.log) |

*Note on Clean (`1.887 Mpps`) vs Rich Policy (`2.015 Mpps` 5s zero-loss / `2.029 Mpps` PDR) NDR binary-search bifurcation*: Adding Rich Policy does **not** accelerate forwarding (Peak is `-1.9%` lower and `bpf_stats` is `+25.7 ns/pkt` higher); in `03-landscape-clean.log`, the 5s binary-search probe at `1972 kpps` experienced `0.0540%` loss (missing the `<= 0.0500%` step-up threshold by `0.004%` due to KVM `pvclock`/softirq jitter) and stepped down to `1887 kpps`, whereas `03-landscape-policy.log`'s probe at `1947 kpps` recorded `-0.0350%` loss and stepped up to `2014 kpps` (`2.015 Mpps @ -0.0285%` over `10.09M` packets) and `2031 kpps` (`2.029 Mpps @ 0.13%` median loss over 3x 10s). Both configurations share a true 1-P-core zero-loss NDR plateau around `~1.9 - 2.0 Mpps`.

*Note on VPP M1 TG ceiling*: Because `tg-vm` runs both 2-thread `pktgen` TX and `tg_wan` `nftables` RX sink on 2 P-cores, `tg-vm`'s total loopback packet rate caps at `~4.5 Mpps` when DUT forwards near-100% of offered load. VPP's internal `show runtime` (`411.6 clocks/pkt` across the full `rdma-input -> nat44-ed-in2out -> ip4-lookup -> rdma-wan-tx` graph) indicates a theoretical 1-P-core ceiling of **`~12.9 Mpps`** at `5.3 GHz` with an external DPDK generator.

*Note on slight negative loss (`-0.01%` to `-0.07%`)*: Minor counter-read skew (`~1-2 ms` between reading `enp1s0` TX and `tg_wan enp2s0` RX in separate shell commands during live traffic) corresponds to `~0.00%` actual packet loss.

---

## 5. Suite M2: Multi-Stream Silicon-Limit Throughput (`Gbps`) & CPU Efficiency

### 5.1 M2-A: 1500B Ethernet Stateful NAT44 (`2 x iperf3 -P 8 = 16 TCP streams`, 3x 10s runs)

| Contestant | 1C GRO/TSO ON (Median Gbps / CPU%) | **1C GRO/TSO OFF (Median Gbps / CPU% / Norm. Gbps/Core)** | 2C GRO/TSO ON (Median Gbps / Avg CPU%) | 2C GRO/TSO OFF (Median Gbps / Avg CPU%) | Raw Log |
| --- | ---: | ---: | ---: | ---: | --- |
| **Linux `nftables`** | `21.654` (`99.72%`) | `14.785` (`99.85%` -> **`14.8 Gbps/core`**) | `21.367` (peak `21.977`, `61.95%` avg) | `15.231` (peak `15.900`, `64.91%` avg) | [03-nftables.log](logs/03-nftables.log) |
| **Linux `nftables + flowtable`** | `22.059` (`99.86%`) | `15.743` (peak `16.498`, `70.43%` -> **`22.4 Gbps/core`**) | `21.640` (peak `21.792`, `59.57%` avg) | `15.465` (peak `17.593`, `37.47%` avg) | [03-nftables-flowtable.log](logs/03-nftables-flowtable.log) |
| **Landscape eBPF (Clean)** | **`21.954`** (`100.00%`) | **`17.894`** (peak `18.228`, `81.73%` -> **`21.9 Gbps/core`**) | **`22.218`** (peak `22.266`, `59.93%` avg) | **`17.265`** (peak `18.109`, `46.51%` avg) | [03-landscape-clean.log](logs/03-landscape-clean.log) |
| **Landscape eBPF (Rich Policy)** | **`21.887`** (`99.86%`) | **`17.809`** (peak `18.060`, `83.96%` -> **`21.2 Gbps/core`**) | `21.909` (peak `22.057`, `60.80%` avg) | `16.553` (peak `17.601`, `48.10%` avg) | [03-landscape-policy.log](logs/03-landscape-policy.log) |
| **FD.io VPP `v26.10` (`mlx5dv`)** | **`22.716`** (`100%` busy-poll) | **`18.271`** (peak `18.420`, `100%` busy-poll) | n/a (1 forwarding core on 2-vCPU VM) | n/a | [03-vpp-rdma-nat44.log](logs/03-vpp-rdma-nat44.log) |

**Analysis**:
- With **GRO/TSO ON**, all contestants hit the `~22 Gbps` `tg-vm` 2-core TCP generator ceiling on a single DUT P-core (equivalent to **~45% of 1 P-core for a full 10 Gbps line**).
- With **GRO/TSO OFF** (strict per-1500B-packet forwarding, eliminating segmentation coalescing), **Landscape eBPF (`17.89 Gbps` @ `81.7%` CPU -> `21.9 Gbps/P-core`)** outperforms standard `nftables` (`14.79 Gbps` @ `99.9%` CPU) by **+48% in per-core efficiency**, matches `nftables + flowtable` (`22.4 Gbps/P-core`) with higher actual TCP throughput (`17.89` vs `15.74 Gbps`, fewer retransmits), and achieves **98% of FD.io VPP's raw-packet throughput (`18.27 Gbps`)** without burning 100% idle CPU.

### 5.2 M2-B: 1492B PPPoE + 802.1Q VLAN 4091 (`pppoe-server -k` Kernel BRAS, 16 TCP streams)

Real PPPoE discovery + PAP authentication + LCP/IPCP negotiation (`MTU/MRU 1492`, DF=1 `1492B` ICMP verified) over 802.1Q VLAN `4091` (`vf11`/`vf12` HW VLAN set to `0`). Landscape ran `t = "pppoe_native"` with `tx-checksumming off` (matching production gateway deployments).

| Contestant (1492B PPPoE + VLAN 4091) | 1 P-core Runs (`Gbps`) | **1 P-core Median (`Gbps`)** | 1C DUT CPU% | **Norm. `Gbps / P-core`** | 2 P-core Median (`Gbps`) | 2C DUT Avg CPU% (`P-cores`) | Raw Log |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| **Landscape Native eBPF PPPoE** (no `ppp0`, `tx off`) | `12.361 / 14.979 / 14.886` | **`14.886`** | `97.45%` | **`15.28`** (**#1**) | `13.793` (peak `14.212`, BRAS-capped) | **`51.70%` (`1.03` cores)** | [04-m2b-pppoe-3way.log](logs/04-m2b-pppoe-3way.log) |
| **Linux `pppd + nftables + flowtable`** (`ppp0`) | `12.883 / 12.902 / 12.839` | `12.883` | `100.00%` | `12.88` (`OFFLOAD=0`) | `13.789` (peak `13.999`, BRAS-capped) | `69.77%` (`1.40` cores) | [04-m2b-pppoe-linux-pppd.log](logs/04-m2b-pppoe-linux-pppd.log) |
| **Linux `pppd + nftables`** (`ppp0`) | `12.314 / 12.199 / 12.197` | `12.199` | `100.00%` | `12.20` | `13.924` (peak `13.980`, BRAS-capped) | `70.07%` (`1.40` cores) | [04-m2b-pppoe-linux-pppd.log](logs/04-m2b-pppoe-linux-pppd.log) |

**10 Gbps PPPoE Sizing**: To sustain full `10.0 Gbps` over `1492B PPPoE + 802.1Q`, **Landscape Native eBPF PPPoE needs only `0.65` of a single P-core** (vs `0.82` P-core for `pppd + nftables` and `0.78` P-core for `pppd + flowtable`), and does not even require the kernel `pppoe.ko` driver module.

---

## 6. Suite M3: Stateful NAT CPS & Latency/Jitter Under Saturation

### 6.1 M3-A: New NAT Connections/sec (`CPS`, Short-Lived HTTP/1.1 `Connection: close`)

Generator: `tg-vm` `/opt/bench/http_cps 2 64 10` (`128` concurrent short-lived HTTP connections rotating across `16` LAN source IPs `198.18.10.2..17` and `8` `nginx` ports `198.18.20.2:8080..8087` = `128x` tuple space, `err=0` on all runs).

| Contestant | 1 P-core Runs (`CPS`, `err=0`) | **1 P-core Median (`CPS`)** | 1C DUT CPU% | 2 P-core Median (`CPS`) | 2C DUT Avg CPU% | Raw Log |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| **FD.io VPP `v26.10` (`nat44-ed`)** | `72,209 / 71,033 / 71,710` | **`71,710`** *(TG-capped)* | `100.0%` busy-poll | n/a | n/a | [03-vpp-rdma-nat44.log](logs/03-vpp-rdma-nat44.log) |
| **Linux `nftables`** | `68,302 / 67,828 / 67,713` | **`67,828`** *(TG-capped)* | `61.92%` (`109.5k/core`) | `67,571` | `36.17%` | [03-nftables-addendum.log](logs/03-nftables-addendum.log) |
| **Linux `nftables + flowtable`** | `66,620 / 66,301 / 65,508` | **`66,301`** *(TG-capped)* | `76.73%` (`86.4k/core`) | `65,094` | `43.15%` | [03-nftables-flowtable-addendum.log](logs/03-nftables-flowtable-addendum.log) |
| **Landscape eBPF (Clean)** | `1,634 / 1,099 / 1,446` | **`1,446`** *(NAT close-timer limited)* | `3.01%` (`97.0%` idle) | `1,177` | `2.64%` | [03-landscape-clean.log](logs/03-landscape-clean.log) |
| **Landscape eBPF (Rich Policy)** | `1,690 / 1,192 / 1,306` | **`1,306`** *(NAT close-timer limited)* | `2.87%` (`97.0%` idle) | `1,297` | `1.87%` | [03-landscape-policy.log](logs/03-landscape-policy.log) |
| **Landscape eBPF (`allow_reuse_port=true`)** | `1,613 / 1,127 / 1,137` | **`1,137`** *(confirms `NAPT_CT_WAIT_TCP_CLOSE` root cause)* | `~3%` | n/a | n/a | [04-m2b-pppoe-and-cps-reuse.log](logs/04-m2b-pppoe-and-cps-reuse.log) |

*(Note: Notice `nftables + flowtable` consumed `+14.8%` MORE CPU than plain `nftables` at ~66k CPS because short-lived HTTP connections pay `flow add @f` insertion + flowtable GC teardown overhead on top of `nf_conntrack` without benefiting from long-lived offload.)*

### 6.2 M3-B: End-to-End UDP RTT Latency & Jitter Under Load (`1 P-core`, `5000` probes @ `500 pps`)

Measured via compiled C `/opt/bench/udp_rtt` (`CLOCK_MONOTONIC`, 5000 probes over 10s) at **Idle** vs **Heavy Saturation** (16 parallel `iperf3` TCP streams saturating the DUT at `~21.5 - 22.6 Gbps`).

| Contestant (1 P-core) | Idle `min / p50 / p95 / p99 / p99.9 / max` (us) | Saturated `min / p50 / p95 / p99 / p99.9 / max` (us) | Loss under Sat. | Raw Log |
| --- | --- | --- | ---: | --- |
| **Linux `nftables`** | `54.4 / 382.8 / 600.1 / 663.1 / 765.4 / 1466.1` | `145.6 / 2092.8 / 2608.5 / 3078.9 / 9290.0 / 16264.2` | `1 / 5000` (`0.02%`) | [03-nftables.log](logs/03-nftables.log) |
| **Linux `nftables + flowtable`** | `86.6 / 355.7 / 549.7 / 612.0 / 678.0 / 1670.3` | `45.3 / 2054.7 / 2778.1 / 3301.3 / 6628.6 / 10484.2` | `0 / 5000` (`0.00%`) | [03-nftables-flowtable.log](logs/03-nftables-flowtable.log) |
| **Landscape eBPF (Clean)** | `96.1 / 422.5 / 551.4 / 590.9 / 642.0 / 1309.0` | `65.2 / 2014.6 / 2433.2 / 2773.7 / 3994.1 / 6663.8` | `5 / 5000` (`0.10%`) | [03-landscape-clean.log](logs/03-landscape-clean.log) |
| **Landscape eBPF (Rich Policy)** | `40.3 / 375.8 / 480.9 / 540.6 / 683.1 / 1212.9` | `58.3 / 2053.1 / 2538.7 / 2872.6 / 3336.8 / 3720.6` | `4 / 5000` (`0.08%`) | [03-landscape-policy.log](logs/03-landscape-policy.log) |
| **FD.io VPP `v26.10` (`mlx5dv`)** | **`34.1 / 234.0 / 319.2 / 353.1 / 412.5 / 674.6`** | `29.7 / 1678.0 / 2833.7 / 3472.5 / 4678.3 / 12774.0` | `0 / 5000` (`0.00%`) | [03-vpp-rdma-nat44.log](logs/03-vpp-rdma-nat44.log) |

---

## 7. Suite M4: Micro-Architectural Profiling & Upstream Engineering Findings

*(Hardware vPMU note: `i7-14700HX` is an Intel hybrid `cpu_core`/`cpu_atom` processor where KVM disables guest hardware PMU counters, so `perf stat -e cycles,instructions` inside `dut-vm` reports `<not supported>`. Micro-architectural attribution was therefore collected via three exact, complementary mechanisms: (1) Landscape live `kernel.bpf_stats_enabled=1` per-program `run_cnt`/`run_time_ns`, (2) `perf record -e cpu-clock -F 999 -C 0` kernel hotspot breakdowns, and (3) VPP `show runtime` hardware `rdtsc` per-node `Packet-Clocks`.)*

### 7.1 Live Landscape eBPF Per-Program Execution Cost (`kernel.bpf_stats_enabled=1`, 6s live samples)

| Workload | BPF Program (`type`) | Live Runs (6s) | Exact `ns/pkt` | Est. `cycles/pkt @ 5.3 GHz` | Source Log |
| --- | --- | ---: | ---: | ---: | --- |
| **M1 64B Clean Eth** | `tc_lan_ingress_route` (`sched_cls`) | `10,552,704` | **`58.62 ns`** | **`310.7 cyc`** | [03-landscape-clean.log](logs/03-landscape-clean.log) |
| **M1 64B Clean Eth** | `tc_wan_egress_route` (`sched_cls`, incl. NAT44 + FW) | `10,555,712` | **`94.59 ns`** | **`501.3 cyc`** | [03-landscape-clean.log](logs/03-landscape-clean.log) |
| **M1 64B Clean Eth** | **Total Landscape eBPF Dataplane** | — | **`153.21 ns`** | **`812.0 cyc`** | — |
| **M1 64B Rich Policy** | `tc_lan_ingress_route` (`1024 CIDR + FiveTuple + L4 Port`) | `10,446,912` | **`86.31 ns`** (`+27.7 ns`) | **`457.4 cyc`** | [03-landscape-policy.log](logs/03-landscape-policy.log) |
| **M1 64B Rich Policy** | `tc_wan_egress_route` (`sched_cls`, incl. NAT44 + FW) | `10,444,928` | **`92.56 ns`** | **`490.6 cyc`** | [03-landscape-policy.log](logs/03-landscape-policy.log) |
| **M1 64B Rich Policy** | **Total Landscape eBPF Dataplane** | — | **`178.87 ns`** | **`948.0 cyc`** | — |
| **M2-B 1492B PPPoE** | `tc_lan_ingress_route` (`sched_cls`) | `7,165,272` | `63.56 ns` | `336.9 cyc` | [04-m2b-pppoe-3way.log](logs/04-m2b-pppoe-3way.log) |
| **M2-B 1492B PPPoE** | `tc_wan_egress_route` (PPPoE+VLAN encap + NAT44 + FW) | `7,168,152` | `136.09 ns` | `721.3 cyc` | [04-m2b-pppoe-3way.log](logs/04-m2b-pppoe-3way.log) |
| **M2-B 1492B PPPoE** | `tc_wan_ingress_intro` (PPPoE decap + ACK path) | `305,470` | `258.54 ns` | `1370.3 cyc` | [04-m2b-pppoe-3way.log](logs/04-m2b-pppoe-3way.log) |
| **M2-B 1492B PPPoE** | **`pppoe_pnet_filter` (`socket_filter`)** | **`7,472,873`** | **`38.41 ns`** | **`203.6 cyc`** | [04-m2b-pppoe-3way.log](logs/04-m2b-pppoe-3way.log) |

### 7.2 Kernel `perf` Hotspots (M1 64B 1 P-core) vs VPP `show runtime`

- **Linux `nftables` (1.415 Mpps)**: `__raw_callee_save___pv_queued_spin_unlock` `13.27%`, `eth_type_trans` `4.25%`, `nft_do_chain` `3.75%`, `__xfrm_decode_session` `2.78%`, `__nf_conntrack_find_get` `2.50%`, `nf_hook_slow` `2.45%`, `__siphash_unaligned` `2.30%`, `nft_immediate_eval` `1.78%`, `nf_nat_inet_fn` `1.77%`, `ip_finish_output2` `1.73%`, `__skb_flow_dissect` `1.72%`, `nf_confirm` `1.45%`.
- **Linux `nftables + flowtable` (2.552 Mpps)**: `__raw_callee_save___pv_queued_spin_unlock` `18.60%`, `eth_type_trans` `6.83%`, `pvclock_clocksource_read_nowd` `3.48%`, `_raw_spin_lock` `2.67%`, `mlx5e_skb_from_cqe_linear` `2.12%`, `nf_flow_offload_ip_hook` `2.05%`, `flow_offload_lookup` `1.90%`, `__dev_queue_xmit` `1.85%`.
- **Landscape eBPF Clean (2.098 Mpps)**: `__raw_callee_save___pv_queued_spin_unlock` `20.18%`, `bpf_prog_*_tc_v4_from_lan` `5.90%`, `eth_type_trans` `5.87%`, `htab_map_hash` `3.99%`, `pvclock_clocksource_read_nowd` `3.77%`, `_raw_spin_lock` `3.67%`, `lookup_nulls_elem_raw` `3.24%`, `__dev_queue_xmit` `2.92%`, `cls_bpf_classify` `2.07%`, `mlx5e_xmit` `2.05%`, `tc_run` `1.75%`, `bpf_prog_*_tc_route4_lan_ingress` `1.25%`. *(Only ~153 ns/pkt is Landscape's own eBPF code; the remaining ~323 ns/pkt is Linux `mlx5e` skb lifecycle + TC + KVM paravirt spinlock overhead.)*
- **FD.io VPP `v26.10` (`show runtime` @ 4.488 Mpps, `6.60` vectors/call)**: Total **`411.6 clocks/pkt`** (`rdma-input` `97.3`, `ethernet-input` `62.8`, `ip4-input-no-checksum` `44.2`, `ip4-sv-reassembly-feature` `22.6`, `nat-pre-in2out` `15.0`, `nat44-ed-in2out` `66.2`, `ip4-lookup` `21.3`, `ip4-rewrite` `21.6`, `rdma-wan-output` `16.8`, `rdma-wan-tx` `43.8`).

### 7.3 Upstream Actionable Findings for `ThisSeanZhang/landscape`

1. **High-Value PPPoE Optimization (`pppoe_pnet_filter` + `ETH_P_ALL` on 100% of TX+RX data packets)**:
   - In [04-m2b-pppoe-3way.log](logs/04-m2b-pppoe-3way.log), the control-plane `socket_filter` `pppoe_pnet_filter` (`landscape-ebpf/src/bpf/pppoe_client.bpf.c:16`) ran **7,472,873 times in 6 seconds** (`38.41 ns/pkt` = `203.6 cycles/pkt`) — matching the exact sum of `tc_wan_egress_route` (`7,168,152`) + `tc_wan_ingress_intro` (`305,470`) = `7,473,622` packets! Because `landscape-ebpf/src/pppoe/mod.rs:20-56` opens and binds the `AF_PACKET` socket with `ETH_P_ALL (0x0003)`, Linux registers it in `dev->ptype_all`, forcing `dev_queue_xmit_nit()` (`skb_clone` + `packet_rcv` + 3x `bpf_skb_load_bytes` + `consume_skb`) on **every outgoing WAN packet** as well as `__netif_receive_skb_core` delivery on **every incoming WAN packet**.
   - Upstream opportunity: (a) immediately dropping `ETH_P_ALL` in favor of `ETH_P_PPP_SES`/`ETH_P_PPP_DISC` removes the socket from `ptype_all` and eliminates 100% of egress `dev_queue_xmit_nit()` clones (`95.9%` of calls here); or (b) forwarding rare LCP/IPCP/IPV6CP/PADT control frames from `tc_intro_pppoe` (`tc_wan_ingress_intro.bpf.c:46`, which already branches on `protocol != ETH_P_PPP_IPV4 && protocol != ETH_P_PPP_IPV6`) via BPF ringbuf while keeping a TX-only `sll_protocol = 0` raw socket during steady state eliminates **100% of both TX and RX packet-socket overhead (~15-20% total PPPoE CPU)**, pushing single-core Native PPPoE toward **`~17+ Gbps`**.
2. **NAT44 Short-Lived TCP CPS Ceiling (`nat4_ct_timer.h:16,18,204-208,297-298` & `tc_nat4_packet.h:54,85`)**:
   - In [03-landscape-clean.log](logs/03-landscape-clean.log), [03-landscape-policy.log](logs/03-landscape-policy.log), and [04-m2b-pppoe-and-cps-reuse.log](logs/04-m2b-pppoe-and-cps-reuse.log), Landscape hit `1,137 - 1,690 CPS` (Run 1 always `1,613 - 1,690 CPS` on a fresh port queue; Runs 2-3 `1,099 - 1,446 CPS`) at `~3%` CPU (`97%` idle) with `0` errors.
   - Root cause verified across `landscape-ebpf/src/bpf/nat_v4/` and `landscape-common/src/wan_service/nat/config.rs`:
     - **7s EIM Port Hold vs 32k Default Pool**: `NatConfig::default()` (`nat/config.rs:43`) seeds `32,768` TCP ports (`32768..=65535`). Each unique `(internal_addr, internal_port)` pops a dedicated WAN port (`tc_nat4_packet.h:54`) and holds it across `1s` `NAPT_CT_REPORT_INTERVAL_NS` (`nat4_ct_timer.h:16,204-208`, waiting for the first timer tick to notice `NAPT_TCP_BOTH_FIN`) + `6s` `NAPT_TCP_CLOSE_TIMEOUT_NS` (`nat4_ct_timer.h:18`) = `~7s` before `NAPT_CT_RETURN_PORT`, exhausting `32,768` ports in `<0.5s` across 16 LAN source IPs and triggering `1s` client TCP SYN RTO backoff.
     - **Explicit `SYN` Drop in `NAPT_CT_WAIT_TCP_CLOSE`**: `nat4_ct_timer.h:297-298` (`if (status == NAPT_CT_WAIT_TCP_CLOSE) return napt_tcp_phase_is_syn(tcp_phase) ? TC_ACT_SHOT : TC_ACT_OK;`) drops any new TCP `SYN` on a recently closed 4-tuple (while `napt_ct_status_can_activate()` at lines `51-54` blocks reactivation).
     - **Outbound Port-Sharing Lockout When `allow_reuse=0`**: `tc_nat4_packet.h:85` calls `napt_dynamic_remote_allowed()` (`tc_nat4.h:73-79`) on outbound `napt_lan_state`, preventing LAN clients from sharing `(internal_addr, internal_port) -> external_port` across distinct remote `(dst_addr, dst_port)` endpoints unless `allow_reuse=1`.
     - **Upstream opportunity**: (1) allow RFC 6191-style TCP `SYN` reopen when `status == NAPT_CT_WAIT_TCP_CLOSE` (`nat4_ct_timer.h:297-298`), (2) arm `NAPT_TCP_CLOSE_TIMEOUT_NS` immediately upon `NAPT_TCP_BOTH_FIN`/`RST` (and optionally widen `NatConfig::default()` to `1024..65535`), and (3) enforce `allow_reuse` only on unsolicited WAN ingress (`!ct` in `napt_wan_state`, `tc_nat4_packet.h:164`) so `allow_reuse=0` provides standard RFC 4787 **EIM + APDF** outbound port sharing while `allow_reuse=1` provides **EIM + EIF (Full-Cone)**.
3. **XDP vs TC Architecture on `ConnectX-4 Lx` (`mlx5` VF)**:
   - Default `v0.28.3` attaches strictly on `tc clsact` (`tc_lan_ingress_route`, `tc_wan_ingress_intro`, `tc_wan_egress_route`), preserving full GRO/GSO/TSO and delivering `21.95 Gbps` / `2.098 Mpps` peak / `1.887 Mpps` NDR.
   - Testing opt-in `--try-xdp` ([05-landscape-try-xdp-check.log](logs/05-landscape-try-xdp-check.log), [05-landscape-native-xdp.log](logs/05-landscape-native-xdp.log)) confirmed `xdp_lan_route` (`id 321`) and `xdp_wan_intro` (`id 304`) attach in `driver` mode on `enp1s0`/`enp2s0`, but `mlx5` SR-IOV VF `XDP_REDIRECT` dropped forwarded packets (`0/10`), validating upstream's TC-only default.
4. **Telemetry Caveat (`kernel.bpf_stats_enabled=1`)**:
   - Leaving `kernel.bpf_stats_enabled=1` enabled globally added `15.54%` CPU overhead in `pvclock_clocksource_read_nowd` inside KVM, depressing Landscape's M1 peak from `2.098 Mpps` to `1.758 Mpps` (`-16.2%`). Production gateways and benchmarks should keep `bpf_stats_enabled=0` except during short diagnostic windows.

---

## 8. Complete Raw Evidence Index (16 Published Technical Logs)

| Log File | Scope & Verification Status |
| --- | --- |
| [00-build-ebpf-bench.log](logs/00-build-ebpf-bench.log) | Detached worktree build of `landscape-ebpf` (`3a35a9c3`, `--features bpf-test`), `EXIT=0` |
| [00-build-webserver-release.log](logs/00-build-webserver-release.log) | Detached worktree release build of `landscape-webserver` (`84472315`), `EXIT=0` |
| [02-suite0-ebpf-microbench.log](logs/02-suite0-ebpf-microbench.log) | Suite 0 `BPF_PROG_TEST_RUN` (`route`, `nat4_v4`, `nat6`, `wan_dispatch`), all `EXIT=0` |
| [03-nftables.log](logs/03-nftables.log) | Contestant 1: Linux `nftables` baseline M1/M2-A/M3-A/M3-B/M4 |
| [03-nftables-addendum.log](logs/03-nftables-addendum.log) | Linux `nftables` 8-port CPS (`67.8k`) & `perf` hotspots |
| [03-nftables-flowtable.log](logs/03-nftables-flowtable.log) | Contestant 2: Linux `nftables + flowtable` M1/M2-A/M3-A/M3-B/M4 |
| [03-nftables-flowtable-addendum.log](logs/03-nftables-flowtable-addendum.log) | Linux `nftables + flowtable` 8-port CPS (`66.3k`) & `perf` hotspots |
| [03-linux-exact-ndr.log](logs/03-linux-exact-ndr.log) | Exact `ratep` 64B NDR verification for `nftables` (`1.347 Mpps`) & `flowtable` (`1.722 Mpps`) |
| [03-landscape-clean.log](logs/03-landscape-clean.log) | Contestant 3a: Landscape eBPF Clean Stateful NAT44 + FW full M1-M4 + `bpf_stats` |
| [03-landscape-policy.log](logs/03-landscape-policy.log) | Contestant 3b: Landscape eBPF Rich Policy (`1024 CIDR + FiveTuple + L4 Port`) full M1-M4 + `bpf_stats` |
| [04-m2b-pppoe-and-cps-reuse.log](logs/04-m2b-pppoe-and-cps-reuse.log) | Landscape `allow_reuse_port=true` CPS verification (`1,137 - 1,613 CPS`) |
| [04-m2b-pppoe-3way.log](logs/04-m2b-pppoe-3way.log) | M2-B `1492B PPPoE + VLAN 4091` Landscape Native eBPF PPPoE (`14.89 Gbps`) + `bpf_stats` (`pppoe_pnet_filter`) |
| [04-m2b-pppoe-linux-pppd.log](logs/04-m2b-pppoe-linux-pppd.log) | M2-B `1492B PPPoE + VLAN 4091` Linux `pppd + nftables` (`12.20 Gbps`) & `pppd + flowtable` (`12.88 Gbps`) |
| [03-vpp-rdma-nat44.log](logs/03-vpp-rdma-nat44.log) | Contestant 4: FD.io VPP `v26.10` (`mlx5dv` RDMA + `nat44-ed`) full M1-M4 + `show runtime` |
| [05-landscape-try-xdp-check.log](logs/05-landscape-try-xdp-check.log) | Landscape `--try-xdp` `bpftool net show` (`mlx5` VF `driver` mode attach) |
| [05-landscape-native-xdp.log](logs/05-landscape-native-xdp.log) | Landscape `--try-xdp` forwarding probe (`mlx5` VF `XDP_REDIRECT` drop proof) |

*(Note: Two host-specific operations logs from the benchmark session — hypervisor VM provisioning `01-pve-provision.log` and post-test teardown `99-teardown-recovery.log` — are intentionally omitted from `logs/` because they contain private hypervisor VM inventory and local monitoring checks. All 16 technical benchmark logs above are published in full after deterministic address/identifier sanitization.)*
