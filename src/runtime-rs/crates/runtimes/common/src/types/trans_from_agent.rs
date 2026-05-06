// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::convert::From;
use std::sync::OnceLock;

use containerd_shim_protos::cgroups::metrics as cgroupsv1;
use nix::sys::statfs::{statfs, CGROUP2_SUPER_MAGIC};
use protobuf::Message;

use super::{cgroupsv2, StatsInfo, StatsInfoValue};

static IS_CGROUPV2: OnceLock<bool> = OnceLock::new();

/// Returns true if the host is running cgroupsv2 (unified hierarchy).
/// The result is cached after the first call.
fn is_cgroupv2() -> bool {
    *IS_CGROUPV2.get_or_init(|| {
        statfs("/sys/fs/cgroup")
            .map(|s| s.filesystem_type() == CGROUP2_SUPER_MAGIC)
            .unwrap_or(false)
    })
}

impl From<Option<agent::StatsContainerResponse>> for StatsInfo {
    fn from(c_stats: Option<agent::StatsContainerResponse>) -> Self {
        let stats = match c_stats {
            None => return StatsInfo { value: None },
            Some(s) => s,
        };

        if is_cgroupv2() {
            stats_to_stats_info_v2(stats)
        } else {
            stats_to_stats_info_v1(stats)
        }
    }
}

fn stats_to_stats_info_v1(stats: agent::StatsContainerResponse) -> StatsInfo {
    let mut metric = cgroupsv1::Metrics::new();

    if let Some(cg_stats) = stats.cgroup_stats {
        if let Some(cpu) = cg_stats.cpu_stats {
            let mut p_cpu = cgroupsv1::CPUStat::new();
            if let Some(usage) = cpu.cpu_usage {
                let mut p_usage = cgroupsv1::CPUUsage::new();
                p_usage.set_total(usage.total_usage);
                p_usage.set_per_cpu(usage.percpu_usage);
                p_usage.set_kernel(usage.usage_in_kernelmode);
                p_usage.set_user(usage.usage_in_usermode);
                p_cpu.set_usage(p_usage);
            }
            if let Some(throttle) = cpu.throttling_data {
                let mut p_throttle = cgroupsv1::Throttle::new();
                p_throttle.set_periods(throttle.periods);
                p_throttle.set_throttled_time(throttle.throttled_time);
                p_throttle.set_throttled_periods(throttle.throttled_periods);
                p_cpu.set_throttling(p_throttle);
            }
            metric.set_cpu(p_cpu);
        }

        if let Some(m_stats) = cg_stats.memory_stats {
            let mut p_m = cgroupsv1::MemoryStat::new();
            p_m.set_cache(m_stats.cache);
            if let Some(m_data) = m_stats.usage {
                let mut p_m_entry = cgroupsv1::MemoryEntry::new();
                p_m_entry.set_usage(m_data.usage);
                p_m_entry.set_limit(m_data.limit);
                p_m_entry.set_failcnt(m_data.failcnt);
                p_m_entry.set_max(m_data.max_usage);
                p_m.set_usage(p_m_entry);
            }
            if let Some(m_data) = m_stats.swap_usage {
                let mut p_m_entry = cgroupsv1::MemoryEntry::new();
                p_m_entry.set_usage(m_data.usage);
                p_m_entry.set_limit(m_data.limit);
                p_m_entry.set_failcnt(m_data.failcnt);
                p_m_entry.set_max(m_data.max_usage);
                p_m.set_swap(p_m_entry);
            }
            if let Some(m_data) = m_stats.kernel_usage {
                let mut p_m_entry = cgroupsv1::MemoryEntry::new();
                p_m_entry.set_usage(m_data.usage);
                p_m_entry.set_limit(m_data.limit);
                p_m_entry.set_failcnt(m_data.failcnt);
                p_m_entry.set_max(m_data.max_usage);
                p_m.set_kernel(p_m_entry);
            }
            for (k, v) in m_stats.stats {
                match k.as_str() {
                    "dirty" => p_m.set_dirty(v),
                    "rss" => p_m.set_rss(v),
                    "rss_huge" => p_m.set_rss_huge(v),
                    "mapped_file" => p_m.set_mapped_file(v),
                    "writeback" => p_m.set_writeback(v),
                    "pg_pg_in" => p_m.set_pg_pg_in(v),
                    "pg_pg_out" => p_m.set_pg_pg_out(v),
                    "pg_fault" => p_m.set_pg_fault(v),
                    "pg_maj_fault" => p_m.set_pg_maj_fault(v),
                    "inactive_file" => p_m.set_inactive_file(v),
                    "inactive_anon" => p_m.set_inactive_anon(v),
                    "active_file" => p_m.set_active_file(v),
                    "unevictable" => p_m.set_unevictable(v),
                    "hierarchical_memory_limit" => p_m.set_hierarchical_memory_limit(v),
                    "hierarchical_swap_limit" => p_m.set_hierarchical_swap_limit(v),
                    "total_cache" => p_m.set_total_cache(v),
                    "total_rss" => p_m.set_total_rss(v),
                    "total_mapped_file" => p_m.set_total_mapped_file(v),
                    "total_dirty" => p_m.set_total_dirty(v),
                    "total_pg_pg_in" => p_m.set_total_pg_pg_in(v),
                    "total_pg_pg_out" => p_m.set_total_pg_pg_out(v),
                    "total_pg_fault" => p_m.set_total_pg_fault(v),
                    "total_pg_maj_fault" => p_m.set_total_pg_maj_fault(v),
                    "total_inactive_file" => p_m.set_total_inactive_file(v),
                    "total_inactive_anon" => p_m.set_total_inactive_anon(v),
                    "total_active_file" => p_m.set_total_active_file(v),
                    "total_unevictable" => p_m.set_total_unevictable(v),
                    _ => (),
                }
            }
            metric.set_memory(p_m);
        }

        if let Some(pid_stats) = cg_stats.pids_stats {
            let mut p_pid = cgroupsv1::PidsStat::new();
            p_pid.set_limit(pid_stats.limit);
            p_pid.set_current(pid_stats.current);
            metric.set_pids(p_pid);
        }

        if let Some(blk_stats) = cg_stats.blkio_stats {
            let mut p_blk_stats = cgroupsv1::BlkIOStat::new();
            p_blk_stats
                .set_io_serviced_recursive(copy_blkio_entry_v1(&blk_stats.io_serviced_recursive));
            p_blk_stats.set_io_service_bytes_recursive(copy_blkio_entry_v1(
                &blk_stats.io_service_bytes_recursive,
            ));
            p_blk_stats
                .set_io_queued_recursive(copy_blkio_entry_v1(&blk_stats.io_queued_recursive));
            p_blk_stats.set_io_service_time_recursive(copy_blkio_entry_v1(
                &blk_stats.io_service_time_recursive,
            ));
            p_blk_stats.set_io_wait_time_recursive(copy_blkio_entry_v1(
                &blk_stats.io_wait_time_recursive,
            ));
            p_blk_stats
                .set_io_merged_recursive(copy_blkio_entry_v1(&blk_stats.io_merged_recursive));
            p_blk_stats
                .set_io_time_recursive(copy_blkio_entry_v1(&blk_stats.io_time_recursive));
            p_blk_stats
                .set_sectors_recursive(copy_blkio_entry_v1(&blk_stats.sectors_recursive));
            metric.set_blkio(p_blk_stats);
        }

        if !cg_stats.hugetlb_stats.is_empty() {
            let mut p_huge = Vec::new();
            for (k, v) in cg_stats.hugetlb_stats {
                let mut h = cgroupsv1::HugetlbStat::new();
                h.set_pagesize(k);
                h.set_max(v.max_usage);
                h.set_usage(v.usage);
                h.set_failcnt(v.failcnt);
                p_huge.push(h);
            }
            metric.set_hugetlb(p_huge);
        }
    }

    let net_stats = stats.network_stats;
    if !net_stats.is_empty() {
        let mut p_net = Vec::new();
        for v in net_stats.iter() {
            let mut h = cgroupsv1::NetworkStat::new();
            h.set_name(v.name.clone());
            h.set_tx_bytes(v.tx_bytes);
            h.set_tx_packets(v.tx_packets);
            h.set_tx_errors(v.tx_errors);
            h.set_tx_dropped(v.tx_dropped);
            h.set_rx_bytes(v.rx_bytes);
            h.set_rx_packets(v.rx_packets);
            h.set_rx_errors(v.rx_errors);
            h.set_rx_dropped(v.rx_dropped);
            p_net.push(h);
        }
        metric.set_network(p_net);
    }

    StatsInfo {
        value: Some(StatsInfoValue {
            type_url: "io.containerd.cgroups.v1.Metrics".to_string(),
            value: metric.write_to_bytes().unwrap(),
        }),
    }
}

fn stats_to_stats_info_v2(stats: agent::StatsContainerResponse) -> StatsInfo {
    use cgroupsv2::metrics as v2;

    let mut metric = v2::Metrics::new();

    if let Some(cg_stats) = stats.cgroup_stats {
        if let Some(cpu) = cg_stats.cpu_stats {
            let mut p_cpu = v2::CPUStat::new();
            if let Some(usage) = cpu.cpu_usage {
                p_cpu.set_usage_usec(usage.total_usage / 1000);
                p_cpu.set_user_usec(usage.usage_in_usermode / 1000);
                p_cpu.set_system_usec(usage.usage_in_kernelmode / 1000);
            }
            if let Some(throttle) = cpu.throttling_data {
                p_cpu.set_nr_periods(throttle.periods);
                p_cpu.set_nr_throttled(throttle.throttled_periods);
                p_cpu.set_throttled_usec(throttle.throttled_time / 1000);
            }
            metric.set_cpu(p_cpu);
        }

        if let Some(m_stats) = cg_stats.memory_stats {
            let mut p_m = v2::MemoryStat::new();
            if let Some(usage) = m_stats.usage {
                p_m.set_usage(usage.usage);
                p_m.set_usage_limit(usage.limit);
            }
            if let Some(swap) = m_stats.swap_usage {
                p_m.set_swap_usage(swap.usage);
                p_m.set_swap_limit(swap.limit);
            }
            for (k, v) in m_stats.stats {
                match k.as_str() {
                    "anon" => p_m.set_anon(v),
                    "file" => p_m.set_file(v),
                    "kernel_stack" => p_m.set_kernel_stack(v),
                    "slab" => p_m.set_slab(v),
                    "sock" => p_m.set_sock(v),
                    "shmem" => p_m.set_shmem(v),
                    "file_mapped" => p_m.set_file_mapped(v),
                    "file_dirty" => p_m.set_file_dirty(v),
                    "file_writeback" => p_m.set_file_writeback(v),
                    "anon_thp" => p_m.set_anon_thp(v),
                    "inactive_anon" => p_m.set_inactive_anon(v),
                    "active_anon" => p_m.set_active_anon(v),
                    "inactive_file" => p_m.set_inactive_file(v),
                    "active_file" => p_m.set_active_file(v),
                    "unevictable" => p_m.set_unevictable(v),
                    "slab_reclaimable" => p_m.set_slab_reclaimable(v),
                    "slab_unreclaimable" => p_m.set_slab_unreclaimable(v),
                    "pgfault" => p_m.set_pgfault(v),
                    "pgmajfault" => p_m.set_pgmajfault(v),
                    "workingset_refault" => p_m.set_workingset_refault(v),
                    "workingset_activate" => p_m.set_workingset_activate(v),
                    "workingset_nodereclaim" => p_m.set_workingset_nodereclaim(v),
                    "pgrefill" => p_m.set_pgrefill(v),
                    "pgscan" => p_m.set_pgscan(v),
                    "pgsteal" => p_m.set_pgsteal(v),
                    "pgactivate" => p_m.set_pgactivate(v),
                    "pgdeactivate" => p_m.set_pgdeactivate(v),
                    "pglazyfree" => p_m.set_pglazyfree(v),
                    "pglazyfreed" => p_m.set_pglazyfreed(v),
                    "thp_fault_alloc" => p_m.set_thp_fault_alloc(v),
                    "thp_collapse_alloc" => p_m.set_thp_collapse_alloc(v),
                    _ => (),
                }
            }
            metric.set_memory(p_m);
        }

        if let Some(pid_stats) = cg_stats.pids_stats {
            let mut p_pid = v2::PidsStat::new();
            p_pid.set_current(pid_stats.current);
            p_pid.set_limit(pid_stats.limit);
            metric.set_pids(p_pid);
        }

        if let Some(blk_stats) = cg_stats.blkio_stats {
            let mut io_stat = v2::IOStat::new();
            io_stat.set_usage(copy_io_entries_v2(&blk_stats.io_service_bytes_recursive));
            metric.set_io(io_stat);
        }

        if !cg_stats.hugetlb_stats.is_empty() {
            let mut p_huge = Vec::new();
            for (k, v) in cg_stats.hugetlb_stats {
                let mut h = v2::HugeTlbStat::new();
                h.set_pagesize(k);
                h.set_max(v.max_usage);
                h.set_current(v.usage);
                p_huge.push(h);
            }
            metric.set_hugetlb(p_huge);
        }
    }

    StatsInfo {
        value: Some(StatsInfoValue {
            type_url: "io.containerd.cgroups.v2.Metrics".to_string(),
            value: metric.write_to_bytes().unwrap(),
        }),
    }
}

fn copy_blkio_entry_v1(entry: &[agent::BlkioStatsEntry]) -> Vec<cgroupsv1::BlkIOEntry> {
    let mut p_entry = Vec::new();
    for e in entry.iter() {
        let mut blk = cgroupsv1::BlkIOEntry::new();
        blk.set_op(e.op.clone());
        blk.set_value(e.value);
        blk.set_major(e.major);
        blk.set_minor(e.minor);
        p_entry.push(blk);
    }
    p_entry
}

fn copy_io_entries_v2(entry: &[agent::BlkioStatsEntry]) -> Vec<cgroupsv2::metrics::IOEntry> {
    // Group entries by major/minor device, mapping op names to cgroupsv2 IOEntry fields.
    use std::collections::HashMap;
    let mut devices: HashMap<(u64, u64), cgroupsv2::metrics::IOEntry> = HashMap::new();

    for e in entry.iter() {
        let dev = devices.entry((e.major, e.minor)).or_insert_with(|| {
            let mut io = cgroupsv2::metrics::IOEntry::new();
            io.set_major(e.major);
            io.set_minor(e.minor);
            io
        });
        match e.op.as_str() {
            "read" => dev.set_rbytes(e.value),
            "write" => dev.set_wbytes(e.value),
            "rios" => dev.set_rios(e.value),
            "wios" => dev.set_wios(e.value),
            _ => (),
        }
    }

    devices.into_values().collect()
}
