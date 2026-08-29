use anyhow::{Context, Result};

pub async fn wait_until_listening(
    interval: &std::time::Duration,
    proc_found_interval: &std::time::Duration,
    port: u16,
    proc_name: &str,
) -> Result<()> {
    loop {
        let procs = procfs::process::all_processes().with_context(
            || "Couldn't read /proc/ in order to monitor any XIVLauncher instances",
        )?;

        let mut delay = interval;

        let listening_candidates = procs
            //Match on process names
            .filter_map(|proc| {
                let Ok(proc) = proc else {
                    tracing::debug!(?proc, "Process vanished");
                    return None;
                };
                let Ok(stat) = proc.stat() else {
                    tracing::debug!(?proc, "Process vanished whilst fetching stat");
                    return None;
                };
                let comm = &stat.comm;
                if comm.contains(proc_name) {
                    tracing::debug!(?stat, ?proc, "Found promising process");
                    delay = proc_found_interval;
                    Some(proc)
                } else {
                    None
                }
            })
            //Check for open ports
            .filter_map(|matching_proc| {
                let Ok(tcp_table) = matching_proc.tcp() else {
                    tracing::warn!(
                        ?matching_proc,
                        "Found promising process but was unable to check for listening ports"
                    );
                    return None;
                };
                let matching_connections = tcp_table
                    .iter()
                    .filter(|conn| conn.local_address.port() == port)
                    .collect::<Vec<_>>();

                if matching_connections.is_empty() {
                    None
                } else {
                    Some(matching_proc)
                }
            })
            .collect::<Vec<_>>();

        if !listening_candidates.is_empty() {
            tracing::info!("XIVLauncher seems to be listening, generating TOTP...");
            break Ok(());
        } else {
            tokio::time::sleep(*delay).await;
        }
    }
}
