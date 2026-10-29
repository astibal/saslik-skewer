param(
    [Parameter(Mandatory=$true)][string]$Root
)

$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path -LiteralPath $Root).Path
$env:PATH = "$Root;$env:PATH"
$env:QT_QPA_PLATFORM = 'offscreen'

# Network-changing fixtures are opt-in, but their presence is a release gate.
# A green unit run must not conceal an incomplete integration-test archive.
foreach ($fixture in @('selected-service-live.ps1','selected-ipv6-egress.ps1',
    'selected-existing-ipv6.ps1','ipv6-marker-peer.py','selected-shared-udp.ps1',
    'udp-marker-peer.py','routed-application-smoke.ps1','run-routed-application-smoke.ps1',
    'native-routing-service-live.ps1','direct-routing-service-live.ps1','service-upgrade-live.ps1',
    'routing-ipc-contention.ps1','selected-pause-live.ps1','selected-handoff-live.ps1')) {
    if (!(Test-Path -LiteralPath (Join-Path $Root $fixture) -PathType Leaf)) {
        throw "Incomplete Windows test bundle: missing $fixture"
    }
}

$tests = @(
    @{ Name = 'windows_application_names'; File = 'application_names_test.exe' },
    @{ Name = 'windows_application_icons'; File = 'application_icons_test.exe' },
    @{ Name = 'windows_process_group'; File = 'process_group_test.exe' },
    @{ Name = 'windows_selection_registry'; File = 'selection_registry_test.exe' },
    @{ Name = 'windows_routing_control'; File = 'routing_control_test.exe' },
    @{ Name = 'selection_auth'; File = 'selection_auth_test.exe' },
    @{ Name = 'windows_selected_packet_epoch'; File = 'selected_packet_epoch_test.exe' },
    @{ Name = 'windows_udp_owners'; File = 'udp_owners_test.exe' },
    @{ Name = 'windows_tcp_owners'; File = 'tcp_owners_test.exe' },
    @{ Name = 'windows_app_guard_inputs'; File = 'app_egress_guard_test.exe'; Arguments = @('--self-test') },
    @{ Name = 'windows_udp'; File = 'udp_endpoint_test.exe'; Timeout = 45 },
    @{ Name = 'selected_tunnel_device'; File = 'selected_tunnel_device_test.exe'; Timeout = 45 },
    @{ Name = 'windows_tunnel_pump'; File = 'tunnel_pump_test.exe'; Timeout = 45 },
    @{ Name = 'windows_tuntom_udp'; File = 'tuntom_udp_test.exe'; Timeout = 45 },
    @{ Name = 'windows_processes'; File = 'skewer-process-probe.exe'; Arguments = @('--self-test') },
    @{ Name = 'wintun_device'; File = 'wintun_device_test.exe'; Timeout = 45 },
    @{ Name = 'windows_flow_tracking'; File = 'flow_tracking_test.exe' },
    @{ Name = 'flow_watch_arguments'; File = 'skewer-flow-watch.exe'; Arguments = @('--self-test') },
    @{ Name = 'windows_pairing_snapshot'; File = 'pairing_snapshot_test.exe' },
    @{ Name = 'windows_client_report'; File = 'client_report_test.exe' },
    @{ Name = 'windows_pairing_storage'; File = 'pairing_storage_test.exe' },
    @{ Name = 'windows_paired_tunnel'; File = 'paired_tunnel_test.exe'; Timeout = 75 },
    @{ Name = 'windows_tunnel_dns'; File = 'tunnel_dns_test.exe' },
    @{ Name = 'windows_service_installer'; File = 'service_installer_test.exe' },
    @{ Name = 'windows_runtime_trust'; File = 'runtime_trust_test.exe' },
    @{ Name = 'windows_ca_trust_panel'; File = 'ca_trust_panel_test.exe' },
    @{ Name = 'windows_routing_panel'; File = 'routing_panel_test.exe' },
    @{ Name = 'windows_direct_host_policy'; File = 'direct_host_policy_test.exe' },
    @{ Name = 'windows_whole_host_policy'; File = 'whole_host_policy_test.exe' },
    @{ Name = 'windows_owned_route_live'; File = 'owned_route_test.exe'; Arguments = @('--live') },
    @{ Name = 'windows_tunnel_routes_live'; File = 'tunnel_routes_test.exe'; Arguments = @('--live') },
    @{ Name = 'tunnel_flows'; File = 'tunnel_flows_test.exe' },
    @{ Name = 'packet_rewrite'; File = 'packet_rewrite_test.exe' },
    @{ Name = 'tunnel_lease'; File = 'tunnel_lease_test.exe' },
    @{ Name = 'routing_scope'; File = 'routing_scope_test.exe' },
    @{ Name = 'owner_evidence'; File = 'owner_evidence_test.exe' },
    @{ Name = 'packet_tuple'; File = 'packet_tuple_test.exe' },
    @{ Name = 'flow_index'; File = 'flow_index_test.exe' },
    @{ Name = 'pending_packets'; File = 'pending_packets_test.exe' },
    @{ Name = 'selected_packets'; File = 'selected_packets_test.exe' },
    @{ Name = 'tunnel_contract'; File = 'tunnel_contract_test.exe' },
    @{ Name = 'portable_process_browser'; File = 'process_browser_test.exe' },
    @{ Name = 'launch_catalog'; File = 'launch_catalog_test.exe' },
    @{ Name = 'shared_application_shell'; File = 'application_shell_test.exe' }
)

function Invoke-NativeTest {
    param([hashtable]$Test)

    $path = Join-Path $Root $Test.File
    if (!(Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing Windows test executable: $($Test.File)"
    }
    $timeout = if ($Test.Timeout) { [int]$Test.Timeout } else { 30 }
    $arguments = if ($Test.Arguments) { [string[]]$Test.Arguments } else { @() }
    $process = $null
    try {
        Write-Host ("START {0}" -f $Test.Name)
        $start = New-Object System.Diagnostics.ProcessStartInfo
        $start.FileName = $path
        $start.WorkingDirectory = $Root
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.Arguments = ($arguments -join ' ')
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $start
        if (!$process.Start()) { throw "Cannot start test: $($Test.Name)" }
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit($timeout * 1000)) {
            & taskkill.exe /PID $process.Id /T /F | Out-Null
            $process.WaitForExit()
            throw "Test timed out after $timeout seconds: $($Test.Name)"
        }
        $process.WaitForExit()
        $out = $outTask.Result
        $err = $errTask.Result
        if ($out) { Write-Host $out.TrimEnd() }
        if ($err) { Write-Host $err.TrimEnd() }
        if ($process.ExitCode -ne 0) {
            throw "Test failed with exit code $($process.ExitCode): $($Test.Name)"
        }
        Write-Host ("PASS  {0}" -f $Test.Name)
    } finally {
        if ($process) { $process.Dispose() }
    }
}

foreach ($test in $tests) {
    Invoke-NativeTest $test
}
Write-Output "PASS: $($tests.Count) native Windows tests"
