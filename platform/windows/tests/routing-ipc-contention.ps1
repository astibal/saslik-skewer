param(
    [Parameter(Mandatory=$true)][string]$Directory,
    [Parameter(Mandatory=$true)][string]$ServiceName,
    [ValidateRange(1,200)][int]$Iterations=25
)
$ErrorActionPreference='Stop'
$client=Join-Path (Resolve-Path $Directory).Path 'skewer-routing-control.exe'
if (!(Test-Path $client)) { throw 'Routing control client missing' }
# Read-only probe: concurrent clients must not start, stop or select routing.
# Each command gets its own connection; never hide a failed exchange by retrying.
$jobs=@()
try {
    foreach ($worker in 1..4) {
        $jobs+=Start-Job -ArgumentList $client,$ServiceName,$Iterations,$worker -ScriptBlock {
            param($client,$service,$iterations,$worker)
            for ($i=0; $i -lt $iterations; ++$i) {
                $text=(& $client status $service 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0) {
                    throw "Worker $worker connection ${i}: exit=$LASTEXITCODE $text"
                }
                $state=$text | ConvertFrom-Json -ErrorAction Stop
                if ($null -eq $state.phase -or $null -eq $state.generation) {
                    throw "Worker $worker received an incomplete status"
                }
            }
            "PASS: IPC worker $worker completed $iterations authenticated connections"
        }
    }
    # Bound the whole fixture as well as each native client's connection budget.
    $null=$jobs | Wait-Job -Timeout (30 + 4 * $Iterations)
    foreach ($job in $jobs) {
        if ($job.State -ne 'Completed') {
            $job | Receive-Job -ErrorAction Continue
            throw "IPC worker did not complete: $($job.State)"
        }
        $job | Receive-Job -ErrorAction Stop
    }
} finally {
    $jobs | Remove-Job -Force
}
