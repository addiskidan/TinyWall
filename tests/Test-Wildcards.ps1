param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$bundle = Split-Path -Parent $PSScriptRoot
$code = Join-Path $bundle 'TinyWall'
Add-Type -Path @(
    (Join-Path $code 'ExecutablePathPattern.cs'),
    (Join-Path $code 'WildcardRuleManager.cs'),
    (Join-Path $PSScriptRoot 'TestTypes.cs')
) -CompilerOptions '/langversion:9.0','/nullable:enable'

$script:passed = 0
function Assert-That([bool]$condition, [string]$name) {
    if (-not $condition) { throw "FAIL: $name" }
    $script:passed++
    Write-Output "PASS: $name"
}
function Assert-Rejected([string]$pattern) {
    $rejected = $false
    try { $null = [pylorak.TinyWall.ExecutablePathPattern]::new($pattern) }
    catch { $rejected = $true }
    Assert-That $rejected "reject $pattern"
}
function New-TestRule([string]$path, [pylorak.TinyWall.PolicyType]$policy) {
    [pylorak.TinyWall.FirewallExceptionV3]::new(
        [pylorak.TinyWall.ExecutableSubject]::new($path),
        [pylorak.TinyWall.ExceptionPolicy]::new($policy))
}

$shallow = [pylorak.TinyWall.ExecutablePathPattern]::new('C:\Apps\*.exe')
Assert-That ($shallow.Matches('c:\apps\ChatGPT.EXE')) 'case-insensitive shallow match'
Assert-That (-not $shallow.Matches('C:\Apps\v1\codex.exe')) 'single star does not cross directories'
Assert-That (-not $shallow.Matches('C:\Apps-other\codex.exe')) 'folder boundary cannot match a sibling'
Assert-That (-not $shallow.Matches('C:\Apps\codex.exe1')) 'only .exe extension matches'
Assert-That (-not $shallow.Matches('C:\Apps\..\outside.exe')) 'candidate traversal rejected'
$recursive = [pylorak.TinyWall.ExecutablePathPattern]::new('C:\Apps\**\codex.exe')
Assert-That ($recursive.Matches('C:\Apps\codex.exe')) 'recursive wildcard includes root'
Assert-That ($recursive.Matches('C:\Apps\v2\bin\codex.exe')) 'recursive wildcard includes nested folders'
Assert-That (-not $recursive.Matches('C:\Apps\v2\rg.exe')) 'exact filename narrows recursive access'
$versioned = [pylorak.TinyWall.ExecutablePathPattern]::new('C:\Apps\OpenAI.Codex_*\app\ChatGPT.exe')
Assert-That ($versioned.Matches('C:\Apps\OpenAI.Codex_27.1\app\ChatGPT.exe')) 'versioned directory pattern'
Assert-That (-not $versioned.Matches('C:\Apps\Other_27.1\app\ChatGPT.exe')) 'unrelated package excluded'
Assert-That ($versioned.MatchesDirectoryPrefix('C:\Apps\OpenAI.Codex_27.1')) 'version folder remains eligible for scanning'
Assert-That ($versioned.MatchesDirectoryPrefix('C:\Apps\OpenAI.Codex_27.1\app')) 'literal folder after wildcard remains eligible'
Assert-That (-not $versioned.MatchesDirectoryPrefix('C:\Apps\Other_27.1')) 'unrelated package subtree not scanned'
Assert-That (-not $versioned.MatchesDirectoryPrefix('C:\Apps\OpenAI.Codex_27.1\app\nested')) 'non-recursive pattern stops at expected depth'
Assert-That ($recursive.MatchesDirectoryPrefix('C:\Apps\v2\deep\bin')) 'recursive directory scan remains eligible'
$question = [pylorak.TinyWall.ExecutablePathPattern]::new('C:/Apps/app?.exe')
Assert-That ($question.Matches('C:\Apps\app1.exe')) 'question wildcard and slash normalization'
Assert-That (-not $question.Matches('C:\Apps\app12.exe')) 'question wildcard matches exactly one character'
foreach ($invalid in @('*.exe','C:\*.exe','C:\**\*.exe','\\server\share\*.exe',
    'C:\Apps\..\*.exe','C:\Apps\*.dll','C:\Apps\bad**\*.exe','C:\Apps.\*.exe',
    'C:\Apps\*.exe:stream','C:\Apps\\*.exe')) { Assert-Rejected $invalid }

$fixture = Join-Path $PSScriptRoot ('fixture-' + [Guid]::NewGuid().ToString('N'))
$root = Join-Path $fixture 'Allowed'
$errors = [Collections.Generic.List[Exception]]::new()
$signal = [Threading.ManualResetEventSlim]::new($false)
$manager = $null
$junction = Join-Path $root 'linked'
try {
    $null = [IO.Directory]::CreateDirectory((Join-Path $root 'v1'))
    [IO.File]::WriteAllText((Join-Path $root 'main.exe'), 'fixture')
    [IO.File]::WriteAllText((Join-Path $root 'v1\codex.exe'), 'fixture')
    [IO.File]::WriteAllText((Join-Path $root 'notes.txt'), 'fixture')
    $pattern = Join-Path $root '**\*.exe'
    $enumerated = [pylorak.TinyWall.ExecutablePathPattern]::new($pattern).EnumerateExecutables()
    Assert-That ($enumerated.Count -eq 2) 'enumerates only executable members'
    $allow = New-TestRule $pattern Unrestricted
    $block = New-TestRule $pattern HardBlock
    $allow.Timer = [pylorak.TinyWall.AppExceptionTimer]::For_5_Minutes
    $exact = New-TestRule (Join-Path $fixture 'standalone.exe') TcpUdpOnly
    $changed = [Action]$signal.Set
    $report = [Action[Exception]]$errors.Add
    $manager = [pylorak.TinyWall.WildcardRuleManager]::new($changed, $report)
    $rules = [pylorak.TinyWall.FirewallExceptionV3[]]@($allow,$block,$exact)
    $expanded = $manager.Expand($rules)
    Assert-That ($expanded.Count -eq 5) 'expands allow and block; retains exact exception'
    $allowMembers = @($expanded | Where-Object Id -eq $allow.Id)
    Assert-That ($allowMembers.Count -eq 2) 'pattern ID preserved for every member'
    Assert-That ([object]::ReferenceEquals($allowMembers[0].Policy,$allow.Policy)) 'port and restriction policy preserved'
    Assert-That ($allowMembers[0].Timer -eq $allow.Timer -and $allowMembers[0].CreationDate -eq $allow.CreationDate) 'lifetime and creation time preserved'
    Assert-That (-not $allowMembers[0].ChildProcessesInherit) 'child inheritance remains off by default'
    $allow.ChildProcessesInherit = $true
    $block.ChildProcessesInherit = $true
    $inheritable = $manager.Expand($rules)
    Assert-That (@($inheritable | Where-Object { $_.Id -eq $allow.Id -and $_.ChildProcessesInherit }).Count -eq 2) 'allow wildcard preserves explicit child-inheritance opt-in for each matched parent'
    Assert-That (@($inheritable | Where-Object { $_.Id -eq $block.Id -and $_.ChildProcessesInherit }).Count -eq 2) 'block wildcard preserves explicit child-inheritance opt-in'
    $allow.ChildProcessesInherit = $false
    $block.ChildProcessesInherit = $false
    $withoutChildren = $manager.Expand($rules)
    Assert-That (@($withoutChildren | Where-Object { ($_.Id -eq $allow.Id -or $_.Id -eq $block.Id) -and $_.ChildProcessesInherit }).Count -eq 0) 'turning child inheritance off removes the option from expanded parents'
    Assert-That (-not $manager.HasMembershipChanged()) 'unchanged membership stable'
    [IO.File]::WriteAllText((Join-Path $root 'v1\new.exe'), 'fixture')
    Assert-That ($signal.Wait(5000)) 'file watcher signals new executable'
    Assert-That ($manager.HasMembershipChanged()) 'new executable detected by fallback scan'
    Assert-That ($manager.Expand($rules).Count -eq 7) 'new executable receives both allow and block policies'
    [IO.File]::Delete((Join-Path $root 'v1\new.exe'))
    Assert-That ($manager.HasMembershipChanged()) 'deleted executable detected'
    Assert-That ($manager.Expand($rules).Count -eq 6) 'deleted allow removed; known block identity retained'
    Assert-That ($manager.Expand([pylorak.TinyWall.FirewallExceptionV3[]]@($exact)).Count -eq 1) 'removing patterns removes their expanded exceptions'
    $null = $manager.Expand([pylorak.TinyWall.FirewallExceptionV3[]]@($allow))
    [IO.File]::Move((Join-Path $root 'v1\codex.exe'),(Join-Path $root 'v1\renamed.exe'))
    Assert-That ($manager.HasMembershipChanged()) 'renamed executable detected'
    $external = Join-Path $fixture 'Outside'
    $null = [IO.Directory]::CreateDirectory($external)
    [IO.File]::WriteAllText((Join-Path $external 'outside.exe'), 'fixture')
    $null = New-Item -ItemType Junction -Path $junction -Value $external
    $safe = [pylorak.TinyWall.ExecutablePathPattern]::new($pattern).EnumerateExecutables()
    Assert-That (-not $safe.Contains((Join-Path $junction 'outside.exe'))) 'does not follow a junction outside the root'
    $rootRejected = $false
    try { $null = [pylorak.TinyWall.ExecutablePathPattern]::new((Join-Path $junction '*.exe')).EnumerateExecutables() }
    catch { $rootRejected = $true }
    Assert-That $rootRejected 'junction cannot serve as a wildcard root'
    Assert-That ($errors.Count -eq 0) 'valid patterns produced no scan or watcher errors'
}
finally {
    if ($manager) { $manager.Dispose() }
    $signal.Dispose()
    if (Test-Path -LiteralPath $junction) { Remove-Item -LiteralPath $junction -Force }
    $resolved = [IO.Path]::GetFullPath($fixture)
    $boundary = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\') + '\'
    if (-not $resolved.StartsWith($boundary,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($resolved) -notmatch '^fixture-[a-f0-9]{32}$') {
        throw 'Refusing to remove an unexpected test fixture path.'
    }
    if (Test-Path -LiteralPath $resolved) { Remove-Item -LiteralPath $resolved -Recurse -Force }
}
Write-Output "Wildcard tests passed: $script:passed"
