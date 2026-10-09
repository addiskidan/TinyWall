param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$bundle = Split-Path -Parent $PSScriptRoot
$script:passed = 0
function Assert-That([bool]$condition, [string]$name) {
    if (-not $condition) { throw "FAIL: $name" }
    $script:passed++
    Write-Output "PASS: $name"
}
Add-Type -TypeDefinition 'public class LoadRoslynForTinyWallTests { }'
$patched = Get-Content -LiteralPath (Join-Path $bundle 'TinyWall\TinyWallService.cs') -Raw
function Get-Method([string]$source, [string]$name, [int]$parameterCount = -1) {
    $root = [Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText($source).GetRoot()
    $methods = @($root.DescendantNodes() | Where-Object {
        $_ -is [Microsoft.CodeAnalysis.CSharp.Syntax.MethodDeclarationSyntax] -and $_.Identifier.ValueText -eq $name -and ($parameterCount -lt 0 -or $_.ParameterList.Parameters.Count -eq $parameterCount)
    })
    if ($methods.Count -ne 1) { throw "Expected exactly one method: $name" }
    return $methods[0]
}
$newInstall = Get-Method $patched InstallRules
$normalizer = Get-Method $patched NormalizeApplicationPaths
$processManager = Get-Content -LiteralPath (Join-Path $bundle 'pylorak.Windows\ProcessManager.cs') -Raw
Assert-That ($processManager -match 'GetProcessPath[\s\S]+PathFormat.Win32') 'process discovery returns Windows paths'
$filter = Get-Method $patched ConstructFilter 2
Assert-That ($filter.ToString() -match 'new AppIdFilterCondition\(r.Application, false, true\)') 'filter constructor assumes kernel-format identities'
Assert-That ($newInstall.ToString() -match 'NormalizeApplicationPaths\(rules\)' -and $newInstall.ToString() -match 'NormalizeApplicationPaths\(rawSocketExceptions\)') 'shared installer normalizes ordinary and raw-socket rules'
Assert-That ($newInstall.ToString().IndexOf('NormalizeApplicationPaths') -lt $newInstall.ToString().IndexOf('ConstructFilter')) 'conversion occurs before filter construction'
$tempCase = Get-Method $patched ProcessCmd
Assert-That ($tempCase.ToString() -match 'ADD_TEMPORARY_EXCEPTION[\s\S]+InstallRules\(rules, rawSocketExceptions, true\)') 'child rules use the corrected shared installer'
Assert-That ($patched -match 'UserExceptions = WildcardRules.Expand\(UserExceptions\)') 'wildcards expand before rule construction'
Assert-That ($patched -match 'WildcardRules.HasMembershipChanged\(\)') 'periodic wildcard reconciliation wired into service'
Assert-That ($patched -match 'UserBlock = 6000000' -and $patched -match 'UserPermit = 5000000') 'explicit block priority remains above allow priority'
$newAssemble = Get-Method $patched AssembleActiveRules
$modeSwitch = @($newAssemble.DescendantNodes() | Where-Object {
    $_ -is [Microsoft.CodeAnalysis.CSharp.Syntax.SwitchStatementSyntax] -and $_.Expression.ToString() -eq 'VisibleState.Mode'
})[0]
$disabled = @($modeSwitch.Sections | Where-Object { $_.Labels.ToString() -match 'FirewallMode.Disabled' })[0].ToString()
$outgoing = @($modeSwitch.Sections | Where-Object { $_.Labels.ToString() -match 'FirewallMode.AllowOutgoing' })[0].ToString()
Assert-That ($disabled -match 'needUserRules = false' -and $disabled -match 'Allow everything') 'Disabled intentionally bypasses application allows and blocks'
Assert-That ($outgoing -notmatch 'needUserRules = false' -and $outgoing -match 'Allow outbound') 'Allow Outgoing retains application rules while permitting general outbound traffic'
Assert-That ($newAssemble.ToString() -match 'Blocklists.EnableBlocklists && ActiveConfig.Service.Blocklists.EnablePortBlocklist') 'master blocklist switch alone does not enable the port list'
$exceptionForm = Get-Content -LiteralPath (Join-Path $bundle 'TinyWall\ApplicationExceptionForm.cs') -Raw
$selectWildcard = Get-Method $exceptionForm SelectWildcard
$createWildcard = Get-Method $exceptionForm CreateWildcardException
Assert-That ($selectWildcard.ToString() -match 'CreateWildcardException\(TmpExceptionSettings\[0\], picker.Pattern\)' -and $selectWildcard.ToString() -notmatch 'DeepClone') 'wildcard dialog uses the tested replacement factory instead of cloning a placeholder'
Assert-That ($createWildcard.ToString() -match 'new FirewallExceptionV3\(new ExecutableSubject\(pattern\), previous.Policy\)' -and $createWildcard.ToString() -match 'return Utils.DeepClone\(replacement\)') 'wildcard subject is valid before deep cloning'
$updateUI = Get-Method $exceptionForm UpdateUI
$accept = Get-Method $exceptionForm btnOK_Click
Assert-That ($updateUI.ToString() -match 'chkInheritToChildren.Enabled = true' -and $updateUI.ToString() -notmatch 'chkInheritToChildren.Checked = false') 'wildcard child-inheritance checkbox remains available'
Assert-That ($accept.ToString() -match 'if \(chkInheritToChildren.Checked\)' -and $accept.ToString() -match 'outside the selected folder') 'wildcard inheritance warns about outside-folder children before accepting'
$manager = Get-Content -LiteralPath (Join-Path $bundle 'TinyWall\WildcardRuleManager.cs') -Raw
Assert-That ($manager -match 'ChildProcessesInherit = rule.ChildProcessesInherit') 'wildcard expansion respects explicit child-inheritance settings'
Assert-That ($newAssemble.ToString().IndexOf('WildcardRules.Expand') -lt $newAssemble.ToString().IndexOf('if (ex.ChildProcessesInherit)')) 'expanded executable parents enter the existing inheritance pipeline'
$picker = Get-Content -LiteralPath (Join-Path $bundle 'TinyWall\WildcardPathForm.cs') -Raw
Assert-That ($picker -match 'ModernFolderPicker.SelectFolder' -and $picker -notmatch 'FolderBrowserDialog') 'folder selection uses the Windows common dialog instead of a tree browser'
Assert-That ($picker -match 'Checked = string.IsNullOrEmpty\(initialPattern\) \|\|') 'new folder wildcards default to including subfolders'

# Compile the actual patched normalization method against a deterministic mapper.
# This tests pipeline behavior, not Windows WFP integration.
$harness = @"
using System;
using System.Collections.Generic;
namespace TinyWallPipelineTests {
  public enum PathFormat { NativeNt }
  public class RuleDef { public string? Application; }
  public class PathMapper {
    public static PathMapper Instance = new PathMapper();
    public string ConvertPathIgnoreErrors(string path, PathFormat format) {
      if (path.StartsWith(@"C:\", StringComparison.OrdinalIgnoreCase)) return @"\Device\TestVolume" + path.Substring(2);
      return path;
    }
  }
  public class Pipeline {
    $($normalizer.ToFullString())
    public static string? Apply(string? path) {
      var rule = new RuleDef { Application = path };
      NormalizeApplicationPaths(new[] { rule });
      return rule.Application;
    }
  }
}
"@
Add-Type -TypeDefinition $harness -CompilerOptions '/langversion:9.0','/nullable:enable'
Assert-That ([TinyWallPipelineTests.Pipeline]::Apply('C:\Apps\codex.exe') -eq '\Device\TestVolume\Apps\codex.exe') 'new child identity converted by actual normalization method'
Assert-That ([TinyWallPipelineTests.Pipeline]::Apply('\Device\TestVolume\Apps\codex.exe') -eq '\Device\TestVolume\Apps\codex.exe') 'already normalized identity unchanged'
$nullResult = [TinyWallPipelineTests.Pipeline].GetMethod('Apply').Invoke($null, [object[]]@($null))
Assert-That ($null -eq $nullResult) 'global or package rule remains identity-free'
Assert-That ([TinyWallPipelineTests.Pipeline]::Apply('System') -eq 'System') 'System pseudo-application preserved'

foreach ($name in @('ApplicationExceptionForm.cs', 'ExecutablePathPattern.cs', 'SettingsForm.cs', 'TinyWallService.cs', 'WildcardPathForm.cs', 'WildcardRuleManager.cs')) {
    $path = Join-Path (Join-Path $bundle 'TinyWall') $name
    $tree = [Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText((Get-Content -LiteralPath $path -Raw))
    $errors = @($tree.GetDiagnostics() | Where-Object Severity -eq Error)
    Assert-That ($errors.Count -eq 0) "C# syntax: $name"
}
Write-Output "Source regression tests passed: $script:passed"
