# @allow id stage destination expected_sha256 expected_bytes force
$ErrorActionPreference = 'Stop'
if (-not [IO.File]::Exists($stage)) {
  [Console]::Error.WriteLine('STAGE_MISSING')
  exit 2
}
$stream = [IO.File]::OpenRead($stage)
try {
  $size = $stream.Length
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $hashBytes = $sha.ComputeHash($stream)
  $stream.Close()
  $hex = ([BitConverter]::ToString($hashBytes) -replace '-', '').ToLower()
} finally {
  try { $stream.Close() } catch {}
}
if ($hex -ne $expected_sha256 -or $size -ne [long]$expected_bytes) {
  [Console]::Error.WriteLine('STAGE_HASH_MISMATCH')
  exit 3
}
Add-Type -Namespace W -Name K -MemberDefinition '[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool MoveFileExW(string s, string d, uint f);' -ErrorAction Stop
$flags = 0
if ($force -eq 'true') { $flags = 1 }
$ok = [W.K]::MoveFileExW($stage, $destination, $flags)
if (-not $ok) {
  $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
  [Console]::Error.WriteLine(('COMMIT_FAILED le=' + $err))
  exit 4
}
[Console]::Out.WriteLine(('OK: committed:' + $id))
exit 0
