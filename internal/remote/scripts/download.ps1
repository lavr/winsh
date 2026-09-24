# @allow id source metadata
$ErrorActionPreference = 'Stop'
try {
  $root = [IO.Path]::GetPathRoot($source)
  if (([IO.DriveInfo]::new($root)).DriveFormat -ne 'NTFS') { throw 'UNSUPPORTED_FILESYSTEM' }
  $part = $source
  while ($part) {
    if (([IO.File]::GetAttributes($part) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE_POINT' }
    $next = [IO.Path]::GetDirectoryName($part)
    if ($next -eq $part) { break }
    $part = $next
  }
  $f = [IO.File]::Open($source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    $sha = [Security.Cryptography.SHA256]::Create()
    $buffer = New-Object byte[] 24576
    $count = [long]0
    while (($n = $f.Read($buffer, 0, $buffer.Length)) -gt 0) {
      [void]$sha.TransformBlock($buffer, 0, $n, $buffer, 0)
      $count += $n
      [Console]::Out.Write(([Convert]::ToBase64String($buffer, 0, $n) + "`r`n"))
    }
    [void]$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
    $hex = ([BitConverter]::ToString($sha.Hash) -replace '-', '').ToLowerInvariant()
    $record = '{"version":1,"id":"' + $id + '","bytes":' + $count + ',"sha256":"' + $hex + '"}'
    $m = [IO.File]::Open($metadata, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
      $data = [Text.Encoding]::UTF8.GetBytes($record)
      $m.Write($data, 0, $data.Length)
      $m.Flush()
    } finally { $m.Close() }
  } finally { $f.Close() }
  exit 0
} catch {
  [Console]::Error.WriteLine('DOWNLOAD_FAILED')
  exit 1
}
