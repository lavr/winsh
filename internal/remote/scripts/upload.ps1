# @allow id stage
$ErrorActionPreference = 'Stop'
try {
  $parent = [IO.Path]::GetDirectoryName($stage)
  if (-not [IO.Directory]::Exists($parent)) { throw 'PARENT_MISSING' }
  $root = [IO.Path]::GetPathRoot($stage)
  if (([IO.DriveInfo]::new($root)).DriveFormat -ne 'NTFS') { throw 'UNSUPPORTED_FILESYSTEM' }
  $part = $parent
  while ($part) {
    if (([IO.File]::GetAttributes($part) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE_POINT' }
    $next = [IO.Path]::GetDirectoryName($part)
    if ($next -eq $part) { break }
    $part = $next
  }
  $stageHandle = [IO.File]::Open($stage, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  $bytes = [long]0
  while ($null -ne ($line = [Console]::In.ReadLine())) {
    if ($line.Length -eq 0) { continue }
    $chunk = [Convert]::FromBase64String($line)
    $stageHandle.Write($chunk, 0, $chunk.Length)
    $bytes += $chunk.Length
  }
  $stageHandle.Flush()
  $stageHandle.Close()
  $readHandle = [IO.File]::OpenRead($stage)
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha.ComputeHash($readHandle)
    $hex = ([BitConverter]::ToString($hashBytes) -replace '-', '').ToLower()
  } finally {
    if ($readHandle) { $readHandle.Close() }
  }
  [Console]::Out.WriteLine(('{"version":1,"id":"' + $id + '","bytes":' + $bytes + ',"sha256":"' + $hex + '"}'))
  exit 0
} catch {
  [Console]::Error.WriteLine('STAGE_FAILED')
  exit 1
} finally {
  if ($stageHandle) { $stageHandle.Close() }
}
