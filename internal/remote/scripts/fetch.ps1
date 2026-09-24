# @allow metadata
try {
  $f = [IO.File]::Open($metadata, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try {
    if ($f.Length -gt 4096) { throw 'CONTROL_TOO_LARGE' }
    $r = [IO.StreamReader]::new($f, [Text.Encoding]::UTF8, $false)
    [Console]::Out.Write($r.ReadToEnd())
  } finally { $f.Close() }
  exit 0
} catch {
  [Console]::Error.WriteLine('CONTROL_FETCH_FAILED')
  exit 1
}
