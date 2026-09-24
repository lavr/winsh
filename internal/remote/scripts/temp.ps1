# @allow
try {
  [Console]::Out.WriteLine([IO.Path]::GetFullPath($env:TEMP))
  exit 0
} catch {
  [Console]::Error.WriteLine('TEMP_FAILED')
  exit 1
}
