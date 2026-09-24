# @allow stage
try {
  if ([IO.File]::Exists($stage)) { [IO.File]::Delete($stage) }
  [Console]::Out.WriteLine('OK: cleaned')
  exit 0
} catch {
  [Console]::Error.WriteLine('CLEANUP_FAILED')
  exit 1
}
