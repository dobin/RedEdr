# Change this:
$password = "password"

# Completely suppress all output
$ErrorActionPreference = 'SilentlyContinue'
$null = & signtool.exe sign /fd SHA256 /a /ph /f $args[0] /p $password $args[1] 2>&1
exit 0
