# Change this:
$password = "password"

signtool.exe sign /fd SHA256 /a /v /ph /f $args[0] /p $password $args[1]
