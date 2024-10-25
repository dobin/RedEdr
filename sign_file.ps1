# Change this:
$password = "password"


# signtool.exe sign /fd SHA256 /a /v /ph /f $args[0] /p $password $args[1]
signtool.exe sign /fd SHA256 /a /ph /f $args[0] /p $password $args[1]
