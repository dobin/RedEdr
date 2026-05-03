$password = "password"
$pfxPath = ".\rededr_ppl.pfx"
$securePassword = ConvertTo-SecureString -String $password -Force -AsPlainText
Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\CurrentUser\My" -Exportable -Password $securePassword