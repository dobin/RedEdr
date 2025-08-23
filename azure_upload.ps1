# Load config
$config = Get-Content -Raw -Path ".\azure_config.json" | ConvertFrom-Json

# cleanup
$path = "C:\rededr\data"
if (Test-Path $path) {
    Get-ChildItem -Path $path -File | Remove-Item -Force
}
Get-ChildItem "c:\rededr\rededr.zip" | Remove-Item -Force

# make a zip
$source = "C:\rededr\*"
$destination = "C:\rededr\rededr.zip"
Compress-Archive -Path $source -DestinationPath $destination -Force

# Upload zip as blob
az storage blob upload `
  --account-name $($config.StorageAccount) `
  --container-name $($config.ContainerName) `
  --name $($config.BlobName) `
  --file $($config.FilePath) `
  --sas-token "`"$($config.SasToken)`"" `
  --overwrite

# delete zip
Get-ChildItem "c:\rededr\rededr.zip" | Remove-Item -Force
