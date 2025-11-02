# Load config
$config = Get-Content -Raw -Path ".\azure_config.json" | ConvertFrom-Json

# cleanup
$path = "C:\rededr\data"
$source = "C:\rededr\*"
$destination = "C:\rededr\rededr.zip"

Write-Output "cleanup..."
if (Test-Path $path) {
    Get-ChildItem -Path $path -File | Remove-Item -Force -ErrorAction SilentlyContinue
}
if (Test-Path $destination) {
  Get-ChildItem $destination | Remove-Item -Force -ErrorAction SilentlyContinue
}

# make a zip
Write-Output "zip..."
Compress-Archive -Path $source -DestinationPath $destination -Force

# Upload zip as blob
Write-Output "upload..."
az storage blob upload `
  --account-name $($config.StorageAccount) `
  --container-name $($config.ContainerName) `
  --name $($config.BlobName) `
  --file $destination `
  --sas-token "`"$($config.SasToken)`"" `
  --overwrite

# delete zip
Write-Output "cleanup..."
Get-ChildItem "c:\rededr\rededr.zip" | Remove-Item -Force
