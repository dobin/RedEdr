$password = "password"

# This is very, very graciouslly taken from Matt G!
# https://gist.github.com/mattifestation/660d7e17e43e8f32c38d820115274d2e
filter Get-TBSHash {
    [OutputType([String])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    Add-Type -TypeDefinition @'
    using System;
    using System.Runtime.InteropServices;
    namespace Crypto {
        public struct CRYPT_DATA_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }
        public struct CRYPT_OBJID_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
        }
        public struct CRYPT_ALGORITHM_IDENTIFIER
        {
            public string pszObjId;
            public CRYPT_OBJID_BLOB Parameters;
        }
        public struct CRYPT_BIT_BLOB
        {
            public uint cbData;
            public IntPtr pbData;
            public uint cUnusedBits;
        }
        public struct CERT_SIGNED_CONTENT_INFO
        {
            public CRYPT_DATA_BLOB ToBeSigned;
            public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
            public CRYPT_BIT_BLOB Signature;
        }
        public class NativeMethods {
            [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptDecodeObject(uint dwCertEncodingType, IntPtr lpszStructType, [In] byte[] pbEncoded, uint cbEncoded, uint dwFlags, [Out] IntPtr pvStructInto, ref uint pcbStructInfo);
        }
    }
'@

    $HashOIDs = @{
        '1.2.840.113549.1.1.4' = 'MD5'
        '1.2.840.113549.1.1.5' = 'SHA1'
        '1.3.14.3.2.29' = 'SHA1'
        '1.2.840.113549.1.1.11' = 'SHA256'
        '1.2.840.113549.1.1.12' = 'SHA384'
        '1.2.840.113549.1.1.13' = 'SHA512'
    }

    $CertBytes = $Certificate.RawData

    $X509_PKCS7_ENCODING = 65537
    $X509_CERT = 1
    $CRYPT_DECODE_TO_BE_SIGNED_FLAG = 2
    $ErrorMoreData = 234

    $TBSData = [IntPtr]::Zero
    [UInt32] $TBSDataSize = 0

    $Success = [Crypto.NativeMethods]::CryptDecodeObject(
        $X509_PKCS7_ENCODING,
        [IntPtr] $X509_CERT,
        $CertBytes,
        $CertBytes.Length,
        $CRYPT_DECODE_TO_BE_SIGNED_FLAG,
        $TBSData,
        [ref] $TBSDataSize
    ); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if((-not $Success) -and ($LastError -ne $ErrorMoreData)) 
    {
        throw "[CryptDecodeObject] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    $TBSData = [Runtime.InteropServices.Marshal]::AllocHGlobal($TBSDataSize)

    $Success = [Crypto.NativeMethods]::CryptDecodeObject(
        $X509_PKCS7_ENCODING,
        [IntPtr] $X509_CERT,
        $CertBytes,
        $CertBytes.Length,
        $CRYPT_DECODE_TO_BE_SIGNED_FLAG,
        $TBSData,
        [ref] $TBSDataSize
    ); $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if((-not $Success)) 
    {
        throw "[CryptDecodeObject] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    $SignedContentInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TBSData, [Type][Crypto.CERT_SIGNED_CONTENT_INFO])

    $TBSBytes = New-Object Byte[]($SignedContentInfo.ToBeSigned.cbData)
    [Runtime.InteropServices.Marshal]::Copy($SignedContentInfo.ToBeSigned.pbData, $TBSBytes, 0, $TBSBytes.Length)

    [Runtime.InteropServices.Marshal]::FreeHGlobal($TBSData)

    $HashAlgorithmStr = $HashOIDs[$SignedContentInfo.SignatureAlgorithm.pszObjId]

    if (-not $HashAlgorithmStr) { throw 'Hash algorithm is not supported or it could not be retrieved.' }

    $HashAlgorithm = [Security.Cryptography.HashAlgorithm]::Create($HashAlgorithmStr)

    $TBSHashBytes = $HashAlgorithm.ComputeHash($TBSBytes)

    ($TBSHashBytes | % { $_.ToString('X2') }) -join ''
}

# Generate new Certificate
$certFolder = "Cert:\CurrentUser\My"
$cert = New-SelfSignedCertificate -certstorelocation $certFolder -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(5) -Subject "CN=ppl_runner" -TextExtension @("2.5.29.37={text}1.3.6.1.4.1.311.61.4.1,1.3.6.1.5.5.7.3.3")
$certLocation = "$certFolder\"+$cert.Thumbprint
# Use the awesome 'Get-TBSHash' from above
$hash = Get-TBSHash $cert

# Write Hash to update in resource
Write-Host "SHA256 Hash: $hash"

# Export from store using the password
$passwordSecure = ConvertTo-SecureString -String $password -Force -AsPlainText
$outputFilename = "rededr_ppl.pfx"
Export-PfxCertificate -cert $cert -FilePath $outputFilename -Password $passwordSecure

# Delete Certificate from store
Remove-Item $certLocation
$cert = $null

# Update Driver Resource with hash
Write-Output @"
#include <windows.h>
#include <ntverp.h>

#define VER_FILETYPE             VFT_DRV
#define VER_FILESUBTYPE          VFT2_DRV_SYSTEM
#define VER_FILEDESCRIPTION_STR  "ppl_runner Driver"
#define VER_INTERNALNAME_STR     "elam_driver.sys"

#include "common.ver"
MicrosoftElamCertificateInfo  MSElamCertInfoID
{
      1,
      L"$hash\0",
      0x800C,
      L"\0"
}
"@ | Set-Content -Path ".\elam_driver\elam_driver.rc"
Write-Host "Written Cert and key to $outputFilename"
