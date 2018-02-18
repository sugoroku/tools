# Plese input the location installed tools
$toolLoc = "C:\Users\user\Documents\tools\"

# Set target file
$target = "C:\Windows\notepad.exe"

# Exif
$exiftool = $toolLoc + "exiftool-10.79\exiftool.exe"
$out = & $exiftool $target
$exif = $out -split "`r`n"

# Hash (MD5, SHA1, SHA256) 
## MD5
$stream = New-Object IO.StreamReader $target
$md5 = [System.Security.Cryptography.MD5]::Create()
$tmp = $md5.ComputeHash($stream.BaseStream)
$hashMd5 = ""
$tmp | %{ $hashMd5 += $_.ToString("x2") }
## SHA1
$sha1 = [System.Security.Cryptography.SHA1]::Create()
$tmp = $sha1.ComputeHash($stream.BaseStream)
$hashSha1 = ""
$tmp | %{ $hashSha1 += $_.ToString("x2") }
##SHA256
$sha256 = [System.Security.Cryptography.SHA256]::Create()
$tmp = $sha256.ComputeHash($stream.BaseStream)
$tmp | %{ $hashSha256 += $_.ToString("x2") }
$stream.Close()
#$hashMd5 = Get-FileHash -Algorithm md5 $target
#$hashSha1 = Get-FileHash -Algorithm SHA1 $target
#$hashSha256 = Get-FileHash -Algorithm SHA256 $target

# Fuzzy Hash 
$ssdeep = $toolLoc + "ssdeep-2.14.1\ssdeep.exe"
#Write-Output $ssdeep
$out = & $ssdeep $target
$buffer = $out -split ","
$fuzzyHash = $buffer[4]

# File Type
## Execute trid.exe
$trid = $toolLoc + "\trid_w32\trid.exe"
$out = & $trid $target
## Extract "File Type"
$i = 0
$j = 0
while($i -le $out.Length){
    if($i -ge 6){
        $fileType += $out[$i] + "`r`n"
        $j++
    }
    $i++
}

#Write-Output $fileType

# Create output image
$result = "+++++ Surface Analysis Information +++++"
## Exif
$result += "`r`n" + "File Information: `r`n  " + $exif[1] + "`r`n  " + $exif[3] + "`r`n  " + $exif[4] + "`r`n  " + $exif[5] + "`r`n  " + $exif[6]
##Hash
$result += "`r`n`r`n" + "Hash: "
$result += "`r`n  MD5:       " + $hashMd5
$result += "`r`n  SHA1:      " + $hashSha1
$result += "`r`n  SHA256:    " + $hashSha256
## Fuzzy Hash
$result += "`r`n`  " + "FuzzyHash: " + $fuzzyHash
## File Type
$result += "`r`n`r`n" + "TrID: "
$result += "`r`n" + $fileType
## VirusTotal
$result += "VirusTotal: " + "`r`n ***Please Write SearchResult***`r`n"

Write-Output $result

