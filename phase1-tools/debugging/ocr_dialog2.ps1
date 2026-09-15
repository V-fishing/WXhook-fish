param(
    [long]$Hwnd = 0x41196,
    [double]$Scale = 3.0,
    [string]$Png = "C:\Users\fish\ZCodeProject\dialog_big.png"
)

Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WR {
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int Left, Top, Right, Bottom; }
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
}
"@

$r = New-Object WR+RECT
if (-not [WR]::GetWindowRect([IntPtr]$Hwnd, [ref]$r)) { Write-Host "GetWindowRect failed"; exit 1 }
$w = $r.Right - $r.Left
$h = $r.Bottom - $r.Top
Write-Host ("dialog rect: " + $r.Left + "," + $r.Top + " " + $w + "x" + $h)

# capture
$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($r.Left, $r.Top, 0, 0, [System.Drawing.Size]::new($w, $h))
$g.Dispose()

# upscale
$big = New-Object System.Drawing.Bitmap([int]($w * $Scale), [int]($h * $Scale))
$g2 = [System.Drawing.Graphics]::FromImage($big)
$g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g2.DrawImage($bmp, 0, 0, $big.Width, $big.Height)
$g2.Dispose()
$big.Save($Png, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
$big.Dispose()
Write-Host ("saved upscaled " + $Png)

# OCR
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
})[0]
function Await($WinRtTask, $ResultType) {
    $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
    $netTask = $asTask.Invoke($null, @($WinRtTask))
    $netTask.Wait(-1) | Out-Null
    $netTask.Result
}
[Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime] | Out-Null
[Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType = WindowsRuntime] | Out-Null
[Windows.Graphics.Imaging.BitmapDecoder, Windows.Graphics, ContentType = WindowsRuntime] | Out-Null

$file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($Png)) ([Windows.Storage.StorageFile])
$stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$softBmp = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])

$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if ($null -eq $engine) { Write-Host "no OCR engine"; exit 1 }
$result = Await ($engine.RecognizeAsync($softBmp)) ([Windows.Media.Ocr.OcrResult])
Write-Host "=== OCR RESULT ==="
Write-Host $result.Text
