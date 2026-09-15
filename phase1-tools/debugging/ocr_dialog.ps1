param(
    [int]$X = 740,
    [int]$Y = 447,
    [int]$W = 300,
    [int]$H = 111,
    [string]$Png = "C:\Users\fish\ZCodeProject\dialog.png"
)

Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap($W, $H)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($X, $Y, 0, 0, [System.Drawing.Size]::new($W, $H))
$bmp.Save($Png, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose()
$bmp.Dispose()
Write-Host ("saved " + $Png)

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
[Windows.Globalization.Language, Windows.Globalization, ContentType = WindowsRuntime] | Out-Null

$file = Await ([Windows.Storage.StorageFile]::GetFileFromPathAsync($Png)) ([Windows.Storage.StorageFile])
$stream = Await ($file.OpenAsync([Windows.Storage.FileAccessMode]::Read)) ([Windows.Storage.Streams.IRandomAccessStream])
$decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
$softBmp = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])

$engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
if ($null -eq $engine) {
    $lang = New-Object Windows.Globalization.Language("zh-Hans-CN")
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($lang)
}
if ($null -eq $engine) {
    Write-Host "OCR engine unavailable. Available languages:"
    [Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages | ForEach-Object { Write-Host ("  " + $_.LanguageTag) }
    exit 1
}

$result = Await ($engine.RecognizeAsync($softBmp)) ([Windows.Media.Ocr.OcrResult])
Write-Host "=== OCR RESULT ==="
Write-Host $result.Text
