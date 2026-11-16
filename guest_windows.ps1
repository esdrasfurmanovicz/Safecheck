# Roda DENTRO do Windows Sandbox. Baixa a URL e analisa o arquivo.
# Entrada: C:\in\url.txt (somente leitura). Saída: C:\out\report.json
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$in = 'C:\in'; $out = 'C:\out'
$dest = 'C:\Users\WDAGUtilityAccount\Downloads\target.bin'
$max = 3GB
$checks = New-Object System.Collections.ArrayList
$facts = [ordered]@{}
function Add-Check($id, $name, $status, $detail) {
    [void]$checks.Add([ordered]@{ id = $id; name = $name; status = $status; detail = $detail })
    # publica o progresso parcial para a interface
    try {
        @{ checks = $checks.ToArray() } | ConvertTo-Json -Depth 5 | Set-Content "$out\progress.tmp" -Encoding UTF8
        Move-Item "$out\progress.tmp" "$out\progress.json" -Force
    } catch { }
}

Add-Type -TypeDefinition @'
using System; using System.IO; using System.Collections.Generic;
public static class Chk {
  static uint U32(byte[] b, long o) { return (uint)(b[o]<<24 | b[o+1]<<16 | b[o+2]<<8 | b[o+3]); }
  static ulong U64(byte[] b, long o) { return ((ulong)U32(b,o) << 32) | U32(b,o+4); }
  // Retorna "" + tipos separados por vírgula, ou "ERR:..." / "TYPES:..."
  public static string Boxes(string path, out long moovPos, out long moovSize) {
    moovPos = -1; moovSize = 0;
    var types = new List<string>();
    using (var f = File.OpenRead(path)) {
      long size = f.Length, pos = 0; var h = new byte[16];
      while (pos < size) {
        f.Seek(pos, SeekOrigin.Begin);
        if (f.Read(h, 0, 8) < 8) return "ERR:cabeçalho truncado|" + string.Join(",", types);
        long sz = U32(h, 0); string t = System.Text.Encoding.GetEncoding(28591).GetString(h, 4, 4);
        if (sz == 1) { f.Read(h, 8, 8); sz = (long)U64(h, 8); } else if (sz == 0) sz = size - pos;
        if (sz < 8 || pos + sz > size) return "ERR:caixa '" + t + "' com tamanho inválido|" + string.Join(",", types);
        if (t == "moov") { moovPos = pos; moovSize = sz; }
        types.Add(t); pos += sz;
      }
    }
    return "OK:" + string.Join(",", types);
  }
  // Retorna "dur;w;h"
  public static string Meta(string path, long pos, long sz) {
    var b = new byte[sz];
    using (var f = File.OpenRead(path)) { f.Seek(pos, SeekOrigin.Begin); f.Read(b, 0, (int)sz); }
    double dur = 0; uint w = 0, hgt = 0;
    long p = 8;
    while (p + 8 <= sz) {
      long s = U32(b, p); string t = System.Text.Encoding.GetEncoding(28591).GetString(b, (int)p + 4, 4);
      if (s < 8 || p + s > sz) break;
      if (t == "mvhd") {
        long o = p + 8; uint ts; double d;
        if (b[o] == 1) { ts = U32(b, o + 20); d = U64(b, o + 24); } else { ts = U32(b, o + 12); d = U32(b, o + 16); }
        dur = ts > 0 ? d / ts : 0;
      } else if (t == "trak") {
        long q = p + 8, end = p + s;
        while (q + 8 <= end) {
          long s2 = U32(b, q); string t2 = System.Text.Encoding.GetEncoding(28591).GetString(b, (int)q + 4, 4);
          if (s2 < 8 || q + s2 > end) break;
          if (t2 == "tkhd") {
            long o = q + 8 + (b[q + 8] == 1 ? 88 : 76);
            uint tw = U32(b, o) >> 16, th = U32(b, o + 4) >> 16;
            if (tw > w) w = tw; if (th > hgt) hgt = th;
          }
          q += s2;
        }
      }
      p += s;
    }
    return dur.ToString(System.Globalization.CultureInfo.InvariantCulture) + ";" + w + ";" + hgt;
  }
  public static bool Find(string path, byte[] pat) {
    var buf = new byte[4 * 1024 * 1024 + pat.Length]; int carry = 0;
    using (var f = File.OpenRead(path)) {
      int n;
      while ((n = f.Read(buf, carry, 4 * 1024 * 1024)) > 0) {
        int total = carry + n;
        for (int i = 0; i + pat.Length <= total; i++) {
          if (buf[i] != pat[0]) continue;
          int j = 1; while (j < pat.Length && buf[i + j] == pat[j]) j++;
          if (j == pat.Length) return true;
        }
        carry = Math.Min(pat.Length - 1, total);
        Buffer.BlockCopy(buf, total - carry, buf, 0, carry);
      }
    }
    return false;
  }
}
'@

function Analyze($path, $size) {
    $head = New-Object byte[] 512
    $fs = [IO.File]::OpenRead($path); $nread = $fs.Read($head, 0, 512); $fs.Close()
    $ascii = [Text.Encoding]::GetEncoding(28591).GetString($head, 0, $nread)
    $bad = $null
    if ($ascii.StartsWith('MZ')) { $bad = 'executável Windows (PE)' }
    elseif ($ascii.StartsWith("PK$([char]3)$([char]4)")) { $bad = 'ZIP' }
    elseif ($ascii.StartsWith('Rar!')) { $bad = 'RAR' }
    elseif ($ascii.StartsWith('7z')) { $bad = '7-Zip' }
    elseif ($ascii.StartsWith('#!')) { $bad = 'script' }
    elseif ($ascii.TrimStart().ToLower() -match '^(<!doctype|<html|<\?xml|\{)') { $bad = 'página/texto (provável página de erro ou captcha, não o vídeo)' }
    if ($bad) { Add-Check 'header' 'Conteúdo é um vídeo (assinatura)' 'FAIL' "arquivo é $bad"; return }
    if ($ascii.Substring(4, 4) -ne 'ftyp') { Add-Check 'header' 'Conteúdo é um vídeo (assinatura)' 'FAIL' "sem assinatura 'ftyp' de MP4"; return }
    Add-Check 'header' 'Conteúdo é um vídeo (assinatura)' 'PASS' "assinatura 'ftyp' de MP4 presente"

    $mp = [long]0; $ms = [long]0
    $r = [Chk]::Boxes($path, [ref]$mp, [ref]$ms)
    if ($r.StartsWith('OK:')) {
        $names = $r.Substring(3).Split(',')
        if ($names | Where-Object { $_ -notmatch '^[\x20-\x7e]{4}$' -or $_ -ne $_.Trim() }) {
            Add-Check 'structure' 'Estrutura MP4 consistente' 'WARN' 'caixa com tipo inválido no fim (dados extras anexados?)'
        } elseif ($names -contains 'moov' -and $names -contains 'mdat') {
            Add-Check 'structure' 'Estrutura MP4 consistente' 'PASS' ("caixas do topo cobrem o arquivo inteiro: " + $r.Substring(3))
        } else { Add-Check 'structure' 'Estrutura MP4 consistente' 'WARN' "faltam caixas moov/mdat: $($r.Substring(3))" }
    } else { Add-Check 'structure' 'Estrutura MP4 consistente' 'WARN' ($r.Substring(4) + ' (dados extras/corrompidos?)') }

    $metaOk = $false
    if ($mp -ge 0 -and $ms -le 64MB) {
        try {
            $m = [Chk]::Meta($path, $mp, $ms).Split(';')
            $dur = [double]$m[0]; $w = [int]$m[1]; $h = [int]$m[2]
            if ($dur -gt 0) {
                $mbps = [math]::Round($size * 8 / $dur / 1e6, 2)
                $facts['duration_s'] = [int]$dur; $facts['width'] = $w; $facts['height'] = $h; $facts['mbps'] = $mbps
                $ts = [TimeSpan]::FromSeconds($dur)
                $weak = ($h -gt 0 -and $h -lt 480) -or ($h -ge 720 -and $mbps -lt 1.0)
                $st = if ($weak) { 'WARN' } else { 'INFO' }
                $extra = if ($weak) { ' (resolução/bitrate baixos)' } else { '' }
                $shown = if ($ts.TotalHours -ge 1) { "{0}h{1:00}m" -f [int][math]::Floor($ts.TotalHours), $ts.Minutes } elseif ($ts.Minutes -ge 1) { "{0}m{1:00}s" -f $ts.Minutes, $ts.Seconds } else { "{0}s" -f $ts.Seconds }
                Add-Check 'quality' 'Metadados de qualidade' $st ("{0}, {1}x{2}, ~{3} Mbps{4}" -f $shown, $w, $h, $mbps, $extra)
                $metaOk = $true
            }
        } catch { }
    }
    if (-not $metaOk) { Add-Check 'quality' 'Metadados de qualidade' 'WARN' 'não foi possível ler duração/resolução' }

    $pat = [Text.Encoding]::GetEncoding(28591).GetBytes('This program cannot be run in DOS mode')
    $rar = [Text.Encoding]::GetEncoding(28591).GetBytes("Rar!$([char]0x1a)$([char]7)")
    if ([Chk]::Find($path, $pat) -or [Chk]::Find($path, $rar)) {
        Add-Check 'embedded' 'Sem executável/arquivo embutido' 'FAIL' 'stub de executável ou arquivo compactado dentro do arquivo'
    } else { Add-Check 'embedded' 'Sem executável/arquivo embutido' 'PASS' 'nenhum stub de executável ou arquivo compactado' }
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $local = Test-Path "$in\local.txt"   # modo arquivo local: nada é baixado
    $sw = [Diagnostics.Stopwatch]::StartNew()
    if ($local) {
        $dest = 'C:\data\target.bin'
        $facts['local_name'] = (Get-Content "$in\local.txt" -Raw -Encoding UTF8).Trim()
        $total = (Get-Item $dest).Length
        $hash = (Get-FileHash $dest -Algorithm SHA256).Hash.ToLower()
    } else {
    $url = (Get-Content "$in\url.txt" -Raw).Trim()
    $req = [Net.HttpWebRequest]::Create($url)
    $req.UserAgent = 'Mozilla/5.0'; $req.Timeout = 30000; $req.MaximumAutomaticRedirections = 5
    $resp = $req.GetResponse()
    $facts['final_url_host'] = $resp.ResponseUri.Host
    $facts['content_type'] = $resp.ContentType
    $stream = $resp.GetResponseStream(); $fout = [IO.File]::Create($dest)
    $buf = New-Object byte[] (1MB); $total = [long]0
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        while (($n = $stream.Read($buf, 0, $buf.Length)) -gt 0) {
            $total += $n
            if ($total -gt $max) { throw "limite de 3 GB excedido" }
            $fout.Write($buf, 0, $n); [void]$sha.TransformBlock($buf, 0, $n, $null, 0)
        }
        [void]$sha.TransformFinalBlock($buf, 0, 0)
    } finally { $fout.Close(); $stream.Close(); $resp.Close() }
    $hash = ([BitConverter]::ToString($sha.Hash) -replace '-', '').ToLower()
    }
    $facts['size'] = $total; $facts['sha256'] = $hash; $facts['download_s'] = [math]::Round($sw.Elapsed.TotalSeconds, 1)
    $label = if ($local) { 'Arquivo recebido (somente leitura)' } else { 'Download dentro do sandbox' }
    Add-Check 'download' $label 'PASS' ("{0} bytes, sha256 {1}…" -f $total, $hash.Substring(0, 16))
    if ($total -lt 5MB) { Add-Check 'size' 'Tamanho plausível para um filme' 'WARN' ("só {0:N1} MB" -f ($total / 1e6)) }
    else { Add-Check 'size' 'Tamanho plausível para um filme' 'PASS' ("{0:N0} MB" -f ($total / 1e6)) }

    Analyze $dest $total

    # Antivírus: Microsoft Defender dentro do sandbox
    try {
        Start-MpScan -ScanType CustomScan -ScanPath $dest
        $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
        if ($threats.Count -gt 0 -or -not (Test-Path $dest)) {
            Add-Check 'av' 'Microsoft Defender (no sandbox)' 'FAIL' 'ameaça detectada ou arquivo removido pelo Defender'
        } else { Add-Check 'av' 'Microsoft Defender (no sandbox)' 'PASS' 'nenhuma ameaça detectada (assinaturas do sandbox, podem estar defasadas)' }
    } catch { Add-Check 'av' 'Microsoft Defender (no sandbox)' 'SKIP' "não foi possível executar: $($_.Exception.Message)" }
}
catch {
    $threats = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
    if ($threats.Count -gt 0) { Add-Check 'download' 'Download dentro do sandbox' 'FAIL' 'Defender bloqueou/removeu o arquivo durante o download' }
    else { Add-Check 'download' 'Download dentro do sandbox' 'FAIL' $_.Exception.Message }
}
finally {
    $report = [ordered]@{ environment = 'Windows Sandbox'; checks = $checks.ToArray(); facts = $facts }
    $report | ConvertTo-Json -Depth 6 | Set-Content "$out\report.tmp" -Encoding UTF8
    Move-Item "$out\report.tmp" "$out\report.json" -Force
    shutdown.exe /s /t 5
}
