##########################################################
# IPv6 ping 実装サンプル
##########################################################
# ICMPv6 Class Include
using module .\ICMPv6.psm1

########################################################
# 16進ダンプ
########################################################
function HexDump([byte[]]$ReceiveBuffer){

	$Max = $ReceiveBuffer.Length

	[array]$ReturnBuffer = @()
	$LineMax = 16
	$InsertSpace = 7

	$j = 0
	$Line = ""
	$Char = ""
	for($i = 0; $i -lt $Max; $i++){
		# 16 バイトで Line 出力
		if( $j -ge $LineMax ){
			$ReturnBuffer += $Line + " "+ $Char
			$Line = ""
			$Char = ""
			$j = 0
		}

		$Line += $ReceiveBuffer[$i].ToString("x2") + " "

		# 8バイトごとに1つ開ける
		if( $j -eq $InsertSpace ){
			$Line += " "
		}

		if( [char]::IsControl($ReceiveBuffer[$i]) -or $ReceiveBuffer[$i] -ge 0xa0){
			$Char += "･"
		}
		else{
			$Char += [char]$ReceiveBuffer[$i]
		}

		$j++
	}

	# 残り出力
	$Line += "   " * ($LineMax - $j)
	if( $j -le　$InsertSpace ){
		$Line += " "
	}
	$ReturnBuffer += $Line + " " + $Char

	Return $ReturnBuffer
}

########################################################
# main
########################################################
# fe80::1 を宛先に指定
$Ping = New-Object ICMPv6Client("fe80::1")


# ping 送信データ組み立て
[byte[]]$Data = @()

$Type = 128
$Code = 0

# ID
$Data += $Ping.GetNetworkBytes([Uint16]1)

# Seq
$Data += $Ping.GetNetworkBytes([Uint16]6)

# ping Data
$Data += [System.Text.Encoding]::UTF8.GetBytes( "abcdefghijklmnopqrstuvwabcdefghi" )

# 送信
$Ping.Send( $Type, $Code, $Data )

# 受信
$ReceiveData = $Ping.Receive()

# 受信データダンプ
HexDump $ReceiveData

$Ping.Dispose()

