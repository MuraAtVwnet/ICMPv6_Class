##############################################
# ICMPv6 Class
##############################################
class ICMPv6Client {
	#-------------------------------------------------------------------------
	# 定数($CC_ : Class Constant)
	#-------------------------------------------------------------------------


	#-------------------------------------------------------------------------
	# 設定($CCONF_ : Class Config)
	#-------------------------------------------------------------------------
	# バッファサイズ
	[int] $CCONF_BufferSize = 1024

	# タイムアウト
	[int] $CCONF_TimeOut = 30

	#-------------------------------------------------------------------------
	# 変数
	#-------------------------------------------------------------------------
	# ソケット
	[System.Net.Sockets.Socket] $Socket

	# ICMPv6 データ
	[Byte[]] $ICMPv6Data

	# 送信元 IPv6 アドレス
	[System.Net.IPAddress] $SrcIPv6Address

	# 宛先 IPv6 アドレス
	[System.Net.IPAddress] $DstIPv6Address

	# 受信バッファ
	[byte[]]$Buffer

	# TTL
	[Int32]$TTL

	#------------------------------------------------
	# ストリーム
	[System.IO.MemoryStream] $Stream

	# ライター
	[System.IO.StreamWriter] $CV_Writer

	# 受信バッファ
	[Byte[]] $CV_ReceiveBuffer

	# 送信バッファ
	[Byte[]] $CV_SendBuffer

	# 受信バッファ Index
	[int] $CV_ReceiveBufferIndex

	# 送信バッファ Index
	[int] $CV_SendBufferIndex

	#-------------------------------------------------------------------------
	# 内部 メソッド (protected 扱い)
	#-------------------------------------------------------------------------
	##########################################################################
	# socket作成
	##########################################################################
	[void]CreateSocket(){
		$AddressFamily = [System.Net.Sockets.AddressFamily]::InterNetworkV6
		$SocketType = [System.Net.Sockets.SocketType]::Raw
		$ProtocolType = [System.Net.Sockets.ProtocolType]::IcmpV6
		$this.Socket = New-Object System.Net.Sockets.Socket( $AddressFamily, $SocketType, $ProtocolType )

		# TTL 初期値セット
		$this.TTL = 1
	}

	##########################################################################
	# ホストバイトオーダー/ネットワークバイトオーダー(ビッグエンディアン)変換
	##########################################################################
	[byte[]]HostNetwork([byte[]]$Data){

		$Max = $Data.Length
		[byte[]]$ReturnData = New-Object byte[] $Max

		# CPU アーキテクチャが IsLittleEndian か
		if( [System.BitConverter]::IsLittleEndian ){
			# バイト配列逆転
			for( $i = 0; $i -lt $Max; $i++ ){
				$ReturnData[$Max - $i -1] = $Data[$i]
			}
		}
		else{
			# 変換無し
			for( $i = 0; $i -lt $Max; $i++ ){
				$ReturnData[$i] = $Data[$i]
			}
		}

		Return $ReturnData
	}

	##########################################################################
	# ICMPv6 チェックサム用データ作成
	##########################################################################
	[byte[]]MakeICMPv6ChecksumData(){

		[byte[]]$Body = @()

		### 疑似ヘッダ
		# 送信元 IPv6 アドレス(128)
		$Body += $this.SrcIPv6Address.GetAddressBytes()

		# 宛先 IPv6 アドレス(128)
		$Body += $this.DstIPv6Address.GetAddressBytes()

		# 上位レイヤー プロトコル パケット長(32)
		[System.UInt32]$Length = $this.ICMPv6Data.Length
		$Body += $this.GetNetworkBytes($Length)
		# zero(24)
		$Zero = New-Object byte[] 3
		$Zero = @(0x00, 0x00, 0x00)
		$Body += $Zero

		# プロトコル(8)
		[byte]$Protocol = 58	# ICMPv6
		$Body += $Protocol

		### 上位レイヤー データ
		$Body += $this.ICMPv6Data

		Return $Body
	}

	##########################################################################
	# チェックサム計算
	##########################################################################
	[byte[]] ComputeChecksum([byte[]]$Body){

		# 2バイトずつ取り出し、Sum を求める
		[System.UInt32]$Sum = 0
		$Max = $Body.Length
		$Bytes = New-Object byte[] 2
		for( $i = 0; $i -lt $Max; $i += 2 ){
			$Bytes = @($Body[$i], $Body[$i +1])
			[System.UInt16]$Data = $this.GetHostUint16($Bytes, 0)
			$Sum += $Data
		}

		# オーバーフロー部分取り出し($Sum >> 16)
		[System.UInt16]$OverFlow = $Sum -shr 16

		# Sum の Uint16 部分($Sum << 16 >> 16)
		[System.UInt32]$Sum32 = ($Sum -shl 16) -shr 16

		# オーバーフロー加算
		$Sum32 += $OverFlow

		# Uint16 部分のみ取り出す
		[System.UInt16]$Sum16 = ($Sum32 -shl 16) -shr 16

		# 1の補数(ビット反転)する
		[System.UInt16]$Checksum = $Sum16 -bxor 0xffff

		# ネットワークオーダーにする
		$ByteChecksum = $this.GetNetworkBytes($Checksum)
		Return $ByteChecksum
	}

	##########################################################################
	# チェックサム セット
	##########################################################################
	[void] SetComputeChecksum( [byte[]]$ByteChecksum ){

		$this.ICMPv6Data[2] = $ByteChecksum[0]
		$this.ICMPv6Data[3] = $ByteChecksum[1]
	}

	##########################################################################
	# ICMPv6 データ作成
	##########################################################################
	[void] CreateICMPv6([byte]$Type, [byte]$Code, [byte[]]$MessageBody){
		## IPv6(RFC 8200)
		# Version(4) (0110)
		# トラフィッククラス(8)
		# フローラベル(20) : 0x60 0x00 0x00 0x00
		# Payload Length(16)
		# Next ヘッダー(8) : 0x3a
		# Hop limit(8) : 0xff
		# 送信元 IPv6 アドレス(128)
		# 宛先 IPv6 アドレス(128)

		## ICMPv6 (RFC 4443)
		$this.ICMPv6Data = @()

		# Type(8)
		$this.ICMPv6Data += $Type

		# Code(8)
		$this.ICMPv6Data += $Code

		# チェックサム(16)
		$Checksum = New-Object byte[] 2
		$Checksum = @(0x00, 0x00)
		$this.ICMPv6Data += $Checksum

		# Message Body
		$this.ICMPv6Data += $MessageBody
	}

	##########################################################################
	# 送信元 IPv6 アドレス選定
	# 一時 IPv6 アドレスと IPv6 アドレスの見分け方法が現状不明 orz
	##########################################################################
	[ipaddress]SelectLongMatch([ipaddress[]]$LocalIPv6Address ){

		# 宛先 IPv6 アドレスの byte 列
		[byte[]]$ByteDstIPv6Address = $this.DstIPv6Address.GetAddressBytes()

		[ipaddress]$ReturnIPv6Address = $LocalIPv6Address[0]	# 初期値(Dummy)

		$AddressMax = $LocalIPv6Address.Count
		$OldMatchBits = 0

		# ローカル IPv6 アドレス loop
		for( $i = 0; $i -lt $AddressMax; $i++ ){
			[byte[]]$NowByteLocalIPv6Address = $LocalIPv6Address[$i].GetAddressBytes()
			$NowMatchBits = 0

			# バイト単位の比較 loop
:EndMatch	for( $j = 0; $j -lt 8; $j++ ){

				# ビット比較 loop
				for( $k = 7; $k -gt 0; $k--){
					if( (($ByteDstIPv6Address[$j] -shr $k) -band 1) -eq (($NowByteLocalIPv6Address[$j] -shr $k) -band 1) ){
						$NowMatchBits++
					}
					else{
						break EndMatch
					}
				}
			}

			# よりマッチした
			if( $OldMatchBits -lt $NowMatchBits ){
				$ReturnIPv6Address = $LocalIPv6Address[$i]
				$OldMatchBits = $NowMatchBits
			}
		}

		Return $ReturnIPv6Address
	}


	#-------------------------------------------------------------------------
	# 公開 メソッド (public 扱い)
	#-------------------------------------------------------------------------

	##########################################################################
	# コンストラクタ
	##########################################################################
	ICMPv6Client(){
		$this.CreateSocket()
	}

	##########################################################################
	# コンストラクタ
	##########################################################################
	ICMPv6Client([string]$DstIPv6Address){
		$this.CreateSocket()
		$this.SetIPv6Address( $DstIPv6Address )
	}

	##########################################################################
	# コンストラクタ
	##########################################################################
	ICMPv6Client([string]$DstIPv6Address, [string]$SrcIPv6Address){
		$this.CreateSocket()
		$this.SetIPv6Address( $DstIPv6Address, $SrcIPv6Address )
	}

	##########################################################################
	# オブジェクト破棄
	##########################################################################
	Dispose(){
		$Shutdown = [System.Net.Sockets.SocketShutdown]::Both
		try {
			$this.Socket.Shutdown($Shutdown)
			$this.Socket.Close()
		}
		catch{
			# エラーは握りつぶす w
			try {
				$this.Socket.Close()
			}
			catch{}
		}
	}

	##########################################################################
	# TTL 設定
	##########################################################################
	[void]SetTTL([Int32]$TTL){
		$this.TTL = $TTL
	}

	##########################################################################
	# IPv6 アドレス指定(送信元自動選択)
	##########################################################################
	[void]SetIPv6Address( [string]$DstIPv6Address ){

		# 宛先 IPv6 アドレス(128)
		$this.DstIPv6Address = [System.Net.IPAddress]::Parse($DstIPv6Address)

		# Local IPv6 Address
		[ipaddress[]]$LocalIPAddress = [System.Net.Dns]::GetHostAddresses( [System.Net.Dns]::GetHostName())
		[ipaddress[]]$LocalIPv6Address = $LocalIPAddress | ? AddressFamily -eq "InterNetworkV6"

		if( $LocalIPv6Address.Count -eq 0 ){
			$ErrorActionPreference = "Stop"
			throw "IPv6 Address not include."
		}

		# 送信元 IPv6 アドレス(128)
		$this.SrcIPv6Address = $this.SelectLongMatch( $LocalIPv6Address )
	}

	##########################################################################
	# IPv6 アドレス指定(送信元指定)
	##########################################################################
	[void]SetIPv6Address( [string]$DstIPv6Address, [string]$SrcIPv6Address ){

		# 宛先 IPv6 アドレス(128)
		$this.DstIPv6Address = [System.Net.IPAddress]::Parse($DstIPv6Address)

		# 送信元 IPv6 アドレス(128)
		$this.SrcIPv6Address = [System.Net.IPAddress]::Parse($SrcIPv6Address)
	}

	##########################################################################
	# ネットワークオーダーのバイト配列にする
	##########################################################################
	[byte[]]GetNetworkBytes([System.ValueType]$Numeric){

		[byte[]]$ReturnBytes = @()

		$Type = $Numeric.GetType().Name
		if(($Type -eq "SByte") -or ($Type -eq "Byte")){
			[byte]$Byte = $Numeric
			$ReturnBytes += $Byte
		}
		else{
			try{
				[byte[]]$Bytes = [System.BitConverter]::GetBytes($Numeric)
				$ReturnBytes = $this.HostNetwork($Bytes)
			}
			catch{
				$ReturnBytes = $null
			}
		}

		Return $ReturnBytes
	}

	##########################################################################
	# ホストオーダーの数値にする(Uint16)
	##########################################################################
	[System.UInt16]GetHostUint16([byte[]]$Bytes, [System.Int32]$Index){

		$SizeOfValue = 2

		[System.UInt16]$ReturnValue = 0

		[byte[]]$WorkBytes = New-Object byte[] $SizeOfValue
		for($i = 0; $i -lt $SizeOfValue; $i++ ){
			$WorkBytes[$i] = $Bytes[$i + $Index]
		}

		$HostBytes = $this.HostNetwork($WorkBytes)
		$ReturnValue = [System.BitConverter]::ToUInt16($HostBytes , 0)

		Return $ReturnValue
	}

	##########################################################################
	# ホストオーダーの数値にする(Uint32)
	##########################################################################
	[System.UInt32]GetHostUint32([byte[]]$Bytes, [System.Int32]$Index){

		$SizeOfValue = 4

		[System.UInt32]$ReturnValue = 0

		[byte[]]$WorkBytes = New-Object byte[] $SizeOfValue
		for($i = 0; $i -lt $SizeOfValue; $i++ ){
			$WorkBytes[$i] = $Bytes[$i + $Index]
		}

		$HostBytes = $this.HostNetwork($WorkBytes)
		$ReturnValue = [System.BitConverter]::ToUInt32($HostBytes , 0)

		Return $ReturnValue
	}

	##########################################################################
	# 送信
	##########################################################################
	[void]Send( [byte]$Type, [byte]$Code, [byte[]]$Data ){
		# ICMPv6 データ作成
		$this.CreateICMPv6($Type, $Code, $Data)

		# チェックサム用データ作成
		[byte[]]$Body = $this.MakeICMPv6ChecksumData()

		# チェックサム計算
		[byte[]] $ByteChecksum = $this.ComputeChecksum($Body)

		# チェックサム セット
		$this.SetComputeChecksum($ByteChecksum)

		# 送信
		$IPEndPoint = New-Object System.Net.IPEndPoint( $this.DstIPv6Address, 0 )

		# TTL セット
		$this.Socket.SetSocketOption( [System.Net.Sockets.SocketOptionLevel]::IPv6,
										[System.Net.Sockets.SocketOptionName]::HopLimit,
										$this.TTL)

		# Debug(なぜ HopLimit がセットできない??)
		$Data = $this.Socket.GetSocketOption( [System.Net.Sockets.SocketOptionLevel]::IPv6,
										[System.Net.Sockets.SocketOptionName]::HopLimit)

		$this.Socket.SendTo($this.ICMPv6Data, $IPEndPoint)
	}

	##########################################################################
	# 受信
	##########################################################################
	[byte[]] Receive(){

		# 受信開始
		[System.IAsyncResult]$Result = $this.ReceiveStart()

		# 受信終了
		[byte[]]$ReturnBuffer = $this.ReceiveEnd($Result)

		Return $ReturnBuffer
	}

	##########################################################################
	# 受信開始
	##########################################################################
	[System.IAsyncResult]ReceiveStart(){
		$this.Buffer = New-Object byte[] $this.CCONF_BufferSize

		[System.IAsyncResult]$Result = $this.Socket.BeginReceive( $this.Buffer, 0, $this.CCONF_BufferSize,
																	[System.Net.Sockets.SocketFlags]::None, $null, $null )
		Return $Result
	}

	##########################################################################
	# 受信終了
	##########################################################################
	[byte[]]ReceiveEnd([System.IAsyncResult]$Result){

		$ReceiveSize = $this.Socket.EndReceive($Result)

		[byte[]]$ReturnBuffer = New-Object byte[] $ReceiveSize

		for($i = 0; $i -lt $ReceiveSize; $i++){
			$ReturnBuffer[$i] = $this.Buffer[$i]
		}

		Return $ReturnBuffer
	}

	##########################################################################
	# チェックサム確認
	##########################################################################
	[bool]TestChecksum([byte[]]$Body){

		# 2バイトずつ取り出し、Sum を求める
		[System.UInt32]$Sum = 0
		$Max = $Body.Length
		$Bytes = New-Object byte[] 2
		for( $i = 0; $i -lt $Max; $i += 2 ){
			$Bytes = @($Body[$i], $Body[$i +1])
			[System.UInt16]$Data = $this.GetHostUint16($Bytes, 0)
			$Sum += $Data
		}

		# オーバーフロー部分取り出し($Sum >> 16)
		[System.UInt16]$OverFlow = $Sum -shr 16

		# Sum の Uint16 部分($Sum << 16 >> 16)
		[System.UInt32]$Sum32 = ($Sum -shl 16) -shr 16

		# オーバーフロー加算
		$Sum32 += $OverFlow

		# Uint16 部分のみ取り出す
		[System.UInt16]$Sum16 = ($Sum32 -shl 16) -shr 16

		[bool]$ReturnStatus = $Sum16 -eq 0xffff

		Return $ReturnStatus
	}
}


<#

		$this.Socket.SetSocketOption( [System.Net.Sockets.SocketOptionLevel]::IPv6,
										[System.Net.Sockets.SocketOptionName]::AcceptConnection, 1)

		[byte[]]$OptionInValue = @( 0x00, 0x00, 0x00, 0x01 )
		[byte[]]$OptionOutValue = @( 0x00, 0x00, 0x00, 0x00 )
		$this.Socket.IOControl( [System.Net.Sockets.IOControlCode]::ReceiveAll, $OptionInValue, $OptionOutValue)
#>
