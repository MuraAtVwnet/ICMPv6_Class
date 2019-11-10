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
	# 変数($CV_ : Class Variable)
	#-------------------------------------------------------------------------
	# ソケット
	[System.Net.Sockets.Socket] $CV_Socket

	# ストリーム
	[System.Net.Sockets.NetworkStream] $CV_Stream

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

	#-------------------------------------------------------------------------
	# 公開 メソッド (public 扱い)
	#-------------------------------------------------------------------------

	##########################################################################
	# コンストラクタ
	##########################################################################
	ICMPv6Client(){
		$AddressFamily = [System.Net.Sockets.AddressFamily]::InterNetworkV6
		$SocketType = [System.Net.Sockets.SocketType]::Raw
		$ProtocolType = [System.Net.Sockets.ProtocolType]::IcmpV6

		$this.CV_Socket = New-Object System.Net.Sockets.Socket( $AddressFamily, $SocketType, $ProtocolType )
	}

	##########################################################################
	# 環境設定変更
	##########################################################################
	[void]SetEnvironment( [int] $TimeOut ){

		# タイムアウト
		if( $TimeOut -ne [int]$null ){
			$this.CCONF_TimeOut = $TimeOut
		}
	}

	##########################################################################
	# 短縮 IPv6 アドレス展開
	##########################################################################
	[string] DecodeIPv6Address([string] $IPv6Address){

		$Max = $IPv6Address.Length

		# : で区切られた内側の文字
		$Str4 = ""

		# : で区切られた内側の文字数
		$Len4 = 0

		# : 区切られた文字群
		[string[]]$Field8 = @()

		# 展開された IPv6 アドレス
		$FullIPv6Address = ""

		# 省略フィールドが使用されたフラグ
		$OmittedFlag = $False
		$OmittedPosition = 8
		$Omitted = 0
		$i = 0
		while($True){
			if(($IPv6Address[$i] -eq [char]":") -or ($i -ge $Max)){
				# リーディングゼロ省略
				if( $Len4 -ne 0 ){
					$Str4 = "0" * (4 - $Len4) + $Str4
					$Field8 += $Str4
					$Str4 = ""
					$Len4 = 0
					if( $OmittedFlag -eq $True ){
						$Omitted--
					}
				}
				# フィールド省略
				else{
					$OmittedPosition = $Field8.Length
					$Omitted = 8 - $OmittedPosition
					$OmittedFlag = $True
				}

				if( $i -ge $Max ){
					break
				}
				$i++
			}
			else{
				$Str4 += $IPv6Address[$i]
				$i++
				$Len4++
				if( $Len4 -gt 4 ){
					$ErrorActionPreference = "Stop"
					throw "IPv6 アドレス形式異常 : $IPv6Address"
				}
			}
		}

		# 省略補完
		$Max = $Field8.Length
		$i = 0
		while($True){
			# :: の時
			if($Field8.Length -eq 0){
				$FullIPv6Address += "0000:" * $Omitted
				break
			}

			$FullIPv6Address += $Field8[$i] + ":"
			$i++

			# 省略開始
			if( $i -eq $OmittedPosition){
				# 省略分挟み込む
				$FullIPv6Address += "0000:" * $Omitted
			}

			if( $i -ge $Max ){
				break
			}
		}

		# 末尾の ":" を消す
		$FullIPv6Address = $FullIPv6Address.Substring(0, $FullIPv6Address.Length -1)

		Return $FullIPv6Address
	}

	##########################################################################
	# ICMPv6 データ作成
	##########################################################################
	[byte[]] CreateICMPv6([byte]$Type, [byte]$Code, [byte[]]$MessageBody){
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
		[byte[]]$ICMPv6 = @()

		# Type(8)
		$ICMPv6 += $Type

		# Code(8)
		$ICMPv6 += $Code

		# チェックサム(16)
		$Checksum = New-Object byte[] 2
		$Checksum = @(0x00, 0x00)
		$ICMPv6 += $Checksum

		# Message Body
		$ICMPv6 += $MessageBody

		Return $ICMPv6
	}

	##########################################################################
	# UINT16 を Byte 列にセットする
	##########################################################################
	[byte[]]SetUint16toBytes([System.UInt16]$Uint){
		$Bytes = New-Object byte[] 2
		$Bytes[0] = $Uint -shr 8
		$Bytes[1] = ($Uint -shl 8) -shr 8
		Return $Bytes
	}

	##########################################################################
	# UINT32 を Byte 列にセットする
	##########################################################################
	[byte[]]SetUint32toBytes([System.UInt32]$Uint){
		$Bytes = New-Object byte[] 4
		$Bytes[0] = $Uint -shr 24
		$Bytes[1] = ($Uint -shl 8) -shr 24
		$Bytes[2] = ($Uint -shl 16) -shr 24
		$Bytes[3] = ($Uint -shl 24) -shr 24
		Return $Bytes
	}

	##########################################################################
	# IPv6 Address を Byte 列にセットする
	##########################################################################
	[byte[]]SetIPv6AddresstoBytes([string]$IPv6Address){
		$AdressesPart = $IPv6Address.Split(":")

		[byte[]]$Bytes = @()
		$Max = $AdressesPart.Length
		for( $i = 0 ; $i -lt $Max ; $i++){
			[System.UInt16]$Uint = [Convert]::ToUInt16($AdressesPart[$i], 16)
			$Bytes += $this.SetUint16toBytes($Uint)
		}

		Return $Bytes
	}

	##########################################################################
	# 2 byte を UINT16 にする
	##########################################################################
	[System.UInt16]Set2ByteToUint16([byte[]]$Bytes){
		[System.UInt16]$Uint = ($Bytes[0] -shl 8) + $Bytes[1]
		Return $Uint
	}

	##########################################################################
	# チェックサム計算
	##########################################################################
	[System.UInt16] ComputeChecksum([byte[]]$SrcIP, [byte[]]$DstIP, [byte[]]$Data){

		# 送信元 IPv6 アドレス(128)
		[byte[]]$Body += $SrcIP

		# 宛先 IPv6 アドレス(128)
		$Body += $DstIP

		# 上位レイヤー プロトコル パケット長(32)
		[System.UInt32]$Length = $Data.Length
		[byte[]]$ByteLength = $this.SetUint32toBytes($Length)
		$Body += $ByteLength

		# zero(24)
		$Zero = New-Object byte[] 3
		$Zero = @(0x00, 0x00, 0x00)
		$Body += $Zero

		# プロトコル(8)
		[byte]$Protocol = 58	# ICMPv6
		$Body += $Protocol

		# 上位レイヤー データ
		$Body += $Data

		# Sum を求める
		[System.UInt32]$Sum = 0
		$Max = $Body.Length
		$Bytes = New-Object byte[] 2
		for( $i = 0; $i -lt $Max; $i += 2 ){
			$Bytes = @( $Body[$i], $Body[$i + 1])
			$Sum += $this.Set2ByteToUint16($Bytes)
		}

		# オーバーフロー
		[System.UInt16]$OverFlow = $Sum -shr 16

		# Sum の Uint16 部分
		[System.UInt32]$Sum16 = ($Sum -shl 16) -shr 16

		# オーバーフロー加算
		$Sum16 += $OverFlow

		# Uint16 部分のみ取り出す
		[System.UInt16]$Checksum = ($Sum16 -shl 16) -shr 16

		Return $Checksum
	}

	##########################################################################
	# チェックサム セット
	##########################################################################
	[byte[]] SetComputeChecksum( [System.UInt16]$Checksum, [byte[]]$ICMPv6 ){

		[byte[]]$ByteChecksum = $this.SetUint16toBytes($Checksum)

		$ICMPv6[2] = $ByteChecksum[0]
		$ICMPv6[3] = $ByteChecksum[1]

		Return $ICMPv6
	}

	##########################################################################
	# 送信
	##########################################################################
	[void]Send( [string]$Message, [bool]$Display ){
		# SendTo
	}

	##########################################################################
	# 受信
	##########################################################################
	[byte[]] Receive ( [string]$Prompt ){
		# ReceiveFrom
		Return (New-Object byte[] 3)
	}

	##########################################################################
	# 破壊
	##########################################################################
	Dispose(){
		$Shutdown = [System.Net.Sockets.SocketShutdown]::Both
		try {
			$this.CV_Socket.Shutdown($Shutdown)
			$this.CV_Socket.Close()
		}
		catch{
			$this.CV_Socket.Close()
		}
	}
}


