■ これは何?
ICMPv6 の送信と、簡易受信クラスです。
Type、Code、送信データを与えると、チェックサムを計算して ICMPv6 を送信します。
ping 戻りなど、簡易レベルであれば受信も出来ます。


■ 使い方
using module で ICMPv6.psm1 を指定してください。
New-Object ICMPv6Client() でコンストラクタを呼びます。

実装サンプル: Ping.ps1


■ メソッド
・コンストラクタ
    ICMPv6Client()
        オブジェクト作成のみ
        送信する前に SetIPv6Address で宛先 IPv6 アドレスを指定してくだい

    ICMPv6Client([string]$DstIPv6Address)
        宛先 IPv6 アドレスを指定
        送信元 IPv6 アドレスは自動選択されます

    ICMPv6Client([string]$DstIPv6Address, [string]$SrcIPv6Address)
        宛先 IPv6 アドレス、送信元を IPv6 アドレスを指定


・オブジェクト破棄
    Dispose()


・TTL 設定(Multicast)
    [void]SetMulticastTTL([Int32]$TTL)
    マルチキャストをあて先に指定する場合に、Hop Limit を明示的に指定します。


・TTL 設定(UNICAST)
    [void]SetUNICASTTTL([Int32]$TTL)
    ユニキャストをあて先に指定する場合に、Hop Limit を明示的に指定します。


・IPv6 アドレス指定(送信元自動選択)
    [void]SetIPv6Address( [string]$DstIPv6Address )
    宛先 IPv6 アドレスを指定します


・IPv6 アドレス指定(送信元指定)
    [void]SetIPv6Address( [string]$DstIPv6Address, [string]$SrcIPv6Address )
    宛先、送信元 IPv6 アドレスを指定します


・ネットワークオーダーのバイト配列にする
    [byte[]]GetNetworkBytes([System.ValueType]$Numeric)
    ホストオーダーの数値をネットワークオーダーのバイト配列にします

・ホストオーダーの数値にする(Uint16)
    [System.UInt16]GetHostUint16([byte[]]$Bytes, [System.Int32]$Index)
    ネットワークオーダーのバイト配列を、ホストオーダーの数値にします
        $Index : 開始位置


・ホストオーダーの数値にする(Uint32)
    [System.UInt32]GetHostUint32([byte[]]$Bytes, [System.Int32]$Index)
    ネットワークオーダーのバイト配列を、ホストオーダーの数値にします
        $Index : 開始位置

・送信
    [void]Send( [byte]$Type, [byte]$Code, [byte[]]$Data )
    データを送信します
        $Type : ICMPv6 タイプ
        $Code : コード
        $Dayta: 送信データ

・受信
    [byte[]] Receive()
    データを受信

・受信開始
    [System.IAsyncResult]ReceiveStart()
    受信を開始します

・受信終了
    [byte[]]ReceiveEnd([System.IAsyncResult]$Result)
    受信を終了します
        $Result : 送信開始時に得られた [System.IAsyncResult]

・チェックサム確認
    [bool]TestChecksum([byte[]]$Body)
    データのチェックサム整合性確認


■ Web site
PowerShell で ICMPv6 のチェックサムの計算をする
https://www.vwnet.jp/Windows/PowerShell/2019111701/ICMPv6Checksum.htm

