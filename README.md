# go-eth-sign
go语言链下用某私钥对参数进行签名，solidity合约中进行签名验证，从签名中可以恢复签名地址，验证是否是某个地址的签名和参数是否被修改。
## 使用场景
* 比如在链下游戏中，用户获得某个奖励，如果平台主动给用户发放到链上，则链上手续费将是不小的一笔费用，平台可以用管理员地址将用户可以获得的奖励签名后，由用户提交到链上，合约内只需要验证签名是否是管理员地址签名的即可。这样既节省手续费也能保证安全。
* 也可在金融等其他领域，需要链下计算，用户链上领取等的场景。

## 使用方法

在solidity合约中：
参数：
* tokenAmount:奖励的代币数量
* nonce：用户累计值，此值需要通过合约的getNonce方法获取，目的是防止用户重复提交到链上，从而重复获取奖励。
* timestamp：时间戳，合约内可以根据设置签名过期时间。
* sig：签名字符串
```solidity
using ECDSA for bytes32;
function getNonce( address addr) public view returns(uint256) {
    return nonceUser[msg.sender];
}
function claim(uint256 tokenAmount,uint256 nonce,uint256 timestamp, bytes memory sig) public  {
       
    require(nonceUser[msg.sender] == nonce, "nonce error");
    require(block.timestamp <= timestamp + timeout,"sig timeout");

    bytes32 hash = keccak256(abi.encodePacked(tokenAmount, msg.sender,userAddr,ordersn,nonce, timestamp));
    require(
        hash.toEthSignedMessageHash().recover(sig) == SIGNER,
        "PxG: Invalid signature"
    );

    nonceUser[msg.sender] = nonce+1;
    //下面发放奖励等

}
```

go代码中：
```go
pk2 := "SignPrivateKey" // 签名私钥
b, _ := hexutil.Decode(pk2)
key, _ := wallet.NewWalletFromPrivKey(b)

//参数
tokenAmount := big.NewInt(100)
nonce := big.NewInt(0) //需要从合约中获取 防止重放攻击
timestamp := big.NewInt(1741682422)

hash := crypto.Keccak256Hash(
common.LeftPadBytes(tokenAmount.Bytes(), 32),
common.LeftPadBytes(nonce.Bytes(), 32),
common.LeftPadBytes(timestamp.Bytes(), 32),
)
prefixedHash := crypto.Keccak256Hash(
[]byte("\x19Ethereum Signed Message:\n32"),
hash.Bytes(),
)
sig, _ := key.Sign(prefixedHash.Bytes())
sig[64] += 27

//转为16进制
fmt.Print(common.Bytes2Hex(sig))
```


