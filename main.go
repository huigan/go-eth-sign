package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/umbracle/ethgo/wallet"
	"math/big"
)

func main() {

	pk2 := "SignPrivateKey" // 签名私钥
	b, _ := hexutil.Decode(pk2)
	key, _ := wallet.NewWalletFromPrivKey(b)

	//参数
	tokenAmount := big.NewInt(100000000000000)
	nonce := big.NewInt(0)              //需要从合约中获取 防止重放攻击
	timestamp := big.NewInt(1741682422) //时间戳

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
}
