package main

import "github.com/go-dfinity-crypto/bls"
import "fmt"
import "time"

type TSPKBytes struct{
	TPK []byte
}

type TSSignKBytes struct{
	TSign []byte
}

func main(){
	err := bls.Init(bls.CurveFp254BNb)
	if err != nil {
		fmt.Println(err)
	}
	m := "testSign"
	fmt.Println(m)
	// 0代表非门限
	var sec0 bls.SecretKey
	sec0.SetByCSPRNG() //获取一个秘密值设为sk
	pub0 := sec0.GetPublicKey() //通过sk获取pk    数量为1
	fmt.Println("--------------------------------")
	fmt.Println("len pk", len(pub0.Serialize())) //Serialize转换为byte测大小
	fmt.Println(pub0.Serialize())
	fmt.Println("--------------------------------")
	s0 := sec0.Sign(m) //直接通过sk前面
	fmt.Println("--------------------------------")
	fmt.Println("len sig", len(s0.Serialize())) //Serialize转换为byte测大小
	fmt.Println("--------------------------------")
	start := time.Now()
	if !s0.Verify(pub0, m) { //验证签名
		fmt.Println("Signature does not verify")
	}
	end := time.Now()
	fmt.Println("--------------------------------")
	fmt.Println("time for Verify", end.Sub(start))
	fmt.Println("--------------------------------")

	var Tpkb TSPKBytes
	Tpkb.TPK = pub0.Serialize()
	fmt.Println("Tpkb.TPK", Tpkb.TPK)

	var Tpk bls.PublicKey
	Tpk.Deserialize(Tpkb.TPK)

	var TSSB TSSignKBytes
	TSSB.TSign = s0.Serialize()
	fmt.Println("TSSignKBytes", TSSB.TSign)

	var TSS bls.Sign
	TSS.Deserialize(TSSB.TSign)

	if !TSS.Verify(&Tpk, m) { //验证签名
		fmt.Println("Signature does not verify")
	}
	// //固化pk 与 sig

	// var bpk = []byte{130, 136, 187, 148, 170, 116, 237, 182, 182, 165, 111, 26, 113, 252, 74, 193, 37, 109, 233, 16, 69, 136, 242, 167, 240, 77, 202, 170, 102, 174, 250, 36, 134, 23, 131, 109, 38, 29, 64, 225, 201, 194, 250, 196, 143, 250, 183, 9, 109, 235, 99, 109, 92, 106, 182, 221, 7, 1, 2, 82, 92, 214, 8, 10}
	// var bsig = []byte{102, 83, 244, 3, 251, 218, 177, 223, 226, 221, 115, 100, 189, 122, 166, 29, 161, 18, 2, 226, 15, 215, 118, 159, 101, 72, 196, 91, 209, 241, 204, 164}
	// var Tpk bls.PublicKey
	// Tpk.Deserialize(bpk)

	// var TSS bls.Sign
	// TSS.Deserialize(bsig)
	// // fmt.Println(TSS.Verify(&Tpk, m))
	// if !TSS.Verify(&Tpk, m) { //验证签名
	// 	fmt.Println("Signature does not verify")
	// }
}

