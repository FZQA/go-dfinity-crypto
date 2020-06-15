package main

import "fmt"
import "github.com/yeongchingtarn/geth-pbft/tssign"

func main(){
	fmt.Println(tssign.TSVerify(tssign.Bsig,tssign.Bpk))
}