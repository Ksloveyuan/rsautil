# rsautil
some frequenetly used rsa crypto utils, e.g. 
- GenerateKey
- EncodePrivateKey
- EncodePublicKey 
- Encrypt
- Decrypt 
- SignWithSha256Base64
- VerySignWithSha256Base64

# An example 
```golang
func TestSignAndVerify(t *testing.T)  {
	sk, pk, _ := GenerateKey(1024)
	skBytes := EncodePrivateKey(sk)
	pkBytes, _ := EncodePublicKey(pk)
	fmt.Println(string(skBytes))
	fmt.Println(string(pkBytes))

	sig, err := SignWithSha256Base64("test", skBytes)
	if err != nil{
		fmt.Printf("%+v", err)
	}
	fmt.Println(sig)

	success, err := VerySignWithSha256Base64("test", sig, pkBytes)
	if success {
		fmt.Println("pass")
	} else {
		fmt.Printf("%+v", err)
	}
}
```

# Usage
[内部API的安全防护怎么搞？密码学中有答案](https://juejin.im/post/5d6354fdf265da03963ba535)

Code:[ApiSecurityDemo](https://github.com/Ksloveyuan/ApiSecurityDemo)
