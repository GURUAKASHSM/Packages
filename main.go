package main

import (
	"log"

	asymmetrictokenservice "github.com/GURUAKASHSM/Packages/AsymmetricTokenService"
)

//import  "github.com/GURUAKASHSM/Packages/SymmetricTokenServiceTest"

func main() {
	//service_test.RunAllTests()
	token,err := asymmetrictokenservice.CreateToken("guruakash.ec20@bitsathy.ac.in","123231324","decrypted_private_key.pem",1)
	if err != nil{
		log.Println(err)
		return
	}
	log.Println("token",token)

	data,err := asymmetrictokenservice.ExtractDetailsFromToken(token,"public_key.pem")
	if err != nil{
		log.Println(err)
		return
	}
	log.Println("details",data)

	id,err := asymmetrictokenservice.ExtractIDFromToken(token,"public_key.pem")
	if err != nil{
		log.Println(err)
		return
	}
	log.Println("details",id)

	valid := asymmetrictokenservice.IsTokenValid(token,"public_key.pem")
	log.Println("vaild",valid)

	tokenManager := asymmetrictokenservice.NewTokenManager()
	err = tokenManager.BlockToken(token,"public_key.pem")
	if err != nil{
		log.Println(err)
		return
	}
	
	valid = tokenManager.IsTokenBlocked(token)
	log.Println("Isblocked",valid)

	err = tokenManager.UnblockToken(token,"public_key.pem")
	if err != nil{
		log.Println(err)
		return
	}
		
	valid = tokenManager.IsTokenBlocked(token)
	log.Println("Isblocked",valid)

	time,err := asymmetrictokenservice.ExtractExpirationTimeFromToken(token,"public_key.pem")
	if err != nil{
		log.Println(err)
		return
	}
	log.Println("ValidTill",time)

	accesstoken,refreshtoken,err := asymmetrictokenservice.GenerateAccessAndRefreshAsymmetricTokens("gurakash.ec20@bitsathy.ac.in","12132434345swf121","decrypted_private_key.pem","public_key.pem")
	if err != nil{
		log.Println(err)
		return
	}
	log.Println("accesstoken",accesstoken)
    log.Println("refreshtoken",refreshtoken)

	accesstoken,err = asymmetrictokenservice.RefreshAsymmetricAccessToken(refreshtoken,"public_key.pem","decrypted_private_key.pem")
	if err != nil{
		log.Println(err)
		return
	}
	log.Println("accesstoken",accesstoken)

}
