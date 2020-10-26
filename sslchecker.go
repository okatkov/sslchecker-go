package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
)

// validity allows unmarshaling the certificate validity date range
type CertInfo struct {
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	SerialNumber string `json:"serial_number"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
}

func main() {
	var certFileName = flag.String("cert","cert.pem", "a string")
	flag.Parse()
	pemData, err := ioutil.ReadFile(*certFileName)
	if err != nil {
		log.Fatal(err)
	}
	block, rest := pem.Decode([]byte(pemData))
	if block == nil || len(rest) > 0 {
		log.Fatal("Certificate decoding error")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	info := CertInfo{
		SerialNumber: fmt.Sprintf("%s", cert.SerialNumber),
		NotBefore:    cert.NotBefore.Local().String(),
		NotAfter:     cert.NotAfter.Local().String(),
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.String(),
	}

	prettyJSON, err := json.MarshalIndent(info, "", "    ")
	if err != nil {
		log.Fatal("Failed to generate json", err)
	}
	fmt.Printf("%s\n", string(prettyJSON))

}
