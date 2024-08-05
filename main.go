package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"Enkriptor/endekrip"

	"github.com/gin-gonic/gin"
)

var (
	encryptFlag = flag.Bool("e", false, "Encrypt data")
	decryptFlag = flag.Bool("d", false, "Decrypt data")
	//data        = flag.String("data", "", "")
	//inputFile   = flag.String("i", "", "Input file path")
	//outputFile  = flag.String("o", "", "Output file path")
	//encryptedKey = flag.String("ek", "", "Path to encrypted key file (PEM format)")
	//publicKey    = flag.String("pk", "", "Path to public key file (PEM format)")
	//privateKey = flag.String("sk", "", "Path to private key file (PEM format)")
)

func buatKunci(privateKeyFile, publicKeyFile string) {

	// Generate RSA keys
	privateKey, publicKey, err := endekrip.GenerateRSAKeys(2048)
	if err != nil {
		log.Fatal(err)
	}

	// Save RSA keys to PEM files
	err = endekrip.SaveRSAPrivateKey(privateKeyFile, privateKey)
	if err != nil {
		log.Fatal(err)
	}

	err = endekrip.SaveRSAPublicKey(publicKeyFile, publicKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("RSA key pair generated and saved.")
	return
}

func enkripsi(publicKeyFile, plainTextFile, encryptedTextFile string) (bool, error) {

	// Load RSA keys from PEM files
	/*
		privateKey, err := endekrip.LoadRSAPrivateKey(privateKeyFile)
		if err != nil {
			log.Fatal(err)
			return false, err
		}
	*/
	fmt.Println("START ENKRIPSI")

	fmt.Println("Loading Public Key")
	publicKey, err := endekrip.LoadRSAPublicKey(publicKeyFile)
	if err != nil {
		fmt.Println("Loading Public Key Failed")
		log.Fatal(err)
		return false, err
	}

	fmt.Println("Loading PlainText")
	// Read plain text from file
	plainText, err := os.ReadFile(plainTextFile)
	if err != nil {
		fmt.Println("Loading PlainText Failed")
		log.Fatal(err)
		return false, err
	}

	fmt.Println("Generate AES Key")
	// Generate AES key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		fmt.Println("Generate AES Key Failed")
		log.Fatal(err)
		return false, err
	}

	fmt.Println("Encrypting PlainText")
	// Encrypt data using AES
	encryptedText, err := endekrip.EncryptAES(plainText, aesKey)
	if err != nil {
		fmt.Println("Encrypting PlainText Failed")
		log.Fatal(err)
		return false, err
	}

	fmt.Println("Writing EncryptedText")
	// Write encrypted text to file
	err = os.WriteFile(encryptedTextFile, []byte(encryptedText), 0644)
	if err != nil {
		log.Fatal(err)
		return false, err
	}

	fmt.Println("Encrypting Key")
	// Encrypt AES key using RSA
	encryptedKey, err := endekrip.EncryptRSA(aesKey, publicKey)
	if err != nil {
		fmt.Println("Encrypting Key Failed")
		log.Fatal(err)
		return false, err
	}
	fmt.Println("Encrypted AES Key:", encryptedKey)

	// Write encrypted key to file [bad practice]
	err = os.WriteFile("encryptedKey.txt", []byte(encryptedKey), 0644)
	if err != nil {
		log.Fatal(err)
		return false, err
	}

	fmt.Println("END ENKRIPSI")
	return true, nil
}

func dekripsi(privateKeyFile, encryptedTextFile, decryptedTextFile string) (bool, error) {

	// Load RSA keys from PEM files
	privateKey, err := endekrip.LoadRSAPrivateKey(privateKeyFile)
	if err != nil {
		log.Fatal(err)
		return false, err
	}

	// Read encrypted text from file
	encryptedKeyBytes, err := os.ReadFile("encryptedKey.txt")
	if err != nil {
		log.Fatal(err)
		return false, err
	}

	// Decrypt AES key using RSA
	decryptedKey, err := endekrip.DecryptRSA(string(encryptedKeyBytes), privateKey)
	if err != nil {
		log.Fatal(err)
		return false, err
	}
	fmt.Println("Decrypted AES Key:", base64.StdEncoding.EncodeToString(decryptedKey))

	// Read encrypted text from file
	encryptedTextBytes, err := os.ReadFile(encryptedTextFile)
	if err != nil {
		log.Fatal(err)
		return false, err
	}

	// Decrypt data using AES
	decryptedText, err := endekrip.DecryptAES(string(encryptedTextBytes), decryptedKey)
	if err != nil {
		log.Fatal(err)
		return false, err
	}

	// Write decrypted text to file
	err = os.WriteFile(decryptedTextFile, decryptedText, 0644)
	if err != nil {
		log.Fatal(err)
		return false, err
	}

	fmt.Println("Decryption completed. Check the decrypted text file.")

	return true, nil
}

/*
func readKey(filePath string) ([]byte, error) {
	keyData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		log.Fatal(err)
		return nil, errors.New("invalid PEM format")
	}

	if *encryptFlag {
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
*/

func main() {
	// Command-line flags
	privateKeyPath := flag.String("private", "private_key.pem", "Path to the RSA private key file")
	publicKeyPath := flag.String("public", "public_key.pem", "Path to the RSA public key file")
	plainTextPath := flag.String("plaintext", "plain_text.txt", "Path to the plain text file")
	encryptedTextPath := flag.String("encrypted", "encrypted_text.txt", "Path to the encrypted text file")
	decryptedTextPath := flag.String("decrypted", "decrypted_text.txt", "Path to the decrypted text file")
	generateKeys := flag.Bool("genkeys", false, "Generate new RSA key pair")
	flag.Parse()

	if *generateKeys {
		buatKunci(*privateKeyPath, *publicKeyPath)
	}

	if *encryptFlag {
		enkripsi(*publicKeyPath, *plainTextPath, *encryptedTextPath)
	}

	if *decryptFlag {
		dekripsi(*privateKeyPath, *encryptedTextPath, *decryptedTextPath)
	}

	// set to debug mode
	gin.SetMode(gin.DebugMode)

	/*
		router := gin.Default()
		router.LoadHTMLGlob("assets/*")

		router.GET("/", getRoot)

		// encrypt URL Handle
		router.GET("/encrypt", getEncrypt)

		// decrypt URL Handle
		router.GET("/decrypt", getDecrypt)

		// key Handle
		//router.GET("/key/create", getKeyCreate)
		//router.GET("/key/delete", getKeyDelete)

		router.Run("localhost:3030")
	*/
}

func getRoot(c *gin.Context) {

	// Call the HTML method of the Context to render an assets
	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the index.html template
		"index.html",
		// Pass the data that the page uses (in this case, 'title')
		gin.H{
			"title": "Home Page",
		},
	)

}

func getEncrypt(c *gin.Context) {
	pt := c.Query("pt")

	c.IndentedJSON(http.StatusNotFound, gin.H{"plain": pt})

}

func getDecrypt(c *gin.Context) {
	et := c.Query("et")

	c.IndentedJSON(http.StatusNotFound, gin.H{"encrypted": et})
}
