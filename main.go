package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"time"

	
	"github.com/gin-gonic/gin"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type OrgSetup struct {
	OrgName      string
	MSPID        string
	CryptoPath   string
	CertPath     string
	KeyPath      string
	TLSCertPath  string
	PeerEndpoint string
	GatewayPeer  string
	Gateway      *client.Gateway
}

// func AuthMiddleware() gin.HandlerFunc {
// 	// In a real-world application, you would perform proper authentication here.
// 	// For the sake of this example, we'll just check if an API key is present.
// 	return func(c *gin.Context) {
// 		apiKey := c.GetHeader("X-API-Key")
// 		if apiKey == "" {
// 			c.AbortWithStatusJSON(401, gin.H{"error": "Unauthorized"})
// 			return
// 		}
// 		c.Next()
// 	}
// }

func (setup *OrgSetup) InitializeHandler(c *gin.Context) {
	log.Printf("Initializing connection for %s...\n", setup.OrgName)

	clientConnection := setup.newGrpcConnection()
	id := setup.newIdentity()
	sign := setup.newSign()

	gateway, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		log.Printf("%v,%v", http.StatusInternalServerError, fmt.Sprintf("Error initializing connection: %s", err))
		return
	}
	setup.Gateway = gateway

	log.Printf("Gateway: %+v\n", setup.Gateway)
	log.Println("Initialization complete")
}

// newGrpcConnection creates a gRPC connection to the Gateway server.
func (setup OrgSetup) newGrpcConnection() *grpc.ClientConn {
	certificate, err := loadCertificate(setup.TLSCertPath)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, setup.GatewayPeer)

	connection, err := grpc.Dial(setup.PeerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func (setup OrgSetup) newIdentity() *identity.X509Identity {
	certificate, err := loadCertificate(setup.CertPath)
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(setup.MSPID, certificate)
	if err != nil {
		panic(err)
	}

	return id
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func (setup OrgSetup) newSign() identity.Sign {
	files, err := ioutil.ReadDir(setup.KeyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key directory: %w", err))
	}
	privateKeyPEM, err := ioutil.ReadFile(path.Join(setup.KeyPath, files[0].Name()))

	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return sign
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

func (setup *OrgSetup) Query(c *gin.Context) {
	fmt.Println("Received Query request")

	chainCodeName := c.Query("chaincodeid")
	channelID := c.Query("channelid")
	function := c.Query("function")
	args := c.QueryArray("args")

	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %v\n", channelID, chainCodeName, function, args)

	fmt.Printf("Gateway: %+v\n", setup.Gateway)

	if setup == nil {
		log.Fatal("setup is nil")
	}
	if setup.Gateway == nil {
		log.Fatal("Gateway is nil")
	}

	network := setup.Gateway.GetNetwork(channelID)
	contract := network.GetContract(chainCodeName)

	evaluateResponse, err := contract.EvaluateTransaction(function, args...)
	if err != nil {
		c.String(500, fmt.Sprintf("Error: %s", err))
		return
	}

	c.String(200, "Response: %s", evaluateResponse)
}

func (setup *OrgSetup) Invoke(c *gin.Context) {
	fmt.Println("Received Invoke request")

	if err := c.Request.ParseForm(); err != nil {
		c.String(500, fmt.Sprintf("ParseForm() err: %s", err))
		return
	}

	chainCodeName := c.Request.FormValue("chaincodeid")
	channelID := c.Request.FormValue("channelid")
	function := c.Request.FormValue("function")
	args := c.QueryArray("args")

	fmt.Printf("channel: %s, chaincode: %s, function: %s, args: %v\n", channelID, chainCodeName, function, args)

	fmt.Printf("Gateway: %+v\n", setup.Gateway)

	if setup == nil {
		log.Fatal("setup is nil")
	}
	if setup.Gateway == nil {
		log.Fatal("Gateway is nil")
	}

	network := setup.Gateway.GetNetwork(channelID)
	contract := network.GetContract(chainCodeName)

	//contract.Submit(function,client.WithArguments(args...))

	txn_proposal, err := contract.NewProposal(function, client.WithArguments(args...))
	if err != nil {
		log.Println("error: %v",err.Error())
		c.String(http.StatusInternalServerError, fmt.Sprintf("Error creating txn proposal: %s", err))
		return
	}

	txn_endorsed, err := txn_proposal.Endorse()
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("Error endorsing txn: %s", err))
		return
	}

	txn_committed, err := txn_endorsed.Submit()
	if err != nil {
		c.String(http.StatusInternalServerError, fmt.Sprintf("Error submitting transaction: %s", err))
		return
	}

	c.String(200, "Transaction ID: %s Response: %s", txn_committed.TransactionID(), txn_endorsed.Result())
}
func main() {

	//Initialize setup for Org1
	cryptoPath := "../../test-network/organizations/peerOrganizations/org1.example.com"
	orgConfig := OrgSetup{
		OrgName:      "Org1",
		MSPID:        "Org1MSP",
		CertPath:     cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem",
		KeyPath:      cryptoPath + "/users/User1@org1.example.com/msp/keystore/",
		TLSCertPath:  cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt",
		PeerEndpoint: "localhost:7051",
		GatewayPeer:  "peer0.org1.example.com",
	}

	// orgConfig.InitializeHandler()

	r := gin.Default()
	r.GET("/init",orgConfig.InitializeHandler)
	r.POST("/invoke", orgConfig.Invoke)

	r.GET("/query", orgConfig.Query)

	err := r.Run(":8080")
	if err != nil {
		fmt.Println(err)
	}
}
