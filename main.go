package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/sha3"
)

type KeyStore struct {
	address    string
	PublicKey  string
	PrivateKey string
}

type UserInfo struct {
	KeyStore     KeyStore
	EthBalance   big.Int
	Erc20Balance map[string]big.Int
}

//map for userID - userInfo
var UsersData = make(map[int]UserInfo)

//map for address - userID
var UsersAddresses = make(map[string]int)

var lastBlockHeight = big.NewInt(0)

var client = new(ethclient.Client)

func main() {

	//connect to ethereum node
	//_client, err := ethclient.Dial("wss://mainnet.infura.io/ws/v3/00bfe69952bb416c8772333ee22f9372")
	_client, err := ethclient.Dial("wss://ropsten.infura.io/ws/v3/1975e4f0e78940deb6d6b8880bd0bf4f")
	if err != nil {
		fmt.Println(err)
		return
	}
	client = _client

	//start API server
	go handleRequests()

	//go startScanning(client)

	headers := make(chan *types.Header)

	sub, err := client.SubscribeNewHead(context.Background(), headers)
	if err != nil {
		fmt.Println(err)
		return
	}

	for {
		select {
		case err := <-sub.Err():
			fmt.Println(err)
			return
		case header := <-headers:
			scanInit(header)
		}
	}
}
func withdrawERC20Deposits() {
	for _, userData := range UsersData {
		privateKey, err := crypto.HexToECDSA(userData.KeyStore.PrivateKey)
		if err != nil {
			fmt.Println(err)
			return
		}
		for contractAddress, balance := range userData.Erc20Balance {
			value := big.NewInt(0)
			toAddress := common.HexToAddress("0x0000000000000000000000000000000000000001")
			tokenAddress := common.HexToAddress(contractAddress)
			transferFnSignature := []byte("transfer(address,uint256)")
			hash := sha3.NewLegacyKeccak256()
			hash.Write(transferFnSignature)
			methodID := hash.Sum(nil)[:4]
			paddedAddress := common.LeftPadBytes(toAddress.Bytes(), 32)
			paddedAmount := common.LeftPadBytes(balance.Bytes(), 32)
			var data []byte
			data = append(data, methodID...)
			data = append(data, paddedAddress...)
			data = append(data, paddedAmount...)
			gasLimit, err := client.EstimateGas(context.Background(), ethereum.CallMsg{
				To:   &toAddress,
				Data: data,
			})
			gasLimit += 100000
			if err != nil {
				fmt.Println(err)
				return
			}
			gasPrice, err := client.SuggestGasPrice(context.Background())
			if err != nil {
				fmt.Println(err)
				return
			}
			nonce, err := client.PendingNonceAt(context.Background(), common.HexToAddress(userData.KeyStore.address))
			if err != nil {
				fmt.Println(err)
				return
			}
			gas := big.NewInt(0)
			gas.Mul(gasPrice, big.NewInt(int64(gasLimit)))
			tx := types.NewTransaction(nonce, tokenAddress, value, gasLimit, gasPrice, data)
			chainID, err := client.NetworkID(context.Background())
			if err != nil {
				fmt.Println(err)
				return
			}

			signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
			if err != nil {
				fmt.Println(err)
				return
			}
			err = client.SendTransaction(context.Background(), signedTx)
			if err != nil {
				fmt.Println(err)
				return
			}
		}

	}

}

func withdrawETHDeposits() {
	for _, userData := range UsersData {
		privateKey, err := crypto.HexToECDSA(userData.KeyStore.PrivateKey)
		if err != nil {
			fmt.Println(err)
			return
		}
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Fatal("error casting public key to ECDSA")
		}

		fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
		nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
		if err != nil {
			fmt.Println(err)
			return
		}
		gasLimit := uint64(21000)
		gasPrice, err := client.SuggestGasPrice(context.Background())
		if err != nil {
			fmt.Println(err)
			return
		}
		gas := big.NewInt(0)
		gas.Mul(gasPrice, big.NewInt(int64(gasLimit)))
		toAddress := common.HexToAddress("0x0000000000000000000000000000000000000000")
		tx := types.NewTransaction(nonce, toAddress, userData.EthBalance.Sub(&userData.EthBalance, gas), gasLimit, gasPrice, nil)
		chainID, err := client.NetworkID(context.Background())
		if err != nil {
			fmt.Println(err)
			return
		}

		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = client.SendTransaction(context.Background(), signedTx)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func scanInit(header *types.Header) {
	if lastBlockHeight.Cmp(big.NewInt(0)) == 0 {
		lastBlockHeight.Set(header.Number)
		lastBlockHeight = lastBlockHeight.Sub(lastBlockHeight, big.NewInt(1))
	}
	if header.Number.Cmp(lastBlockHeight) != 1 {
		return
	}

	diff := big.NewInt(0)

	diff.Sub(header.Number, lastBlockHeight)

	for i := 0; i < int(diff.Int64()); i++ {
		scanERC20Transfers(lastBlockHeight)
		scanETHTransfers(lastBlockHeight)
		lastBlockHeight.Add(lastBlockHeight, big.NewInt(1))
	}
}

func scanERC20Transfers(height *big.Int) {

	block, err := client.BlockByNumber(context.Background(), height)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, tx := range block.Transactions() {
		if len(tx.Data()) > 0 {
			go scanERC20Receipt(tx.Hash(), block.Number(), tx.GasPrice())
		}
	}
}

func scanERC20Receipt(hash common.Hash, blockHeight *big.Int, gasPrice *big.Int) {
	receipt, err := client.TransactionReceipt(context.Background(), hash)
	if err != nil {
		fmt.Println(err)
		return
	}
	if receipt.Status != 1 {
		return
	}
	for _, logs := range receipt.Logs {
		if logs.Topics[0].String() == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef" {

			if len(logs.Topics) == 3 {
				value := big.NewInt(0)
				value.SetBytes(logs.Data)

				sender := strings.ToUpper(logs.Topics[1].String())[len(logs.Topics[1].String())-40:]
				receiver := strings.ToUpper(logs.Topics[2].String())[len(logs.Topics[2].String())-40:]
				sender = "0X" + sender
				receiver = "0X" + receiver
				if userID, exist := UsersAddresses[sender]; exist {

					fee := big.NewInt(0)
					fee.Mul(gasPrice, big.NewInt(int64(receipt.GasUsed)))
					go finalizeERC20TxSender(userID, logs.Address, *value, *fee)
				}
				if userID, exist := UsersAddresses[receiver]; exist {
					go finalizeERC20TxReceiver(hash, userID, logs.Address, *value, *blockHeight)
				}
			}
		}
	}
}

func scanETHTransfers(height *big.Int) {
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		fmt.Println(err)
		return
	}
	block, err := client.BlockByNumber(context.Background(), height)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, tx := range block.Transactions() {
		//smart contract creation tx
		if tx.To() == nil {
			continue
		}
		if userID, exist := UsersAddresses[strings.ToUpper(tx.To().String())]; exist {
			go finalizeEthTxReceiver(tx.Hash(), userID, *tx.Value(), *block.Number())
		}
		msg, err := tx.AsMessage(types.LatestSignerForChainID(chainID), nil)
		if err != nil {
			fmt.Println(err)
			return
		}
		if userID, exist := UsersAddresses[strings.ToUpper(msg.From().String())]; exist {
			go finalizeEthTxSender(tx.Hash(), userID, *tx.Value())
		}
	}
}

func finalizeEthTxReceiver(txHash common.Hash, userID int, value big.Int, blockHeight big.Int) {
	receipt, err := client.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		fmt.Println(err)
		return
	}
	if receipt.Status == 1 {
		userData := UsersData[userID]
		userData.EthBalance.Add(&value, &userData.EthBalance)
		UsersData[userID] = userData
		WebHook(txHash.String(), value, "ETH", "", blockHeight, userID)
	}
}

func finalizeEthTxSender(txHash common.Hash, userID int, value big.Int) {
	receipt, err := client.TransactionReceipt(context.Background(), txHash)
	if err != nil {
		fmt.Println(err)
		return
	}
	if receipt.Status == 1 {
		userData := UsersData[userID]
		userData.EthBalance.Sub(&userData.EthBalance, &value)
		UsersData[userID] = userData
	}
}

func finalizeERC20TxReceiver(txHash common.Hash, userID int, address common.Address, value big.Int, blockHeight big.Int) {
	userData := UsersData[userID]
	if userData.Erc20Balance == nil {
		m := make(map[string]big.Int)
		userData.Erc20Balance = m
	}
	tmp := userData.Erc20Balance[address.String()]
	tmp.Add(&value, &tmp)
	userData.Erc20Balance[address.String()] = tmp
	UsersData[userID] = userData
	WebHook(txHash.String(), value, "ERC20", address.String(), blockHeight, userID)
}

func finalizeERC20TxSender(userID int, address common.Address, value big.Int, fee big.Int) {

	userData := UsersData[userID]
	tmp := userData.Erc20Balance[address.String()]
	tmp.Sub(&value, &tmp)
	userData.Erc20Balance[address.String()] = tmp
	userData.EthBalance.Sub(&userData.EthBalance, &fee)
	UsersData[userID] = userData
}

func WebHook(blockchainTxId string, amount big.Int, txType string, tokenAddress string, blockNumber big.Int, userId int) {
	fmt.Println("webhook: ", blockchainTxId, " ", amount.String(), " ", txType, " ", tokenAddress, " ", blockNumber.String(), " ", userId)
}

func handleRequests() {
	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc("/generateWalletAPI", generateWalletAPI)
	myRouter.HandleFunc("/withdrawERC20Deposits", withdrawERC20DepositsAPI)
	myRouter.HandleFunc("/withdrawETHDeposits", withdrawETHDepositsAPI)
	myRouter.HandleFunc("/userInfo/{userID}", GetUserInfo)

	corsObj := handlers.AllowedOrigins([]string{"*"})
	log.Fatal(http.ListenAndServe(":8000", handlers.CORS(corsObj)(myRouter)))
}

func withdrawERC20DepositsAPI(w http.ResponseWriter, r *http.Request) {
	withdrawERC20Deposits()
}

func withdrawETHDepositsAPI(w http.ResponseWriter, r *http.Request) {
	withdrawETHDeposits()
}

func GetUserInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	_userID, ok := vars["userID"]

	if !ok {
		fmt.Println("userID not provided")
		w.Write([]byte("userID not provided"))
		return
	}

	userID, err := strconv.Atoi(_userID)
	if err != nil {
		fmt.Println(err)
		return
	}

	if _, exist := UsersData[userID]; !exist {
		fmt.Println("Wallet has not been created for this user")
		w.Write([]byte("Wallet has not been created for this user"))
		return
	}
	balance := UsersData[userID].EthBalance
	addr := UsersData[userID].KeyStore.address[2:]
	addr = "0x" + addr
	message := "user with userID:" + _userID + "  has wallet address:" + addr + "		balance:" + balance.String() + " wei"
	message += "\n"
	for address, erc20 := range UsersData[userID].Erc20Balance {
		message += "token: " + address + "balance: " + erc20.String() + "\n"
	}

	w.Write([]byte(message))
}

func generateWalletAPI(w http.ResponseWriter, r *http.Request) {
	_userID := r.FormValue("userID")

	if _userID == "" {
		fmt.Println("userID not provided")
		w.Write([]byte("userID not provided"))
		return
	}

	userID, err := strconv.Atoi(_userID)
	if err != nil {
		fmt.Println(err)
		return
	}

	if _, exist := UsersData[userID]; exist {
		fmt.Println("Wallet is allready created for this user")
		w.Write([]byte("Wallet is allready created for this user"))
		return
	}

	newAddress, err := generateWallet(userID)
	if err != nil {
		return
	}
	message := "New wallet is generated. The address is " + newAddress
	fmt.Println(message)
	w.Write([]byte(message))
}

//generates new wallet for user with userID and returns wallet address
func generateWallet(userID int) (string, error) {

	//generate private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println(err)
		return "", err
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)

	//generate public key
	publicKey := privateKey.Public()

	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	newKeystore := new(KeyStore)
	newKeystore.PrivateKey = hexutil.Encode(privateKeyBytes)[2:]
	newKeystore.PublicKey = hexutil.Encode(publicKeyBytes)[4:]
	newKeystore.address = strings.ToUpper(crypto.PubkeyToAddress(*publicKeyECDSA).Hex())

	newUserInfo := new(UserInfo)
	newUserInfo.KeyStore = *newKeystore
	newUserInfo.EthBalance = *big.NewInt(0)

	UsersData[userID] = *newUserInfo

	UsersAddresses[newKeystore.address] = userID
	addr := UsersData[userID].KeyStore.address[2:]
	addr = "0x" + addr
	return addr, nil
}
