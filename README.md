# Blockchain Development task

## Usage
#### run the binary file 
#### generate wallet for users with localhost:8000/generateWalletAPI?userID={userID} 
#### deposit Eth or ERC20 token 
#### wait for webhook in console 
#### withdraw ERC20 deposits first if available with localhost:8000/withdrawERC20Deposits
#### withdraw ETH with localhost:8000/withdrawETHDeposits

## APIs
#### localhost:8000/generateWalletAPI?userID={userID} 
#### localhost:8000/userInfo/{userID}  
#### localhost:8000/withdrawERC20Deposits
#### localhost:8000/withdrawETHDeposits


## Note
#### wallets are stored only in memory