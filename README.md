# EOS KeyProtector Smart Contract

### Description:

`keyprotector` is a proof of concept smart contract that can help protect a user against lost/stolen account keys. The user simply has to set `CONTRACTNAME@eosio.code` permission on their owner authority.

### How To Use:

- Deploy contract to account
- Set eosio.code permission on user for contract
	- `cleos set account permission USERNAME owner '{"threshold": 1,"keys": [{"key": "YOUR_CURRENT_OWNER_PUBLIC_KEY","weight": 1}], "accounts": [{"permission":{"actor":"CONTRACTNAME","permission":"eosio.code"},"weight":1}]}' -p USERNAME@owner`
- Push `setkeys` action to CONTRACTNAME
	-	`cleos push action CONTRACTNAME setkeys '{"o":"USERNAME","ok":"NEW_OWNER_PUBLIC_KEY","ak":"NEW_ACTIVE_PUBLIC_KEY"}' -p USERNAME`
- Push `run` action to CONTRACTNAME where `i` is run interval
	- `cleos push action CONTRACTNAME run '{"i":3600}' -p CONTRACTNAME@active

### Note:

`keyprotector` is still under development and has not yet been deployed on the EOSIO mainnet. If you wish to use the contract, proceed at your own risk and be capable of evaluating the source code before blindly running it.
