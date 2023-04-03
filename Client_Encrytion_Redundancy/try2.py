from web3 import Web3

private_key_hex = "0xf23a2e5c0fc265be9c572cbf11e668aa1b3a93997cdd4336ebeaa6874403f1df"
private_key = Web3.to_bytes(hexstr=private_key_hex)
w3 = Web3()
account = w3.eth.account.from_key(private_key)
address = account.address

print(f"Public address: {address}")
