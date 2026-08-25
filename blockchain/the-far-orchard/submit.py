import json
from web3 import Web3
launch=json.load(open('launch2.json'))
receipts=json.load(open('receipts.json'))
rpc=launch['0']['RPC_URL']
priv=launch['1']['PRIVKEY']
wallet=Web3.to_checksum_address(launch['3']['WALLET_ADDR'])
w3=Web3(Web3.HTTPProvider(rpc,request_kwargs={'timeout':30}))
abi=[{
 'type':'function','name':'honorSeal','stateMutability':'nonpayable',
 'inputs':[{'name':'sealId','type':'uint256'},{'name':'nullifier','type':'bytes32'},{'name':'signature','type':'bytes'}],
 'outputs':[]
},{'type':'function','name':'honoredCount','stateMutability':'view','inputs':[],'outputs':[{'type':'uint256'}]},
  {'type':'function','name':'honoredBitmap','stateMutability':'view','inputs':[],'outputs':[{'type':'uint256'}]}]
orchard=w3.eth.contract(address=Web3.to_checksum_address(receipts[0]['orchard']),abi=abi)
nonce=w3.eth.get_transaction_count(wallet)
for r in receipts:
 assert r['status']=='ok'
 tx=orchard.functions.honorSeal(
   int(r['seal_id']), bytes.fromhex(r['nullifier'].removeprefix('0x')),
   bytes.fromhex(r['signature'].removeprefix('0x'))
 ).build_transaction({'from':wallet,'nonce':nonce,'chainId':w3.eth.chain_id,'gas':300000,'gasPrice':w3.eth.gas_price})
 signed=w3.eth.account.sign_transaction(tx,private_key=priv)
 h=w3.eth.send_raw_transaction(signed.raw_transaction)
 rcpt=w3.eth.wait_for_transaction_receipt(h,timeout=30)
 print(f"seal {r['seal_id']}: status={rcpt.status} tx={h.hex()}")
 if rcpt.status != 1: raise SystemExit('transaction reverted')
 nonce += 1
print('honoredCount',orchard.functions.honoredCount().call())
print('honoredBitmap',hex(orchard.functions.honoredBitmap().call()))
