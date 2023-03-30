from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from dotenv import load_dotenv
from uuid import UUID
import os
import json
#from MerkleTree import MerkleTree

class Connector:
	def __init__(self):
		# Load the environment variables from the .env file.
		# TODO: might not need .env in the future i guesss
		load_dotenv('../.env')

		# Connect to the Ethereum blockchain via remote node provider.
		self.w3 = Web3(Web3.HTTPProvider(os.getenv("INFURA_NODE_ENDPOINT")))

		# Load the contract ABI and contract address.
		with open('E:\programming\courses\cmpt456\Distributed-Storage-on-Ethereum\Contract\contract_abi.json', 'r') as f:
			contract_abi = json.load(f)
		
		contract_address = os.getenv("CONTRACT_ADDRESS")
		self.contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)

	
	def is_valid_hash(self, root_hash_raw):
		'''
		Input: hash value - the 32-byte hex string.
		Output: If the hash value valid or not, return hash value if valid or error if no valid.
		'''
		# File root hash should be provided and should be 32-byte hex string.
		if not root_hash_raw.startswith("0x"):
			root_hash_raw = "0x" + root_hash_raw
		if len(root_hash_raw) != 66:
			return {"is_valid": False, "hash_value": "PROVIDED HASH STRING IS NOT 32-BYTE."}
		try:
			root_hash_int = int(root_hash_raw, 16)
			root_hash = hex(root_hash_int)
			return {"is_valid": True, "hash_value": root_hash}
		except ValueError:
			return {"is_valid": False, "hash_value": "CAN NOT CONVERT PROVIDED HASH STRING TO HEX."}

	
	def is_valid_uuid(self, uuid_value):
		'''
		Input: UUID to test.
		Output: Return True if the UUID is valid, otherwise return false.
		'''
		try:
			UUID(str(uuid_value))
			return True
		except ValueError:
			return False


	def file_preprocess(self, file_json):
		'''
		Purpose: Pre-check the provided file details before making the transaction. 
		Input: File details includes file name, file size, chunk size, redundancy, file root hash, file chunks info.
		Output: Argument list for calling corresponding smart contract function + Error message.
		'''
		file_details = json.loads(file_json)

		# =========== FILE PRE-PRECESSING ===========
		# File name should be provided and should not be empty string.
		if ("file_name" in file_details) and (file_details["file_name"] is not None):
			if file_details["file_name"]:
				file_name = file_details["file_name"] 
			else: 
				return {"args": None, "err": "FILE NAME SHOULD NOT BE EMPTY."}
		else:
			return {"args": None, "err": "MISSING FILE NAME INFORMATION."}

		# File size should be provided and should be integer (or should able to convert to integer).
		if ("file_size" in file_details) and (file_details["file_size"] is not None):
			if file_details["file_size"]:
				try:
					file_size = int(file_details["file_size"])
					if file_size < 0:
						return {"args": None, "err": "FILE SIZE SHOULD NOT LESS THAN 0 BYTE."}
				except ValueError:
					return {"args": None, "err": "FILE SIZE SHOULD BE INTEGER."}                
			else:
				return {"args": None, "err": "FILE SIZE SHOULD NOT BE EMPTY."}
		else:
			return {"args": None, "err": "MISSING FILE SIZE INFORMATION."} 

		# Each file chunk size should be provided and should be interger (or should able to convert to integer).
		if ("chunk_size" in file_details) and (file_details["chunk_size"] is not None):
			if file_details["chunk_size"]:
				try:
					chunk_size = int(file_details["chunk_size"])
					if chunk_size < 0:
						return {"args": None, "err": "CHUNK SIZE SHOULD NOT LESS THAN 0 BYTE."}
				except ValueError:
					return {"args": None, "err": "CHUNK SIZE SHOULD BE INTEGER."}                
			else:
				return {"args": None, "err": "CHUNK SIZE SHOULD NOT BE EMPTY."}
		else:
			return {"args": None, "err": "MISSING CHUNK SIZE INFORMATION."} 

		# Each file redundancy should be provided and should be interger (or should able to convert to integer).
		if ("redundancy" in file_details) and (file_details["redundancy"] is not None):
			if file_details["redundancy"]:
				try:
					redundancy = int(file_details["redundancy"])
					if redundancy < 0:
						return {"args": None, "err": "REDUNDANCY SHOULD NOT LESS THAN 0."}
				except ValueError:
					return {"args": None, "err": "REDUNDANCY SHOULD BE INTEGER."}                
			else:
				return {"args": None, "err": "REDUNDANCY SHOULD NOT BE EMPTY."}
		else:
			return {"args": None, "err": "MISSING REDUNDANCY INFORMATION."} 

		# File root hash should be provided and should be 32-byte hex string. 
		if ("root_hash" in file_details) and (file_details["root_hash"] is not None):
			if file_details["root_hash"]:
				root_hash_raw = file_details["root_hash"]
				is_valid_hash = self.is_valid_hash(root_hash_raw)
				if is_valid_hash["is_valid"]:
					root_hash = is_valid_hash["hash_value"]
				else:
					return {"args": None, "err": is_valid_hash["hash_value"]}
			else: 
				return {"args": None, "err": "FILE ROOT HASH SHOULD NOT BE EMPTY."}
		else:
			return {"args": None, "err": "MISSING FILE ROOT HASH."}  

		# File chunks list should be provided but can be empty.
		file_chunks = []
		if ("file_chunks" in file_details) and (file_details["file_chunks"] is not None):
			if isinstance(file_details["file_chunks"], list): 
				try:
					file_chunks_raw = file_details["file_chunks"]
					for chunk_obj in file_chunks_raw:
						is_valid_hash = self.is_valid_hash(chunk_obj["chunk_hash"])
						if is_valid_hash["is_valid"]:
							chunk_hash = chunk_obj["chunk_hash"]
						else: 
							return {"args": None, "err": is_valid_hash["hash_value"]}
						
						is_valid_uuid = self.is_valid_uuid(chunk_obj["node_id"])
						if is_valid_uuid:
							node_id = chunk_obj["node_id"]
						else: 
							return {"args": None, "err": "NODE ID IS NOT VALID UUID."}
						file_chunks.append([chunk_hash, node_id])
				except:
					return {"args": None, "err": "ERROR WHEN PARSING THE FILE CHUNK DETAILS."}
			else: 
				return {"args": None, "err": "FILE CHUNKS SHOULD BE PROVIDED IN THE FORM OF A LIST."}
		else:
			return {"args": None, "err": "MISSING FILE CHUNKS INFORMATION."}

		args = [
			file_name,
			file_size,
			chunk_size,
			redundancy,
			root_hash,
			file_chunks
		]
		return {"args": args, "err": None}


	def node_preprocess(self, node_json):
		'''
		Purpose: Pre-check the provided node details before making the transaction. 
		Input: Node details including node ID, net address, communication protocol, port info.
		Output: Argument list for calling corresponding smart contract function + Error message.
		'''
		node_details = json.loads(node_json)

		# =========== NODE PRE-PRECESSING ===========
		# Node ID should be provided and should not be empty string and should be uuid.
		if ("node_id" in node_details) and (node_details["node_id"] is not None):
			if node_details["node_id"]:
				if self.is_valid_uuid(node_details["node_id"]):
					node_id = node_details["node_id"]
				else:
					return {"args": None, "err": "NODE ID IS NOT VALID UUID."}
			else: 
				return {"args": None, "err": "NODE ID SHOULD NOT BE EMPTY."}
		else:
			return {"args": None, "err": "MISSING NODE ID INFORMATION."}
		
		# IP address should be provided and should not be empty string.
		if ("ip_address" in node_details) and (node_details["ip_address"] is not None):
			if node_details["ip_address"]:
				ip_address = node_details["ip_address"] 
			else: 
				return {"args": None, "err": "IP ADDRESS SHOULD NOT BE EMPTY."}
		else:
			return {"args": None, "err": "MISSING IP ADDRESS INFORMATION."}
		
		# Domain should be provided, but it can be empty.
		if ("domain" in node_details) and (node_details["domain"] is not None):
			domain = node_details["domain"] if node_details["domain"] else ""
		else:
			return {"args": None, "err": "MISSING NET ADDRESS INFORMATION."}
		
		# Protocol must be one of 3 values: 0(TCP), 1(UDP) or 2(Others).
		if ("protocol" in node_details) and (node_details["protocol"] is not None):
			if node_details["protocol"] in range(3):
				protocol = node_details["protocol"] 
			else: 
				return {"args": None, "err": " INVALID PROTOCOL INFORMATION (MUST BE 0[TCP], 1[UDP] or 2[OTHERS])."}
		else:
			return {"args": None, "err": "MISSING PROTOCOL INFORMATION."}

		# Port number should be provided and should be integer (or should able to convert to integer).
		# Port number range (1, 65535).
		if ("port" in node_details) and (node_details["port"] is not None):
			if node_details["port"]:
				try:
					port = int(node_details["port"])
					if port < 1 or port > 65535:
						return {"args": None, "err": "PORT NUMBER SHOULD BE IN RANGE (1, 65535)."}
				except ValueError:
					return {"args": None, "err": "PORT NUMBER SHOULD BE INTEGER."}
			else:
				return {"args": None, "err": "PORT NUMBER SHOULD NOT BE EMPTY."}
		else:
			return {"args": None, "err": "MISSING PORT NUMBER INFORMATION."}

		args = [
			node_id,
			ip_address,
			domain,
			protocol,
			port
		]
		return {"args": args, "err": None}


	def generate_receipt(self, raw_receipt):
		'''
		Purpose: Generate the developer-friendly receipt for better debugging process.
		Input: Raw transaction receipt return from chain. 
		Output: Receipt with most common used data. 
		'''
		gas_price = raw_receipt["effectiveGasPrice"] * 10**(-9) # Unit in Gwei
		transaction_fee = raw_receipt["effectiveGasPrice"] * raw_receipt["gasUsed"] * 10**(-18) # Unit in ETH

		receipt = {
			"status": raw_receipt["status"],
			"transaction_hash": raw_receipt["transactionHash"],
			"transaction_fees": transaction_fee,
			"gas_price:": gas_price,
			"gas_used": raw_receipt["gasUsed"],
		}
		return receipt


	def sign_transaction(self, func_name, func_args):
		'''
		Purpose: A generic function for signing a transaction (for write function).
		Input: Function name to be invoked and required function arguments.
		Output: Transaction receipt with information like transaction status. 
		'''
		# Define function name and required arguments.
		function_name = func_name
		function_args = func_args

		# Build transaction.
		nonce = self.w3.eth.get_transaction_count(os.getenv("WALLET_PUBLIC_ADDRESS"))
		gas_price = self.w3.eth.gas_price

		encoded_data = self.contract.encodeABI(fn_name=function_name, args=function_args)

		tx = self.contract.functions[function_name](*function_args).build_transaction({
			"nonce": nonce,
			'gasPrice': gas_price,
			'from': os.getenv("WALLET_PUBLIC_ADDRESS")   
		})

		tx['gas'] = self.w3.eth.estimate_gas(tx)
		private_key = os.getenv("WALLET_PRIVATE_KEY")

		# Sign and send the transaction. 
		signed_function = self.w3.eth.account.sign_transaction(tx, private_key=private_key)
		tx_hash = self.w3.eth.send_raw_transaction(signed_function.rawTransaction)
		tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

		# Generate transaction receipt.
		receipt = self.generate_receipt(tx_receipt)
		return receipt
 

	def is_file_exists(self, root_hash):
		'''
		Input: File root hash.
		Output: Return True if file exists, otherwise false.
		'''
		is_exists = self.contract.functions.fileExists(root_hash).call({
			"from": os.getenv("WALLET_PUBLIC_ADDRESS")
		})

		return is_exists


	def list_file(self):
		'''
		Input: None
		Output: The metadata of all files that current address owns.
		'''
		raw_list_file = self.contract.functions.listFiles().call({
			"from": os.getenv("WALLET_PUBLIC_ADDRESS")
		})

		list_file = []
		for f in raw_list_file:
			file = {}
			file["owner"] = f[0]
			file["file_name"] = f[1]
			file["file_size"] = f[2]
			file["chunk_size"] = f[3]
			file["redundancy"] = f[4]
			file["root_hash"] = f[5].hex()
			file["file_chunk_count"] = f[6]

			file["file_chunks"] = []
			for c in f[7]:
				chunk = {}
				chunk["chunk_hash"] = c[0].hex()
				chunk["node_id"] = c[1]
				file["file_chunks"].append(chunk)

			list_file.append(file)

		list_file_json = json.dumps(list_file)
		return list_file_json


	def list_all_file(self):
		'''
		Input: None
		Output: The metadata of all files that current address owns.
		Restriction: Only authorized addresses are able to call this function.
		'''
		raw_list_file = self.contract.functions.listAllFiles().call({
			"from": os.getenv("WALLET_PUBLIC_ADDRESS")
		})

		list_file = []
		for f in raw_list_file:
			file = {}
			file["owner"] = f[0]
			file["file_name"] = f[1]
			file["file_size"] = f[2]
			file["chunk_size"] = f[3]
			file["redundancy"] = f[4]
			file["root_hash"] = f[5].hex()
			file["file_chunk_count"] = f[6]

			file["file_chunks"] = []
			for c in f[7]:
				chunk = {}
				chunk["chunk_hash"] = c[0].hex()
				chunk["node_id"] = c[1]
				file["file_chunks"].append(chunk)

			list_file.append(file)


	def upload_file(self, file_json):  
		'''
		Input: File details including file name, file size, chunk size, redundancy, file root hash, file chunks info.
		Output: Transaction receipt with information such as transaction status (Success=1, Fail=0), or error message string if any.
		'''
		process_status = self.file_preprocess(file_json)
		if process_status["args"] is not None: 
			receipt = self.sign_transaction("addFile", process_status["args"])
			if receipt["status"] == 1:
				return {"status": 1, "receipt": receipt}
			else:
				return {"status": 0, "receipt": receipt}
		else:
			return {"status": 0, "receipt": process_status["err"]}
 

	def retrieve_file(self, root_hash):
		'''
		Input: File root hash.
		Return: Metadata for that file.
		'''
		# Check return value to see if file exist.
		raw_retrieved_file = self.contract.functions.getFile(root_hash).call({
			"from": os.getenv("WALLET_PUBLIC_ADDRESS")
		})

		retrieved_file = {}
		retrieved_file["owner"] = raw_retrieved_file[0]
		retrieved_file["file_name"] = raw_retrieved_file[1]
		retrieved_file["file_size"] = raw_retrieved_file[2]
		retrieved_file["chunk_size"] = raw_retrieved_file[3]
		retrieved_file["redundancy"] = raw_retrieved_file[4]
		retrieved_file["root_hash"] = raw_retrieved_file[5].hex()
		retrieved_file["file_chunk_count"] = raw_retrieved_file[6]

		retrieved_file["file_chunks"] = []
		for c in raw_retrieved_file[7]:
			chunk = {}
			chunk["chunk_hash"] = c[0].hex()
			chunk["node_id"] = c[1]
			retrieved_file["file_chunks"].append(chunk)
		
		retrieved_file_json = json.dumps(retrieved_file)
		return retrieved_file_json

	
	def update_file(self, file_update_json):
		'''
		Purpose: This function is not used to update the file content, but update the node Id where the file chunk stored.
		Input: Updated file details including origianl file root hash, new file name, and updated file chunks list (Chunk hash : Node Id).
		Output: Transaction receipt with information such as transaction status (Success=1, Fail=0), or error message string if any.
		'''
		process_status = self.file_preprocess(file_update_json)
		if process_status["args"] is not None:

			# Raw structure: [key, file_name, file_size, root_hash, file_chunks[]].
			raw_args = process_status["args"]

			# Reconstruct argument list: [root_hash, file_name, file_chunks[]].
			args = [
				raw_args[3], 
				raw_args[1], 
				raw_args[4]
			]

			receipt = self.sign_transaction("updateFile", args)

			if receipt["status"] == 1:
				return {"status": 1, "receipt": receipt}
			else:
				return {"status": 0, "receipt": receipt}
		else:
			return {"status": 0, "receipt": process_status["err"]} 


	def remove_file(self, root_hash):  
		'''
		Input: File root hash.
		Output: Transaction receipt with information such as transaction status (Success=1, Fail=0).
		'''
		receipt = self.sign_transaction("removeFile", [root_hash])
		if receipt["status"] == 1:
			return {"status": 1, "receipt": receipt}
		else:
			return {"status": 0, "receipt": receipt}


	def is_node_exists(self, node_id):
		'''
		Input: Node ID (Valid UUID).
		Output: Return -1: UUID invalid, 1: node exists, 0: node not exists.
		'''
		is_valid = self.is_valid_uuid(node_id)
		if is_valid:
			is_exists = self.contract.functions.nodeExists(node_id).call({
				"from": os.getenv("WALLET_PUBLIC_ADDRESS")
			})

			if is_exists:
				return {"is_exists": 1, "err": None}
			else:
				return {"is_exists": 0, "err": None}
		else:
			return {"is_exists": -1, "err": "INVALID UUID"}


	def list_nodes(self):
		'''
		Input: None
		Output: The information of all available nodes.
		'''
		raw_list_node = self.contract.functions.listNodes().call({
			"from": os.getenv("WALLET_PUBLIC_ADDRESS")
		})

		list_node = []
		for n in raw_list_node:
			node = {}
			node["node_id"] = n[0]
			node["ip_address"] = n[1]
			node["domain"] = n[2]
			node["protocol"] = n[3]
			node["port"] = n[4]
			node["owner"] = n[5]
			list_node.append(node)

		list_node_json = json.dumps(list_node)
		return list_node_json
		

	def add_node(self, node_json):  
		'''
		Input: Node details including node ID, IP address, net address, communication protocol, port info.
		Output: Transaction receipt with information such as transaction status (Success=1, Fail=0), or error message string if any.
		'''
		process_status = self.node_preprocess(node_json)
		if process_status["args"] is not None: 
			receipt = self.sign_transaction("addNode", process_status["args"])
			if receipt["status"] == 1:
				return {"status": 1, "receipt": receipt}
			else:
				return {"status": 0, "receipt": receipt}
		else:
			return {"status": 0, "receipt": process_status["err"]}

	
	def get_node(self, node_id):
		'''
		Input: Node ID
		Output: Node information
		'''
		raw_node = self.contract.functions.getNode(node_id).call({
			"from": os.getenv("WALLET_PUBLIC_ADDRESS")
		})

		node = {}
		node["node_id"] = raw_node[0]
		node["ip_address"] = raw_node[1]
		node["domain"] = raw_node[2]
		node["protocol"] = raw_node[3]
		node["port"] = raw_node[4]
		node["owner"] = raw_node[5]

		node_json = json.dumps(node)
		return node_json


	def remove_node(self, node_id):  
		'''
		Input: Node id.
		Output: Transaction receipt with information such as transaction status (Success=1, Fail=0).
		'''
		receipt = self.sign_transaction("removeNode", [node_id])
		if receipt["status"] == 1:
			return {"status": 1, "receipt": receipt}
		else:
			return {"status": 0, "receipt": receipt}

	
	def merkle_proof(self, root_hash, leaf_hash, index):
		'''
		Input: File root hash, chunk hash, and the index of the chunk.
		Output: Boolean value inform whether the proof provided matches the root hash or not. 
		'''
		args = [root_hash, leaf_hash, index]

		raw_proof_result = self.contract.functions.performMerkleProof(args).call({
			"from": os.getenv("WALLET_PUBLIC_ADDRESS")
		})
		
		proof_result = json.dumps(raw_proof_result)
		return proof_result


if __name__ == '__main__':
	conn = Connector()
	
	# ============= FILE ============
	# Retrieve all files:
	# receipt = conn.list_all_file()
	
	# Upload file:
	# receipt = conn.upload_file('{"file_name": "Cloud", "file_size": "100", "root_hash": "0x52f215a01392f27cb930d13954f402a798cb63b67fa88a3d3a9c3649af10dc8b", "file_chunks": [{"chunk_hash":"0x5808f6d31f38b0557f3e0d3c3a3ec1e0e57f0ee9b31d1ab2662b2f16b47b0565", "node_id": "5338d5e4-6f3e-45fe-8af5-e2d96213b3f0"},{"chunk_hash":"0x5f5bb5f5e0648b04988ec1dd0c157a90a79871a8c31bf170d94c33a7f62fb955", "node_id": "e46b3dc7-11f2-4b9c-8693-3eae76c03735"}]}')
	
	# Get single file:
	# receipt = conn.retrieve_file("0x7f2c17a8d7e82fc0aefb7d9a03761d72bfe31f92879e63f1bc6b3a3d2f6b1d6c")

	# Update exist file chunk - node information:
	# receipt = conn.update_file('{"file_name": "Iris", "file_size": "31", "root_hash": "0x8f2c17a8d7e82fc0aefb7d9a03761d72bfe31f92879e63f1bc6b3a3d2f6b1d6f", "file_chunks": [{"chunk_hash":"0x5f2c17a8d7e82fc0aefb7d9a03761d72bfe31f91879e63f1bc6b3a3d2f6b1d61", "node_id": "13"}]}')

	# Remove specific file:
	# receipt = conn.remove_file(["0x8f2c17a8d7e82fc0aefb7d9a03761d72bfe31f92879e63f1bc6b3a3d2f6b1d6f"])

	# Check if file exist:
	#receipt = conn.is_file_exists("0x52f215a01392f27cb930d13954f402a798cb63b67fa88a3d3a9c3649af10dc8b")

	# ============= NODE ============
	# Check valid UUID:
	# receipt = conn.is_valid_uuid("xx38d5e4-6f3e-45fe-8af5-e2d96213b3f0")

	# Node info precheck:
	# receipt = conn.node_preprocess('{"node_id": "d0cfa1b4-4f9b-4bb8-bb24-16c86b15f135", "ip_address": "8.8.8.8", "domain": "JK", "protocol": 0, "port": "2"}')
	
	# Check if node exist:
	receipt = conn.is_node_exists("5338d5e4-6f3e-45fe-8af5-e2d96213b3f0")
	# All active nodes:
	# receipt = conn.list_nodes()

	# Add new node:
	# receipt = conn.add_node('{"node_id": "d0cfa1b4-4f9b-4bb8-bb24-16c86b15f135", "ip_address": "8.8.8.8", "domain": "JK", "protocol": 0, "port": "2"}')
	
	# Get single node:
	# receipt = conn.get_node("d0cfa1b4-4f9b-4bb8-bb24-16c86b15f135")

	# Remove node:
	#receipt = conn.remove_node("d0cfa1b4-4f9b-4bb8-bb24-16c86b15f135")
	
	print(receipt)

'''
Valid UUID: 
	5338d5e4-6f3e-45fe-8af5-e2d96213b3f0,
	d0cfa1b4-4f9b-4bb8-bb24-16c86b15f135,
	e46b3dc7-11f2-4b9c-8693-3eae76c03735,
	913c8e8a-5c5a-435d-9dc5-30b8cc7c140e,


Invalid UUID: xx38d5e4-6f3e-45fe-8af5-e2d96213b3f0


Root hash pool:
	0x52f215a01392f27cb930d13954f402a798cb63b67fa88a3d3a9c3649af10dc8b
	0x5808f6d31f38b0557f3e0d3c3a3ec1e0e57f0ee9b31d1ab2662b2f16b47b0565
	0x5f5bb5f5e0648b04988ec1dd0c157a90a79871a8c31bf170d94c33a7f62fb955
'''

