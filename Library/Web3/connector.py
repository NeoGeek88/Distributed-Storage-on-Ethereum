from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from dotenv import load_dotenv
import os
import json

class Connector:
    def __init__(self):
        # Load the environment variables from the .env file.
        # TODO: might not need .env in the future i guesss
        load_dotenv("./.env")

        # Connect to the Ethereum blockchain via remote node provider.
        self.w3 = Web3(Web3.HTTPProvider(os.getenv("INFURA_NODE_ENDPOINT")))

        # Load the contract ABI and contract address.
        with open('./Contract/contract_abi.json', 'r') as f: 
            contract_abi = json.load(f)
        
        contract_address = os.getenv("CONTRACT_ADDRESS")
        self.contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)  

    def file_preprocess(self, file_json):
        '''
        PURPOSE: Pre-check provided file details before making the transaction. 
        INPUT: File details including file name, file size, file root hash, file chunks info.
        RETURN: Argument list for calling corresponding smart contract function + .
        # TODO: return an object contains arguemnet list + error 
        # TODO: another function for root hash checking
        {args: [], err: string}
        {args: '', err: }
        '''
        file_details = json.loads(file_json)

        # =========== FILE PRE-PRECESSING ===========
        # File name should be provided and should not be empty string.
        if ("file_name" in file_details) and (file_details["file_name"] is not None):
            if file_details["file_name"]:
                file_name = file_details["file_name"] 
            else: 
                return "message: file name should not be empty."
        else:
            return "message: missing file name info."

        # File size should be provided and should be integer (or should able to convert to integer).
        if ("file_size" in file_details) and (file_details["file_size"] is not None):
            if file_details["file_size"]:
                if isinstance(file_details["file_size"], int):
                    file_size = file_details["file_size"]
                else:
                    try:
                        file_size = int(file_details["file_size"])
                        if file_size < 0:
                            return "message: file size should not less than 0 byte."
                    except ValueError:
                        return "message: file size should be intger."
            else:
                return "message: file fize should not be empty."
        else:
            return "message: missing file size info."

        # File root hash should be provided and should be 32-byte hex string. 
        if ("root_hash" in file_details) and (file_details["root_hash"] is not None):
            if file_details["root_hash"]:
                root_hash_raw = file_details["root_hash"]
                if not root_hash_raw.startswith("0x"):
                    root_hash_raw = "0x" + root_hash_raw
                if len(root_hash_raw) != 66:
                    return "message: provided root hash string is not 32-byte."
                try:
                    root_hash_int = int(root_hash_raw, 16)
                    root_hash = hex(root_hash_int)
                except ValueError:
                    return "message: can not convert provided root hash string to hex."
            else: 
                return "message: file root hash should not be empty."
        else:
            return "message: missing file root hash."

        # File chunks list should be probvided and at least one chunk present.
        file_chunks = []
        if ("file_chunks" in file_details) and (file_details["file_chunks"] is not None):
            if (file_details["file_chunks"]) and (isinstance(file_details["file_chunks"], list)): 
                try:
                    file_chunks_raw = file_details["file_chunks"]
                    for chunk_obj in file_chunks_raw:
                        for k, v in chunk_obj.items():
                            file_chunks.append([k,v])
                except:
                    return "message: Error when parsing the file chunk details."
            else: 
                return "message: file chunks list should be provided and should not be empty."
        else:
            return "message: missing file chunks."

        args = [
            file_name,
            file_size,
            root_hash,
            file_chunks
        ]
        return args


    def generate_receipt(self, raw_receipt):
        '''
        INPUT: Raw transaction receipt return from chain. 
        RETURN: Receipt with most common used data. 
        '''
        gas_price = raw_receipt["effectiveGasPrice"] * 10**(-9) # Gwei
        transaction_fee = raw_receipt["effectiveGasPrice"] * raw_receipt["gasUsed"] * 10**(-18) # ETH

        receipt = {
            "status": raw_receipt["status"],
            "transaction_hash": raw_receipt["transactionHash"],
            "transaction_fees": transaction_fee,
            "gas_price:": gas_price,
            "gas_used": raw_receipt["gasUsed"],
        }
        return receipt

    def list_file(self):
        '''
        RETRUN: The metadata of all files that current address owns
        '''
        raw_list_file = self.contract.functions.listFiles().call({
            "from": os.getenv("WALLET_PUBLIC_KEY")
        })

        list_file = []
        for f in raw_list_file:
            file = {}
            file["owner"] = f[0]
            file["file_name"] = f[1]
            file["file_size"] = f[2]
            file["root_hash"] = f[3].hex()
            file["file_chunk_count"] = f[4]

            #file_chunks = f[5]
            file["file_chunks"] = []
            for c in f[5]:
                chunk = {}
                chunk["chunk_hash"] = c[0].hex()
                chunk["node_id"] = c[1]
                file["file_chunks"].append(chunk)
            list_file.append(file)
        list_file_json = json.dumps(list_file)
        print(list_file_json) # del later
        return list_file_json


    def upload_file(self, file_json):  
        '''
        INPUT: file details including file name, file size, file root hash, file chunks info.
        RETURN: transaction receipt with status (upload succeed or error code & msg). 
        # TODO: consider transaction not included in the chain
        '''
        args = self.file_preprocess(file_json)

        function_name = 'addFile'
        function_args = args
        nonce = self.w3.eth.get_transaction_count(os.getenv("WALLET_PUBLIC_KEY"))
        gas_price = self.w3.eth.gas_price
        tx = self.contract.functions[function_name](*function_args).build_transaction({
            'nonce': nonce,
            'gasPrice': gas_price,
            'from': os.getenv("WALLET_PUBLIC_KEY")
        })
        tx['gas'] = self.w3.eth.estimate_gas(tx)
        private_key = os.getenv("WALLET_PRIVATE_KEY")

        # Sign and send the transaction. 
        signed_function = self.w3.eth.account.sign_transaction(tx, private_key=private_key)
        #tx_hash = self.w3.eth.send_raw_transaction(signed_function.rawTransaction)
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        recepit = self.generate_receipt(tx_receipt)
        print(recepit)
        return recepit


    def retrieve_file(self, root_hash):
        '''
        INPUT: File root hash.
        RETURN: File metadata.
        '''
        raw_retrieved_file = self.contract.functions.getFile(root_hash).call({
            "from": os.getenv("WALLET_PUBLIC_KEY")
        })

        retrieved_file = {}
        retrieved_file["owner"] = raw_retrieved_file[0]
        retrieved_file["file_name"] = raw_retrieved_file[1]
        retrieved_file["file_size"] = raw_retrieved_file[2]
        retrieved_file["root_hash"] = raw_retrieved_file[3].hex()
        retrieved_file["file_chunk_count"] = raw_retrieved_file[4]

        retrieved_file["file_chunks"] = []
        for c in raw_retrieved_file[5]:
            chunk = {}
            chunk["chunk_hash"] = c[0].hex()
            chunk["node_id"] = c[1]
            retrieved_file["file_chunks"].append(chunk)
        
        retrieved_file_json = json.dumps(retrieved_file)
        return retrieved_file_json


# Create an Ethereum account 
# TODO: auth via metamask 
# TODO: window.ethereum object!!!

'''
# TODO: Get transaction error, if fails.      
'''

if __name__ == '__main__':
    conn = Connector()
    #conn.retrieve_file("0x7f2c17a8d7e82fc0aefb7d9a03761d72bfe31f92879e63f1bc6b3a3d2f6b1d6c")

    err = conn.upload_file('{"file_name": "s", "file_size": "12", "root_hash": "0x7f2c17a8d7e82fc0aefb7d9a03761d72bfe31f92879e63f1bc6b3a3d2f6b1d6c", "file_chunks": [{"0x7f2c17a8d7e82fc0aefb7d9a03761d72bfe31f92879e63f1bc6b3a3d2f6b1d6c":"01"},{"0x7f2c17a8d7e82fc0aefb7d9a03761d72bfe31f92879e63f1bc6b3a3d2f6b1d6c": "02"}]}')
    
    #print(err)
    #conn.list_file()
    # if file_details["file_name"]:
      #      else: return "message: file ane should not be empty!"
