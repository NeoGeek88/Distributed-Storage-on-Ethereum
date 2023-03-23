from web3 import Web3, EthereumTesterProvider


class MerkleTree:

    def __init__(self, chunk_list):
        self.merkle_tree = self.build_merkle_tree(chunk_list)

    '''
    Perform keccak256 hash method same as Solidity function
    INPUT: data to be hashed and the data type (it should always be 'bytes' for smart contract)
    OUTPUT: HexBytes with length of 32.
    '''
    def keccak256(self, bin, type):
        w3 = Web3(EthereumTesterProvider)
        hash_hex = w3.solidity_keccak([type], [bin])
        return hash_hex

    '''
    Build the merkle tree with all intermediate hash values for further process
    INPUT: the chunk list of a file (extracted from the smart contract)
    OUTPUT: an array of HexBytes including all leaf hash and intermediate hash values
    '''
    def build_merkle_tree(self, chunk_list):
        tree = []
        for chunk in chunk_list:
            #tree.append(self.keccak256(chunk, 'string'))
            tree.append(bytes.fromhex(chunk.chunk_hash[2:]))

        n = len(tree)
        offset = 0

        while n > 1:
            for i in range(0, n-1, 2):
                test = tree[offset+i] + tree[offset+i+1]
                tree.append(self.keccak256(tree[offset+i] + tree[offset+i+1], 'bytes'))
            if n % 2 != 0:
                tree.append(tree[offset+n-1])
            offset += n
            n = int(n / 2) + n % 2

        return tree

    '''
    Build the proof array to be send to the smart contract for Merkle Proof function
    INPUT: the index of the chunk to be proofed, and the total number of chunks (length)
    OUTPUT: the array including all the necessary hashes for the Merkle Proof
    '''
    def build_proof(self, index, length):
        proof = []
        base = 0
        while index < len(self.merkle_tree)-1:
            if (index - base) % 2 == 0:
                proof.append(self.merkle_tree[index+1])
            else:
                proof.append(self.merkle_tree[index-1])
            index = int((index - base) / 2) + base + length
            base = base + length
            length = int(length / 2) + length % 2
        #proof.append(tree[len(tree)-1])
        return proof

    '''
    Test function, same as the one in the smart contract
    '''
    def verify(self, proof, root, leaf, index):
        hash = bytes.fromhex(leaf[2:])
        
        for i in range(len(proof)):
            proofElement = proof[i]
            if index % 2 == 0:
                hash = self.keccak256(hash + proofElement, 'bytes')
            else:
                hash = self.keccak256(proofElement + hash, 'bytes')
            index = int(index / 2)

        #print(hash.hex())
        #print(root)
        return hash.hex() == root

#chunk_list = ["wefewf","wfwfe","wqr","2e1r","3fw","2e213ef","32rwf"]
#mt = MerkleTree(chunk_list)
#tree = merkle_tree.build_merkle_tree(chunk_list)
#print(mt.merkle_tree)
#proof = mt.build_proof(3, 7)
#print(proof)
#result = mt.verify(proof, '0x7ebd327486284003019a45093a555a9e62a7df2dadf74a658421a4b59a509a3d', '0x453e71bbe39e6e5a7af4304085460339733da38eb14bcffc9e603f227a2ac49a', 3)
#print(result)
