// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

library MerkleProof {
    function verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf,
        uint256 index
    ) internal pure returns (bool) {
        bytes32 hash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            if(proof[i] != bytes32(0)){
                bytes32 proofElement = proof[i];

                if (index % 2 == 0) {
                    hash = keccak256(abi.encodePacked(hash, proofElement));
                } else {
                    hash = keccak256(abi.encodePacked(proofElement, hash));
                }
            }
            index = index / 2;
        }

        return hash == root;
    }

    function buildProof(bytes32[] memory _merkleTree, uint256 index, uint256 _chunkLength) internal pure returns (bytes32[] memory) {
        uint256 len = 0;
        uint256 tempChunkLength = _chunkLength;
        while (tempChunkLength / 2 > 0) {
            len++;
            tempChunkLength = tempChunkLength / 2 + tempChunkLength % 2;
        }
        
        bytes32[] memory _proof = new bytes32[](len);
        uint256 base = 0;
        uint256 proofIndex = 0;
        while (index < _merkleTree.length-1) {
            if ((index - base) % 2 == 0 && index - base < _chunkLength - 1) {
                _proof[proofIndex] = _merkleTree[index+1];
                proofIndex++;
            }
            else if ((index - base) % 2 != 0){
                _proof[proofIndex] = _merkleTree[index-1];
                proofIndex++;
            }
            else {
                _proof[proofIndex] = bytes32(0);
                proofIndex++;
            }
            index = (index - base) / 2 + base + _chunkLength;
            base = base + _chunkLength;
            _chunkLength = _chunkLength / 2 + _chunkLength % 2;
        }
        return _proof;
    }
}