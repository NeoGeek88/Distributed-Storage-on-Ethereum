// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// provide _msgSender() and _msgData
import "@openzeppelin/contracts/utils/Context.sol";

// provide _owner
import "@openzeppelin/contracts/access/Ownable.sol";

// provide MerkleProof
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract DS is Context, Ownable {
    
    // File chunk structure, used inside the File structure.
    struct FileChunk{
        string chunkHash;
        string nodeId;
    }
    // File metadata structure.
    struct File{
        address owner;
 		string fileName;
        uint256 fileSize;
        string rootHash;
        uint256 fileChunkCount;
        FileChunk[] fileChunks;
    }
    
    // Mapping for file owner to all its files. 
    mapping(address => string[]) private _fileMapping;
    // Mapping the root hash of a file to its metadata.
    mapping(string => File) private _fileList;

    /**
     * Modifier to determine if the address is the file owner.
     */
    modifier isFileOwner(string memory _rootHash) {
        require(_fileList[_rootHash].owner == _msgSender(), "You don't have access to this file");
        _;
    }

    /*
     * Add new file and associate it with the owner via mapping (everyone can execute this function).
     */
    function addFile(string memory _fileName, uint256 _fileSize, string memory _rootHash, FileChunk[] memory _fileChunks) public returns(bool) {
        _fileList[_rootHash].owner = _msgSender();
        _fileList[_rootHash].fileName = _fileName;
        _fileList[_rootHash].fileSize = _fileSize;
        _fileList[_rootHash].rootHash = _rootHash;
        _fileList[_rootHash].fileChunkCount = _fileChunks.length;
        for (uint i=0; i<_fileChunks.length; i++){
            _fileList[_rootHash].fileChunks.push(_fileChunks[i]);
        }
        _fileMapping[_msgSender()].push(_rootHash);
        return true;
    }

    /*
     * Retrieve information of all files owned by this address and return. 
     */
    function listFiles() public view returns(File[] memory) {
        File memory file;
        File[] memory files = new File[](_fileMapping[_msgSender()].length);
        for (uint i=0; i<_fileMapping[_msgSender()].length; i++) {
            file = _fileList[_fileMapping[_msgSender()][i]];
            files[i] = file;
        }
        return files;
    }

    /*
     * Retrive single file information from owner's file list. (only file owner is allowed to execute this function).
     */
    function getFile(string memory _rootHash) public view returns(File memory) {
        require(_fileList[_rootHash].owner == _msgSender(), "You don't have access to this file");
        return _fileList[_rootHash];
    }

    function removeFile(string memory _rootHash) public isFileOwner(_rootHash) returns(bool) {
        for (uint i = 0; i < _fileMapping[_msgSender()].length; i++) {
            bytes32 storageHash = keccak256(abi.encodePacked(_fileMapping[_msgSender()][i]));
            bytes32 memoryHash = keccak256(abi.encodePacked(_rootHash));
            if (storageHash == memoryHash) {
                deleteFileMappingByIndex(i);
                break;
            }
        }
        delete _fileList[_rootHash];
        return true;
    }

    function checkFileList(string memory _rootHash) public view returns (File memory) {
        return _fileList[_rootHash];
    }

    /*
     * Util function to delete a value at 'index' from an array.
     */
    function deleteFileMappingByIndex(uint index) private {
        require(index < _fileMapping[_msgSender()].length, "Index out of bounds");
        
        for (uint i = index; i < _fileMapping[_msgSender()].length-1; i++) {
            _fileMapping[_msgSender()][i] = _fileMapping[_msgSender()][i+1];
        }
        
        _fileMapping[_msgSender()].pop();
    }

    // a set of possible porotocol type.
    enum protocol{
        TCP,
        UDP,
        OTHER
    }

    // Node information structure.
    struct Node{
        string nodeId;
        string ipAddress;
        string netAddress;
        protocol protocol;
        uint256 port;
        address owner;
    }

    // Mapping for node owner to all its nodes.
    mapping(address => string[]) private _nodeMapping;
    // Mapping the node ID to its information.
    mapping(string => Node) private _nodeList;

    /**
     * Modifier to determine if the address is the node owner.
     */
    modifier isNodeOwner(string memory _nodeId) {
        require(_nodeList[_nodeId].owner == _msgSender(), "You don't have access to this node");
        _;
    }

    /*
     * Add new file and associate it with the owner via mapping (everyone can execute this function).
     */
    function addNode(string memory _nodeId, string memory _ipAddress, string memory _netAddress, protocol _protocol, uint256 _port) public returns(bool) {
        _nodeList[_nodeId].owner = _msgSender();
        _nodeList[_nodeId].nodeId = _nodeId;
        _nodeList[_nodeId].ipAddress = _ipAddress;
        _nodeList[_nodeId].netAddress = _netAddress;
        _nodeList[_nodeId].protocol = _protocol;
        _nodeList[_nodeId].port = _port;
        _nodeMapping[_msgSender()].push(_nodeId);
        return true;
    }

    /*
     * Retrieve information of all files owned by this address and return. 
     */
    function listNodes() public view returns(Node[] memory) {
        Node memory node;
        Node[] memory nodes = new Node[](_nodeMapping[_msgSender()].length);
        for (uint i=0; i<_nodeMapping[_msgSender()].length; i++) {
            node = _nodeList[_nodeMapping[_msgSender()][i]];
            nodes[i] = node;
        }
        return nodes;
    }

    /*
     * Retrive single file information from owner's file list. (only file owner is allowed to execute this function).
     */
    function getNode(string memory _nodeId) public view returns(Node memory) {
        require(_nodeList[_nodeId].owner == _msgSender(), "You don't have access to this node");
        return _nodeList[_nodeId];
    }

    function removeNode(string memory _nodeId) public isNodeOwner(_nodeId) returns(bool) {
        for (uint i = 0; i < _nodeMapping[_msgSender()].length; i++) {
            bytes32 storageHash = keccak256(abi.encodePacked(_nodeMapping[_msgSender()][i]));
            bytes32 memoryHash = keccak256(abi.encodePacked(_nodeId));
            if (storageHash == memoryHash) {
                deleteNodeMappingByIndex(i);
                break;
            }
        }
        delete _nodeList[_nodeId];
        return true;
    }

    function checkNodeList(string memory _nodeId) public view returns (Node memory) {
        return _nodeList[_nodeId];
    }

    /*
     * Util function to delete a value at 'index' from an array.
     */
    function deleteNodeMappingByIndex(uint index) private {
        require(index < _nodeMapping[_msgSender()].length, "Index out of bounds");
        
        for (uint i = index; i < _nodeMapping[_msgSender()].length-1; i++) {
            _nodeMapping[_msgSender()][i] = _nodeMapping[_msgSender()][i+1];
        }
        
        _nodeMapping[_msgSender()].pop();
    }
}