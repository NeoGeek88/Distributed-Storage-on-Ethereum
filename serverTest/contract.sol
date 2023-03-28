// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// provide _msgSender() and _msgData
import "./Context.sol";

// provide _owner
import "./Ownable.sol";

// provide MerkleProof
import "./MerkleProof.sol";

contract DS is Context, Ownable {
    
    // File chunk structure, used inside the File structure.
    struct FileChunk{
        bytes32 chunkHash;
        string nodeId;
    }
    // File metadata structure.
    struct File{
        address owner;
        string fileName;
        uint256 fileSize;
        bytes32 rootHash;
        uint256 fileChunkCount;
        FileChunk[] fileChunks;
    }
    
    // Mapping for file owner to all its files. 
    mapping(address => bytes32[]) private _fileMapping;
    // Mapping the root hash of a file to its metadata.
    mapping(bytes32 => File) private _fileList;

    /**
     * Modifier to determine if the address is the file owner.
     */
    modifier isFileOwner(bytes32 _rootHash) {
        require(_fileList[_rootHash].owner == _msgSender(), "You don't have access to this file");
        _;
    }

    /*
     * Add new file and associate it with the owner via mapping (everyone can execute this function).
     */
    function addFile(
        string memory _fileName, 
        uint256 _fileSize, 
        bytes32 _rootHash, 
        FileChunk[] memory _fileChunks
    ) public returns(bool) {
        _fileList[_rootHash].owner = _msgSender();
        _fileList[_rootHash].fileName = _fileName;
        _fileList[_rootHash].fileSize = _fileSize;
        _fileList[_rootHash].rootHash = _rootHash;
        _fileList[_rootHash].fileChunkCount = _fileChunks.length;
        for (uint256 i=0; i<_fileChunks.length; i++){
            _fileList[_rootHash].fileChunks.push(_fileChunks[i]);
        }
        _fileMapping[_msgSender()].push(_rootHash);
        return true;
    }

    /*
     * Modify the chunk data and file name for an existing file.
     */
    function updateFile(
        bytes32 _rootHash, 
        string memory _newFileName, 
        FileChunk[] memory _updatedFileChunks
    ) public isFileOwner(_rootHash) returns(bool) {
        _fileList[_rootHash].fileName = _newFileName;
        for (uint256 i=0; i<_updatedFileChunks.length; i++){
            for (uint256 j=0; j<_fileList[_rootHash].fileChunks.length; j++){
                if (_fileList[_rootHash].fileChunks[j].chunkHash == _updatedFileChunks[i].chunkHash){
                    _fileList[_rootHash].fileChunks[j].nodeId = _updatedFileChunks[i].nodeId;
                }
            }
        }
        return true;
    }

    /*
     * Retrieve information of all files owned by this address and return. 
     */
    function listFiles() public view returns(File[] memory) {
        File memory file;
        File[] memory files = new File[](_fileMapping[_msgSender()].length);
        for (uint256 i=0; i<_fileMapping[_msgSender()].length; i++) {
            file = _fileList[_fileMapping[_msgSender()][i]];
            files[i] = file;
        }
        return files;
    }

    /*
     * Retrive single file information from owner's file list. (only file owner is allowed to execute this function).
     */
    function getFile(bytes32 _rootHash) public view isFileOwner(_rootHash) returns(File memory) {
        return _fileList[_rootHash];
    }

    function removeFile(bytes32 _rootHash) public isFileOwner(_rootHash) returns(bool) {
        for (uint256 i = 0; i < _fileMapping[_msgSender()].length; i++) {
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

    /*
     * Contract owner only debug function.
     */
    function checkFileList(bytes32 _rootHash) public view onlyOwner() returns (File memory) {
        return _fileList[_rootHash];
    }

    /*
     * Util function to delete a value at 'index' from an array.
     */
    function deleteFileMappingByIndex(uint256 index) private {
        require(index < _fileMapping[_msgSender()].length, "Index out of bounds");
        
        for (uint256 i = index; i < _fileMapping[_msgSender()].length-1; i++) {
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
    // Full node list with node ID only
    string[] _fullNodeIdList;

    /**
     * Modifier to determine if the address is the node owner.
     */
    modifier isNodeOwner(string memory _nodeId) {
        require(_nodeList[_nodeId].owner == _msgSender(), "You don't have access to this node");
        _;
    }

    modifier hasActiveNode() {
        require(_nodeMapping[_msgSender()].length > 0, "You are not allowed to call this function");
        _;
    }

    /*
     * Add new file and associate it with the owner via mapping (everyone can execute this function).
     */
    function addNode(
        string memory _nodeId, 
        string memory _ipAddress, 
        string memory _netAddress, 
        protocol _protocol, 
        uint256 _port
    ) public returns(bool) {
        _nodeList[_nodeId].owner = _msgSender();
        _nodeList[_nodeId].nodeId = _nodeId;
        _nodeList[_nodeId].ipAddress = _ipAddress;
        _nodeList[_nodeId].netAddress = _netAddress;
        _nodeList[_nodeId].protocol = _protocol;
        _nodeList[_nodeId].port = _port;
        _nodeMapping[_msgSender()].push(_nodeId);
        _fullNodeIdList.push(_nodeId);
        return true;
    }

    /*
     * Update existing node information.
     */
    function updateNode(
        string memory _nodeId, 
        string memory _ipAddress, 
        string memory _netAddress, 
        protocol _protocol, 
        uint256 _port
    ) public isNodeOwner(_nodeId) returns(bool) {
        _nodeList[_nodeId].ipAddress = _ipAddress;
        _nodeList[_nodeId].netAddress = _netAddress;
        _nodeList[_nodeId].protocol = _protocol;
        _nodeList[_nodeId].port = _port;
        return true;
    }

    /*
     * Retrieve information of all available nodes. 
     */
    function listNodes() public view returns(Node[] memory) {
        Node memory node;
        Node[] memory nodes = new Node[](_fullNodeIdList.length);
        for (uint256 i=0; i<_fullNodeIdList.length; i++) {
            node = _nodeList[_fullNodeIdList[i]];
            nodes[i] = node;
        }
        return nodes;
    }

    /*
     * Retrive single file information from owner's file list. (only file owner is allowed to execute this function).
     */
    function getNode(string memory _nodeId) public view isNodeOwner(_nodeId) returns(Node memory) {
        return _nodeList[_nodeId];
    }

    function removeNode(string memory _nodeId) public isNodeOwner(_nodeId) returns(bool) {
        for (uint256 i = 0; i < _nodeMapping[_msgSender()].length; i++) {
            bytes32 storageHash = keccak256(abi.encodePacked(_nodeMapping[_msgSender()][i]));
            bytes32 memoryHash = keccak256(abi.encodePacked(_nodeId));
            if (storageHash == memoryHash) {
                deleteNodeMappingByIndex(i);
                break;
            }
        }
        for (uint256 i = 0; i < _fullNodeIdList.length; i++) {
            bytes32 storageHash = keccak256(abi.encodePacked(_fullNodeIdList[i]));
            bytes32 memoryHash = keccak256(abi.encodePacked(_nodeId));
            if (storageHash == memoryHash) {
                deleteFullNodeIdListByIndex(i);
                break;
            }
        }
        delete _nodeList[_nodeId];
        return true;
    }

    /*
     * Contract owner only debug function.
     */
    function checkNodeList(string memory _nodeId) public view onlyOwner() returns (Node memory) {
        return _nodeList[_nodeId];
    }

    /*
     * Util function to delete a value at 'index' from an array.
     */
    function deleteNodeMappingByIndex(uint256 index) private {
        require(index < _nodeMapping[_msgSender()].length, "Index out of bounds");
        
        for (uint256 i = index; i < _nodeMapping[_msgSender()].length-1; i++) {
            _nodeMapping[_msgSender()][i] = _nodeMapping[_msgSender()][i+1];
        }
        
        _nodeMapping[_msgSender()].pop();
    }

    /*
     * Util function to delete a value at 'index' from an array.
     */
    function deleteFullNodeIdListByIndex(uint256 index) private {
        require(index < _fullNodeIdList.length, "Index out of bounds");
        
        for (uint256 i = index; i < _fullNodeIdList.length-1; i++) {
            _fullNodeIdList[i] = _fullNodeIdList[i+1];
        }
        
        _fullNodeIdList.pop();
    }


    function performMerkleProof(
        bytes32[] memory proof, 
        bytes32 root, 
        bytes32 leaf, 
        uint256 index
    ) public view hasActiveNode() returns (bool) {
        return MerkleProof.verify(proof, root, leaf, index);
    }

    function kickNode(string memory _nodeId) public hasActiveNode() returns (bool) {
        address owner = _nodeList[_nodeId].owner;
        for (uint256 i = 0; i < _nodeMapping[owner].length; i++) {
            bytes32 storageHash = keccak256(abi.encodePacked(_nodeMapping[owner][i]));
            bytes32 memoryHash = keccak256(abi.encodePacked(_nodeId));
            if (storageHash == memoryHash) {
                deleteNodeMappingByIndex(i);
                break;
            }
        }
        for (uint256 i = 0; i < _fullNodeIdList.length; i++) {
            bytes32 storageHash = keccak256(abi.encodePacked(_fullNodeIdList[i]));
            bytes32 memoryHash = keccak256(abi.encodePacked(_nodeId));
            if (storageHash == memoryHash) {
                deleteFullNodeIdListByIndex(i);
                break;
            }
        }
        delete _nodeList[_nodeId];
        return true;
    }
}