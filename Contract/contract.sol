// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// provide _msgSender() and _msgData
import "@openzeppelin/contracts/utils/Context.sol";

// provide _owner, 
import "@openzeppelin/contracts/access/Ownable.sol";

contract DS is Context, Ownable {
    
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
    }

    enum protocol{
        TCP,
        UDP,
        OTHER
    }

    struct Node{
        string nodeId;
        string ipAddress;
        string netAddress;
        protocol protocol;
        uint256 port;
        address owner;
    }

    
    // Mapping for file owner to all its files. 
    mapping(address => string[]) private _fileMapping;
    mapping(string => File) private _fileList;

    /**
     * Modifier to determine if the address is the file owner. // no need maybe
     */
    modifier isFileOwner(string memory _rootHash) {
        require(_fileMapping[_msgSender()].length != 0, "You don't have access to this file");
        _;
    }

    /*
     * Add new file and associate it with the owner via mapping (everyone can execute this function).
     */
    function addFile(string memory _fileName, uint256 _fileSize, string memory _rootHash) public returns(bool) {
        File memory file;
        file.owner = _msgSender();
        file.fileName = _fileName;
        file.fileSize = _fileSize;
        file.fileChunkCount = 0;//_fileChunks.length;
        //for (uint i=0; i<_fileChunks.length; i++){
            //file.fileChunks.push(_fileChunks[i]);
        //}
        _fileList[_rootHash] = file;
        _fileMapping[_msgSender()].push(_rootHash);
        return true;
    }

    /*
     * Retrieve all files owned by this address and return. 
     */
    function listFiles() public view returns(File[] memory) {
        File[] memory files;
        for (uint i=0; i<_fileMapping[_msgSender()].length; i++) {
            files[i] = _fileList[_fileMapping[_msgSender()][i]];
        }
        return files;
    }

    /*
     * Download single file from owner's file list. (only file owner is allowed to execute this function).
     */
    function getFile(string memory _rootHash) public isFileOwner(_rootHash) returns(File memory) {
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

    function deleteFileMappingByIndex(uint index) private {
        require(index < _fileMapping[_msgSender()].length, "Index out of bounds");
        
        for (uint i = index; i < _fileMapping[_msgSender()].length-1; i++) {
            _fileMapping[_msgSender()][i] = _fileMapping[_msgSender()][i+1];
        }
        
        _fileMapping[_msgSender()].pop();
    }
}