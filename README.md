# Distributed-Storage-on-Ethereum
### Setup
#### Smart Contract

Our existing Smart Contract deployed on the Sepolia testnet is at https://sepolia.etherscan.io/address/0x89c509099abc732b2023889f8affabf30c60bb6b

Or you can use 4 `.sol` files inside the Contract folder to deploy a Smart Contract by your self.

#### Client Setup

To use the client application, the user needs to provide the following information:

- `INFURA_NODE_ENDPOINT`: This is the endpoint for the [Infura API Key](https://www.infura.io/) used to connect to the Ethereum blockchain.

- `CONTRACT_ADDRESS`: This is the address of the smart contract used to store the file information on the blockchain.

- `WALLET_PUBLIC_ADDRESS`: This is the public address of the user Ethereum wallet used to interact with the smart contract.

- `WALLET_PRIVATE_KEY`: This is the private key of the user Ethereum wallet used to sign transactions on the blockchain.

##### Libraries used:
The following libraries are required to run the Client software:

- `inquirer`: This library is used to provide an interactive command-line interface for the user.

- `requests`: This library is used to make HTTP requests to the storage nodes.

- `numpy`: This library is used to manipulate arrays and perform mathematical operations.

- `base64`: This library is used to encode and decode binary data in base64 format.

- `MerkleTree`: This is a custom class that implements the Merkle tree data structure.

- `FileHandler`: This is a custom class that handles the encryption, split, encode, decode, and merge. (may need to rewrite?)

- `dotenv`: This library is used to load environment variables from a `.env` file.

- `threading`: This library is used to create a background thread that periodically verifies the integrity of the uploaded chunks.

##### Connecting to the nodes:

The Client software communicates with the nodes using HTTP requests. To connect to the nodes, the Client software requires the IP address and port number of each node.  (may need chunk id in the future?)

To set up the Client software, follow these steps:

- Clone the project from GitHub and navigate to the root directory.

- Install the necessary dependencies by running `pip install -r requirements.txt`.

- If there is no `.env` file in your directory. The client program will create `.env` for you in the first time.

- In the `.env` file, set the following environment variables:

  - `INFURA_NODE_ENDPOINT`: The endpoint URL for your Infura node.

  - `CONTRACT_ADDRESS`: The address of the smart contract.

  - `WALLET_PUBLIC_ADDRESS`: Your wallet's public address.

  - `WALLET_PRIVATE_KEY`: Your wallet's private key.

- If any of the above environment variables are missing, the program will prompt you to enter the required information.

- Run the program by running python client.py.

- Once the program is running, you will be prompted with a menu with the following options:

  - Upload: Upload or share a file to the distributed storage network. 

  - Download: Download a file from the distributed storage network.

  - Check: Check the status of a file on the distributed storage network, and prompt the user if they want to remove the file.

  - Exit: Exit the program.

- If you choose Upload, you will have the options to share the file or upload the file to the distributed storage network. If you select Share, you will be prompted to enter the receiver’s public key and the file path of the file you wish to upload. If you select Upload to server, you will be prompted to enter the file path of the file you wish to upload. The program will then split the file into chunks and upload them to the network.

- If you choose Download, you will be prompted to enter the file path of the file you wish to save. The program will then list the files which you own or shared with you. If you select a file, you will be asked is the file your own file or a shared file. If you select Shared file, you will be prompted to enter the sender’s public key. The program will then download the chunks from the network and reassemble them into the original file.

- If you choose Check, you will be prompted to enter the file hash of the file you wish to check. The program will then display information about the file, such as the node IDs of file chunks. Then, you will have the option to remove the file from the network if desired.


#### Node Setup
The storage node provides 5 HTTP APIs.

- `/chunk` POST request: Allows the node to receive and store chunk data sent from a client. The data is saved into a database indexed by a randomly generated ID.
- `/chunk/verify` GET request: Request the node to verify its saved chunks are registered on the blockchain, thus allowing these chunks to be available for downloading.
- `/chunk/<id>` GET request: Requests the node to check the availability of a chunk whose id is `<id>` and sends the chunk back to the client for downloading files.
- `/chunk/<id>/check` GET request: Requests the node to provide a hash value of the chunk with id of `<id>`,  to check if the chunk is stored properly.
- `/chunk/<id>/remove` DELETE request: Requests the node to remove the chunk with id `<id>`.

Before start a storage node, you need to save the ethereum credentials into `.env` file under the running path. Keep this file in a safe envrionment.

```
INFURA_NODE_ENDPOINT="https://sepolia.infura.io/v3/325c2e4f72b743a99bf8325760da19c5"
CONTRACT_ADDRESS=0x70C251E437a894f57b07Ae8a8bed120c0bAbE223
WALLET_PUBLIC_ADDRESS=<your wallet address>
WALLET_PRIVATE_KEY=<your wallet private key>
```

```
usage: server.py [-h] [-p PORT] [-H IP] [-d DOMAIN] [-c CONFIG]

Distributed Storage Server

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port number (default: 3000)
  -H IP, --ip-address IP
                        Host address (default: 127.0.0.1)
  -d DOMAIN, --domain DOMAIN
                        Host domain (default: localhost)
  -c CONFIG, --config CONFIG
                        Config file path
```

To start a local storage node on port 3000, and save the config file to `./config.json`.

```shell
cd Server
python3 server.py -H 127.0.0.1 -d localhost -p 3000 -c ./config.json
```


We provide two `.env` files that contains ethereum key pair for testers, you can search Sepolia Faucet to acquire test Ethereums.

```

```

```
```


