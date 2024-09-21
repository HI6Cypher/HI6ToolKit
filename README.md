# CyG33k (is developing...)

A simple client-server messaging system that allows users to send and receive messages. The system is implemented in Python using socket and threading modules for network communication and multi-threading

## Features

- Post : Send a message to another user by providing the recipient's hostname and the message content
- Inbox : View received messages in the inbox
- Sent : View sent messages in the sent folder

## Prerequisites

- Python 3.x
- Terminal or Command Prompt

## Installation

- Clone the repository : `git clone https://github.com/HI6Cypher/CyGeek.git`

## Usage

1. Start the server by running the `main_server.py` script : `python main_server.py`
   - The server with listen for handshakes connections on port 50321 (UDP)
   - The server will listen for incoming connections on port 40321 (TCP)
2. Start the client by running the `main_client.py` script : `python main_client.py`
   - The client will prompt you to enter options :
     - Enter '1' to post a message
     - Enter '2' to view the inbox
     - Enter '3' to view the sent folder
3. Follow the prompts to perform the desired action

## Notes
- The server listens on port 50321 to sends unsend messages to special client that handshakes with server
- The client_server uses UDP broadcast for the initial handshake to discover the server's IP address and port
- Messages are sent over TCP connections for reliability
- Message data is stored in JSON format in the inbox and sent folder
- Error handling and security considerations are not fully implemented in this example. Please ensure proper error handling and security measures before deploying in a production environment
- This program isn't secure and it's just practical project for practice programming

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT)

## Acknowledgments

- The code is based on an original implementation by [HI6Cypher](https://github.com/HI6Cypher)
- Special thanks to the creators of the socket and threading modules for their contributions to the Python ecosystem
- Special thanks to ChatGPT-3.5 for helping me to make this readme
- Any comment to (huaweisclu31@hotmail.com)
