# eob
eob - Ephemeral Onion Box client and server

The Onion Box is a secure file management system that operates over the Tor network. It provides an ephemeral onion service for managing files on a remote server while ensuring anonymity and encryption. The system consists of two components:

Server : Hosts the files and runs as a Tor onion service.
Client : Interacts with the server via the Tor network to manage files anonymously.

Features
Ephemeral Onion Addresses : The server generates new onion addresses periodically, ensuring anonymity.  

File Management : Users can list, upload, download, delete, and view files on the server.  

Email Notifications : Subscribers receive encrypted emails with the new onion address and validity details.  

Tor Integration : Built-in support for the Tor network ensures anonymity for both server and client.

The repository contains an aes folder, which includes a small utililty do decrypt the automatic messages send by the server.
