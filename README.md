# Mirada Private Chatroom
MPCR is a custom server/client script that allows running a secure chatroom service.

- Runs on sockets (python)
- Uses AES Encryption 
- Has commands (ban, ipban, kick etc)
- Client preserves last used IP, Port and Username 
- Only needs one 3rd party library (pycryptodome)
- Server information/user limit is configurable using JSON files (automatically created)

## Important Info
- Run a server, connect a client to it and see %help for commands 
- Server and client both have a 60s connection timeout, so wait if it's stuck on connecting/exchanging keys.
- Admin file `MPCRAdminCreds.json` needs to be configured in SERVER before running. It contains admin credentials in a list of format `["user", "pass"]`. Make sure to edit/add admin credentials (for running commands)

## How to start 
- Install pycryptodome 
`python -m pip install pycryptodome`
- Configure `MPCRAdminCreds.json` (for server only)
- Run client/server 
`python ./PCR_Client/Client.py` 
`python ./PCR_Server/Server.py` 
- Configure `MPCRConfig.json` and rerun server (for server only)

## Credits 
Files `PCR_Server/Lib/ServEncryp.py` and `PCR_Client/Lib/ClientEncryp.py` were taken from [HERE](https://github.com/debidong/SafeChatroom)

PS: I know the code is not beautiful but I actually coded the whole thing on my Android phone...
