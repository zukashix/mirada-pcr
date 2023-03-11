# Mirada PCR Server
  
try:
  # begin imports
  import socket
  import select
  import sys
  import json
  
  from _thread import *
  
  from Lib.ServEncryp import encrypt_AESkey
  from Crypto.Random import get_random_bytes
  
  # define constants
  SERVER_VERSION = 2.2
  AESkey = get_random_bytes(16)
  CMDHELPMSG = "\n\n" + "-"*20 + "\nServer Commands Help\n" + "-"*20 + "\n[ <message> ] Send a normal, end-to-end encrypted message.\n[ % <message> ] Send a non-encrypted message (Not recommended, unsafe)\n[ %help ] Displays this page for command help\n[ %close ] Disconnect client from server\n[ %list ] List online users\n[ %iplist <adminUser>:<adminPass> ]** List online users with IP\n[ %kick <userIP> <adminUser>:<adminPass> ]** Kick a user\n[ %banuser <username> <adminUser>:<adminPass> ]** Ban a username (use with %kick if user is already in server)\n[ %banip <userIP> <adminUser>:<adminPass> ]** Ban an IP address (use with %kick if user is already in server)\n[ %unban <userIp/userName> <adminUser>:<adminPass> ]** Unban a user. It will automatically scan both IP bans and username bans\n[ NOTE ] Commands marked with ** are admin-only\n" + "-"*20 + "\n\n"
  
  print("-"*20 + "\nMirada PCR Server" + f"\nVersion: {SERVER_VERSION} REL\n" + "-"*20)
   
  # create socket object
  server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  print("> Socket Object Ready")
  
  # function to load admin credential files and check if provided credentials match
  def checkAdmin(credens):
    try:
      credens = credens.split(":")
      adminCredentials = json.load(open("MPCRAdminCreds.json", "r"))
      
      for admin in adminCredentials["Admins"]:
        if (credens[0] == admin[0]) and (credens[1] == admin[1]):
          return True

      return False

    except Exception as e:
      print(e)
      return False

  # function to remove id from banlist
  def unbanList(banaddr):
    try:
      banfile = json.load(open("MPCRBanData.json", "r"))
    except:
      return 1
      
    try:
      banfile["IPList"].remove(banaddr)
      json.dump(banfile, open("MPCRBanData.json", "w"))
      return 0
    except:
      try:
        banfile["UserList"].remove(banaddr)
        json.dump(banfile, open("MPCRBanData.json", "w"))
        return 0
      except ValueError:
        return 2
      except:
        return 1

  # function to add new id to banlist
  def editBanList(banaddr, file):
    try:
      banfile = json.load(open("MPCRBanData.json", "r"))
      banfile[file].append(banaddr)
      json.dump(banfile, open("MPCRBanData.json", "w"))
      return 0
    except:
      try:
        banFileBlueprint = {
          "IPList": [],
          "UserList": []
        }
        banFileBlueprint[file].append(banaddr)
        json.dump(banFileBlueprint, open("MPCRBanData.json", "w"))
        return 0
      except:
        return 2
   
  # handle server config file
  try:
    # load server config
    defaultConfig = json.load(open("MPCRConfig.json", "r"))
    SRV_BIND_IP = defaultConfig["ServerIP"].strip()
    SRV_BIND_PORT = defaultConfig["ServerPort"]
    SRV_LIMIT = defaultConfig["ServerLimit"]
    SRV_NAME = defaultConfig["ServerName"].strip()[:45]
    SRV_WLCMTXT = defaultConfig["ServerWelcome"].strip()[:256]
    SRV_CODENAME = defaultConfig["ServerCodename"].strip().replace(" ", "")[:15]
    SRV_JOINTXT = defaultConfig["ServerJoin"].strip()[:256]
    SRV_QUITTXT = defaultConfig["ServerLeave"].strip()[:256]
    print("> Loaded configs from file")
    
    # print server info
    print("-"*20 + f"\n[ Server Information ]\n" + "-"*20)
    print(f"\n[ Name ] {SRV_NAME}")
    print(f"[ IP ] {SRV_BIND_IP}")
    print(f"[ Port ] {SRV_BIND_PORT}")
    print(f"[ User Limit ] {SRV_LIMIT}")
    print(f"[ Codename ] {SRV_CODENAME}")
    print(f"[ Server Version ] {SERVER_VERSION}\n" + "-"*20)
    
  except Exception as cfgLoadErr:
    # create new config with blueprint incase file is inaccessible 
    print("\nCould not access config file to load defaults.")
    print(f"ERROR: {cfgLoadErr}")
    
    cfgBlueprint = {
      "ServerIP": "0.0.0.0",
      "ServerPort": 23491,
      "ServerLimit": 100,
      "ServerName": "Unknown",
      "ServerWelcome": "Welcome to this chatroom!",
      "ServerCodename": "srv69",
      "ServerJoin": "[ SERVER ] ${USR}$ just joined the chat!",
      "ServerLeave": "[ SERVER ] ${USR}$ has left the chat."
    }
    
    try:
      json.dump(cfgBlueprint, open("MPCRConfig.json", "w"))
      print("A config file \"./MPCRConfig.json\" has been created, please edit it according to the server.")
      
    except Exception as cfgFileCrErr:
      # if failed to create file, print blueprint for manual creation
      print("Failed to create config file.")
      print(f"ERROR: {cfgFileCrErr}")
      print("Please create a file named \"MPCRConfig.json\" in the working directory with JSON format:\n")
      print(str(cfgBlueprint))
      
    sys.exit(1)
  
  # bind server to host and listen for clients
  server.bind((SRV_BIND_IP, SRV_BIND_PORT))
  server.listen(SRV_LIMIT)
  print(f"> Bound socket to host {SRV_BIND_IP}:{SRV_BIND_PORT} and listening for {SRV_LIMIT} connections.")
   
  # maintain a list of clients and username with same index
  list_of_clients = []
  list_of_usernames = []
   
  # handle individual client connection in a thread 
  def clientthread(conn, addr, usrnm):
      # send welcome text to client
      conn.send((SRV_WLCMTXT + '\n').encode())
      print(f"> {addr[0]} [{usrnm}] joined server.")
      
      # broadcast user join message 
      broadcastWelcomeMsg = SRV_JOINTXT.strip().replace("${USR}$", usrnm)
      broadcast(broadcastWelcomeMsg.encode(), usrnm, addr)
   
      while True:
          try:
            # recieve messages
            message = conn.recv(2048)
            if message:

              try:
                message = message.decode()
                # %kick server command 
                if message.startswith("%kick"):
                  splitmessage = message.strip().split(" ")
                  credentials = splitmessage[2]
                  toAction = splitmessage[1]
                  
                  # check admin
                  if checkAdmin(credentials):
                    if conn.getpeername()[0] == toAction:
                      conn.send("[ SERVER ] You cannot kick yourself. Use %close instead.".encode())
                      continue
                    
                    setSH = 0
                    for connUsr in list_of_clients:
                      connCuAddr = connUsr.getpeername()
                      
                      if connCuAddr[0] == toAction:
                        connUsrname = list_of_usernames[list_of_clients.index(connUsr)]
                        
                        # kick selected user
                        remove(connUsr, connUsrname, connCuAddr)
                        conn.send(f"[ SERVER ] {connCuAddr[0]} ({connUsrname}) has been kicked.".encode())
                        setSH = 1
                        break
                      
                    if setSH == 0:
                      conn.send("[ SERVER ] No such user found".encode())
                    elif setSH == 1:
                      pass

                  else:
                    # disallow invalid creds
                    conn.send("[ SERVER ] Incorrect credentials".encode())

                # close command to disconnect a user
                elif message.startswith("%close"):
                  conn.send("[ SERVER ] Closing connection...".encode())
                  remove(conn, usrnm, addr)
                  
                # help command to send command help
                elif message.startswith("%help"):
                  conn.send(CMDHELPMSG.encode())

                # list online users command
                elif message.startswith("%list"):
                  iplist = "-"*20 + f"\nList of connected users [ Total: {len(list_of_clients)} ]\n" + "-"*20 + "\n"
                    
                  for i in range(len(list_of_usernames)):
                    iplist = iplist + f"> {list_of_usernames[i]}\n"
                    
                  iplist = iplist + "-"*20
                  conn.send(iplist.encode())
                  
                # list online users command with their ip 
                elif message.startswith("%iplist"):
                  splitmessage = message.strip().split(" ")
                  credentials = splitmessage[1]
                  
                  # check admin
                  if checkAdmin(credentials):
                    iplist = "-"*20 + f"\nList of connected users [ Total: {len(list_of_clients)} ]\n" + "-"*20 + "\n"
                    
                    for i in range(len(list_of_usernames)):
                      iplist = iplist + f"> {list_of_usernames[i]} ({list_of_clients[i].getpeername()[0]})\n"
                      
                    iplist = iplist + "-"*20
                    conn.send(iplist.encode())
                    
                  else:
                    # disallow invalid creds
                    conn.send("[ SERVER ] Incorrect credentials".encode())
                    
                # ip address ban command
                elif message.startswith("%banip"):
                  splitmessage = message.strip().split(" ")
                  credentials = splitmessage[2]
                  toAction = splitmessage[1]
                  
                  # check admin
                  if checkAdmin(credentials):
                    eblRet = editBanList(toAction, "IPList")
                    
                    if eblRet == 0:
                      conn.send(f"[ SERVER ] IP {toAction} added to banlist.".encode())

                    elif eblRet == 2:
                      conn.send("[ SERVER ] BanList is inaccessible due to server issues.".encode())
                    
                  else:
                    # disallow invalid creds
                    conn.send("[ SERVER ] Incorrect credentials".encode())
                    
                # username ban command
                elif message.startswith("%banuser"):
                  splitmessage = message.strip().split(" ")
                  credentials = splitmessage[2]
                  toAction = splitmessage[1]
                  
                  # check admin
                  if checkAdmin(credentials):
                    eblRet = editBanList(toAction, "UserList")
                    
                    if eblRet == 0:
                      conn.send(f"[ SERVER ] Username {toAction} added to banlist.".encode())

                    elif eblRet == 2:
                      conn.send("[ SERVER ] BanList is inaccessible due to server issues.".encode())
                    
                  else:
                    # disallow invalid creds
                    conn.send("[ SERVER ] Incorrect credentials".encode())
                    
                # unban username/ip command
                elif message.startswith("%unban"):
                  splitmessage = message.strip().split(" ")
                  credentials = splitmessage[2]
                  toAction = splitmessage[1]
                  
                  # check admin
                  if checkAdmin(credentials):
                    eblRet = unbanList(toAction)
                    
                    if eblRet == 0:
                      conn.send(f"[ SERVER ] {toAction} removed from banlist.".encode())
                      
                    elif eblRet == 1:
                      conn.send("[ SERVER ] BanList is inaccessible due to server issues.".encode())
                      
                    elif eblRet == 2:
                      conn.send(f"[ SERVER ] {toAction} was not found in BanList.".encode())
                    
                  else:
                    # disallow invalid creds
                    conn.send("[ SERVER ] Incorrect credentials".encode())

                # broadcast message
                elif message.startswith("% "):
                  # if message is not a command, broadcast it
                  conn.send("[ SERVER ] WARNING: You are sending a message without decryption. See %help if you do not know about this.\n".encode())
                  
                  messageToSend = f"[ Non-Encrypted ] [ {usrnm} ] {message}"

                  broadcast(messageToSend.replace("% ","").encode(), usrnm, addr)
                  
                else:
                  conn.send("[ SERVER ] Unknown command. See %help".encode())
              
              except IndexError:
                conn.send("[ SERVER ] Invalid command usage, please use command \"%help\" to get details.".encode())
                continue

              # encrypted message
              except UnicodeDecodeError:
                broadcast(message, usrnm, addr)

            else:
                # kick client if message is empty
                remove(conn, usrnm, addr)

          except Exception as e:
              if "[Errno 9]" in str(e):
                # destroy thread if client disconnected
                break
              else:
                print(f"> An error occurred in runtime, ignoring... [{e}]")
                continue
   
  # func to broadcast msg to all clients
  def broadcast(message, usrnm, addr):
      for clients in list_of_clients:
          try:
              clients.send(message)
          except:
              # if the link is broken, we remove the client
              remove(clients, usrnm, addr)
   
  # func to kick client
  def remove(connection, usrnm, addr):
      if connection in list_of_clients:
          connection.close()
          list_of_clients.remove(connection)
          list_of_usernames.remove(usrnm)
          
          # broadcast client removal
          print(f"> {addr[0]} [{usrnm}] was removed from the server.")
          broadcastLeaveMsg = SRV_QUITTXT.strip().replace("${USR}$", usrnm)
          broadcast(broadcastLeaveMsg.encode(), usrnm, addr)
         
  # func to read client requests 
  def readFirstReq(conn, addr):
    conn.settimeout(60)
    message = conn.recv(2048).decode()
    
    # send server stats on req
    if message == "$!;_F3TcH$~%SEP%~$SRv$~%SEP%~$m3T4DATA_;!$":
      print(f"> Recieved metadata request from {addr[0]}")
      
      brmsg = f"{SRV_NAME}$~%SEP%~${SRV_LIMIT}$~%SEP%~${SRV_CODENAME}$~%SEP%~${len(list_of_clients)}$~%SEP%~${SERVER_VERSION}"
      
      conn.send(brmsg.encode())
      
    # allow entry to chatroom on req
    elif "$;_AlL0w$~%SEP%~$cH4TRO0m$~%SEP%~$c0Nn_;$" in message:
      username = message.split("#`=Us3R&s3P4=`#")[1].strip().replace(" ", "_")[:20]
      
      print(f"> Recieved chatroom request from {addr[0]} [ Username: {username} ]")
      
      # init banlist
      try:
        banfile = json.load(open("MPCRBanData.json", "r"))
      except:
        banfile = {
          "IPList": [],
          "UserList": []
        }
      
      # close connection if username is invalid
      if username == "":
        print(f"> Closing connection for {addr[0]} due to invalid username.")
        conn.send("[ SERVER ] Invalid Username".encode())
        
      # check if user is banned
      elif (username.lower() in banfile["UserList"]) or (conn.getpeername()[0] in banfile["IPList"]):
        print(f"> Closing connection for {addr[0]} because they\'re banned.")
        conn.send("[ SERVER ] You are banned on this server.".encode())
      
      else:
        # exchange encryption keys
        print(f"> Exchanging encryption keys with {addr[0]}")
        pubKeyPEM = bytes(conn.recv(1024))
        encrypted_AESkey = encrypt_AESkey(AESkey, pubKeyPEM)
        conn.send(bytes(encrypted_AESkey))
        
        # start individual thread to handle client
        conn.settimeout(None)
        list_of_clients.append(conn)
        list_of_usernames.append(username)
        start_new_thread(clientthread,(conn,addr,username))
        return
      
    # close connection on invalid sock
    else:
      print(f"> Recieved invalid request from {addr[0]}")
      conn.send("Invalid client socket request.".encode())
    
    conn.close()
   
  print(f"> Server \"{SRV_CODENAME}\" is ready!")
  while True:
      # accept incoming connections
      conn, addr = server.accept()
      start_new_thread(readFirstReq,(conn,addr))    
    
  server.close()
  
except KeyboardInterrupt:
  # try to safely shutdown server on Ctrl+C
  try:
    server.close()
    print("> Server safe-shutdown success")
  except Exception as e:
    print(f"> Server safe-shutdown failure. ERROR: {e}")

except Exception as e:
  # report fatal error and quit
  print(f"> FATAL ERROR: {e}")
  sys.exit(1)
