# Mirada PCR Client
try:
  # begin imports
  import socket
  import select
  import sys
  import json

  from Lib.ClientEncryp import AESCipher, RSCCipher
  
  # define constants
  CLIENT_VERSION = 2.2
   
  print("-"*20 + "\nMirada PCR Client" + f"\nVersion: {CLIENT_VERSION} REL\n" + "-"*20)
  
  # function to input and save ip, port and username for chatroom server
  def entryMethod():
    IP_address = str(input("[ Enter Server IP to connect ]: "))
    Port = int(input("[ Enter Server Port to connect ]: "))
    pickedUsername = str(input("[ Enter a username to display ]: ")).strip().replace(" ", "_")[:20]
      
    # disallow empty usernames
    if pickedUsername == "":
      print("> Empty username is not allowed")
      exit(1)
      
    try:
      preserveBlueprint = {
        "LastIP": IP_address,
        "LastPort": Port,
        "LastUser": pickedUsername
      }
       
      # preserve last connection data
      json.dump(preserveBlueprint, open("PCRClientConfig.json", "w"))
      
    except Exception as saveCfgErr:
      print("> Could not save data to file, you will have to manually enter details every restart.")
      
    return IP_address, Port, pickedUsername
  
  try:
    # load preserved data from last connection 
    preservedVars = json.load(open("PCRClientConfig.json", "r"))
    
    IP_address = preservedVars["LastIP"] 
    Port = preservedVars["LastPort"]
    pickedUsername = preservedVars["LastUser"]
    
    # confirm if user wishes to connect to previous data
    prsrChoice = str(input(f"> Last used connection data: {pickedUsername}@{IP_address}:{Port}. Connect to the same server? (y/n): "))
    
    if prsrChoice.lower().strip() == "y":
      pass
    else:
      IP_address, Port, pickedUsername = entryMethod()
  except Exception as cfgLoadErr:
    # use manual input if data file inaccessible
    print(f"> Could not load from last user data: {cfgLoadErr}")
    IP_address, Port, pickedUsername = entryMethod()
   
  server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  
  try:
    # fetch server info with 60 second timeout 
    print("> Fetching server info...")
    
    server.settimeout(60)
    server.connect((IP_address, Port))
    
    server.send("$!;_F3TcH$~%SEP%~$SRv$~%SEP%~$m3T4DATA_;!$".encode())
    metadata = server.recv(2048).decode().split("$~%SEP%~$")
    
    # print server info if recieved 
    print("-"*20 + f"\n[ Server Information ]\n" + "-"*20)
    print(f"\n[ Name ] {metadata[0]}")
    print(f"[ IP ] {IP_address}")
    print(f"[ User Limit ] {metadata[1]}")
    print(f"[ Codename ] {metadata[2]}")
    print(f"[ Online Users ] {metadata[3]}")
    print(f"[ Server Version ] {metadata[4]}\n")
    
    # confirm if user wishes to connect to srv
    connChoice = str(input("> Proceed to connect? (y/n): ")).lower().strip()
    
    if connChoice == "y":
      if CLIENT_VERSION != float(metadata[4]):
        print("> Client and server are not on the same version, you may encounter bugs or the software may not work entirely.\n")
      
      print("> Requesting permission...")
      # create socket 
      server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      server.connect((IP_address, Port))
      
      # request chatroom thread on server
      server.send(f"$;_AlL0w$~%SEP%~$cH4TRO0m$~%SEP%~$c0Nn_;$#`=Us3R&s3P4=`#{pickedUsername}".encode())
      
      print("> Exchanging encryption data...")
      # exchange encryption data
      rsc = RSCCipher()
      # sending RSC pubkey to server
      server.send(rsc.pubKeyPEM)
      # receiving and decrypt AESkey
      encrypted_AESkey = bytes(server.recv(1024))
      AESkey = rsc.decrypt(encrypted_AESkey)
      cipher = AESCipher(AESkey)

      server.settimeout(None)
      
    else:
      print("> Abort")
      exit(0)
    
  except ValueError as potentialBan:
    if "Ciphertext with incorrect length." in str(potentialBan):
      print(encrypted_AESkey.decode())
      print(f"> Server sent invalid keys")
      exit(1)
      
  except Exception as sockConnErr:
    print(f"> ERROR: {sockConnErr}")
    exit(1)
  
  print(f"> You are now connected to server \"{metadata[2]}\"")
  print("-"*20 + "\n")
   
  while True:
   
      # maintains a list of possible input streams
      sockets_list = [sys.stdin, server]
   
      read_sockets,write_socket, error_socket = select.select(sockets_list,[],[])
   
      for socks in read_sockets:
          if socks == server:
            # recieve messages
              
              message = socks.recv(2048)
              try:
                message = cipher.decrypt(message)
              except ValueError:
                message = message.decode()
              
              if message:
                # display message if recieved
                print (message)
              else:
                # quit if server hanged up
                print(f"> Server \"{metadata[2]}\" closed the connection.")
                server.close()
                exit(0)
                
          else:
              # read message input 
              message = sys.stdin.readline()
              # differentiate b/w commands and normal text
              if message.startswith("%"):
                server.send(message.encode())
              else:
                message = "[ " + pickedUsername + " ] " + message
                server.send(cipher.encrypt(message))
                
              sys.stdout.flush()
              
              
  server.close()
  
except KeyboardInterrupt:
  # try to safely shutdown client by closing sock
  try:
    server.close()
    print("> Client safe-shutdown success")
  except Exception as e:
    print(f"> Client safe-shutdown failure. ERROR: {e}")

except Exception as e:
  # report fatal error
  print(f"> FATAL ERROR: {e}")
  exit(1)
