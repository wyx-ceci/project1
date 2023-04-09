import struct
import secrets
from dh import create_dh_key, calculate_dh_secret
from .xor import XOR
from Crypto.Hash import HMAC
from Crypto.Cipher import AES, ChaCha20  #AES cipher
from Crypto.Random import get_random_bytes
from lib.helpers import appendMac, macCheck, appendSalt, generate_random_string
from Crypto.Hash import SHA256
import random



class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.key = None
        self.rand_IV = None
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = True  # verbose
        self.shared_secret = None
        self.session_ID = list()
        self.hmac = None
        self.initiate_session()
        
        
        

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            print()
            print("my public key: " + str(my_public_key)+"\n")
            # Receive their public key
            their_public_key = int(self.recv())
            print()
            print("their public key: " + str(their_public_key)+"\n")
            # Obtain our shared secret
            self.shared_secret = calculate_dh_secret(their_public_key, my_private_key)
            self.hmac = HMAC.new(self.shared_secret,digestmod=SHA256)   
            print("Shared hash: {}".format(self.shared_secret.hex()))
            

            
       
            

    def send(self, data):
        if self.shared_secret:
            # generating unique session ID 
            session_ID = secrets.token_bytes(16)
            while session_ID in self.session_ID:
                session_ID = secrets.token_bytes(16)

            IV_1, IV_2 = create_dh_key()
            IV = calculate_dh_secret(IV_1,IV_2)
            self.rand_IV = IV[:16]
            
           
            cipher = AES.new(self.shared_secret,AES.MODE_CFB,self.rand_IV)
            data_to_send = cipher.encrypt(data)
         
            self.hmac.update(data_to_send)
            hmac_data = self.hmac.hexdigest().encode()
            data_to_send = hmac_data + data_to_send + self.rand_IV + session_ID    
            if self.verbose:
                print()
                print("Original message : {}".format(data))
                print("Encrypted data: {}".format(repr(data_to_send)))
                print("Sending packet of length: {}".format(len(data_to_send)))
                print()
                print("sender: " + str(self.rand_IV))
        else:
            data_to_send = data
            

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack("H", len(data_to_send))
       
        self.conn.sendall(pkt_len)
        self.conn.sendall(data_to_send)
        

        
       

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize("H"))
        unpacked_contents = struct.unpack("H", pkt_len_packed)
        pkt_len = unpacked_contents[0]
        


        if self.shared_secret:
            encrypted_data = self.conn.recv(pkt_len)
            hmac_received = encrypted_data[:64]
            self.rand_IV = encrypted_data[-32:-16]
            session_ID = encrypted_data[:-16]
            encrypted_data = encrypted_data[64:-32]
            
            self.hmac.update(encrypted_data)
            hmac_data = self.hmac.hexdigest().encode()
            # checking if received HMAC is same as generated HMAC  
            if hmac_received != hmac_data:
                print("YE SHALL NOT PASS")
                self.conn.close()
                

            # checking if session ID is used as replay attack
            if session_ID in self.session_ID:
                print("Replay attack detected")
                self.conn.close()
            # if not, append unique session ID to session ID record
            self.session_ID.append(session_ID)

        
            cipher = AES.new(self.shared_secret,AES.MODE_CFB,self.rand_IV)
            original_msg = cipher.decrypt(encrypted_data)
            print("receiver: " + str(self.rand_IV))

            if self.verbose:
                print()
                print("Receiving message of length: {}".format(len(encrypted_data)))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original message: {}".format(original_msg))
                print()
                
        else:
            original_msg = self.conn.recv(pkt_len)

        return original_msg

    def close(self):
        self.conn.close()

