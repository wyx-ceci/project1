import struct
import secrets
from dh import create_dh_key, calculate_dh_secret
from .xor import XOR
from Crypto.Protocol.KDF import bcrypt
from Crypto.Cipher import AES #AES cipher
from Crypto.Random import get_random_bytes
from lib.helpers import appendMac, macCheck, appendSalt, generate_random_string


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.key = None
        self.rand_IV = bytes()
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = True  # verbose
        self.shared_secret = None
        self.initiate_session()
        
        
        

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            self.rand_IV = secrets.randbits(128)
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
            # salt = secrets.token_bytes(16) # get random 128 bits for salt
            self.shared_secret = bcrypt(self.shared_secret,14,salt)
            print("Shared hash: {}".format(self.shared_secret.hex()))
            # self.key = os.urandom(32) #AES 256
            
       
            

    def send(self, data):
        if self.shared_secret:
            cipher = AES.new(self.shared_secret,AES.MODE_CFB,self.rand_IV)
            data_to_send = cipher.encrypt(data)
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
        self.conn.sendall(self.rand_IV)
        self.conn.sendall(data_to_send)

        
       

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize("H"))
        unpacked_contents = struct.unpack("H", pkt_len_packed)
        pkt_len = unpacked_contents[0]
        self.rand_IV =  self.conn.recv(16)

        if self.shared_secret:
            encrypted_data = self.conn.recv(pkt_len)
            # Project TODO: as in send(), change the cipher here.
            #cipher = XOR(self.shared_secret)
            #original_msg = cipher.decrypt(encrypted_data)
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

