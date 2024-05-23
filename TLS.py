from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread
import time
import hashlib
import hmac

BUFFER_SIZE = 65536 # 수정 금지
#프로토콜 정의
protocol={0:"ClientHello",
        1:"ServerHello",
        2:"Certificate",
        3:"ServerHelloDone",
        4:"ClientKeyExcnage",
        5:"ChangeCipherSpec",
        6:"Finished",
        255:"Error code", 
        254:"ECHO Mode", 
        253:"Data Decryption Mode"}
protocol_str={"ClientHello":0,
            "ServerHello":1,
            "Certificate":2,
            "ServerHelloDone":3,
            "ClientKeyExcnage":4,
            "ChangeCipherSpec":5,
            "Finished":6,
            "Error code":255,
            "ECHO Mode":254,
            "Data Decryption Mode":253}

#for debug
#주고 받은 데이터를 출력하기 위한 디버깅용 함수
def print_packet(additional,data,enc=False):
    if enc:
        print (f"{additional} (raw)", data)
        print (f"{additional} (hex)", data.hex())
    else:
        protocol={0:"ClientHello",1:"ServerHello",2:"Certificate",3:"ServerHelloDone",4:"ClientKeyExcnage",5:"ChangeCipherSpec",6:"Finished",255:"Error code", 254:"ECHO Mode", 253:"Data Encryption Mode", 252:"Data Decryption Mode"}
        p = data[0]
        msg_len = int.from_bytes(data[1:5],"little")
        msg = data[5:5+msg_len]
        mac = data[5+msg_len:]
        ret = {"protocol":protocol[p], "Message_len":msg_len,"Message(bytes)":msg,"Message(Hex)":msg.hex(),"MAC":mac}
        import pprint
        print(f"{additional}")
        pprint.pprint(ret)    
    

####################################################################
##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
#MINI TLS start
def start_mini_tls(server:socket):

    #############################################
    #############################################
    #############################################
    #############################################
    #############################################
    # 구현필요
    # 송신 (send_data 함수 사용)
    # 통신1. 난수 생성1. client_random = 
    client_random = gen_random(32)
    # 통신1. Clienthello 송신(client_random)
    send_data(server,protocol_str["ClientHello"],client_random)
    
    # 수신 (get_dat 함수 사용)
    # 통신2. ServerHello 수신(서버 난수) server_random = 
    receivedprotocal2,msg2_len,server_random = get_data(server)
    # 통신3. Certificate 수신(서버 인증서) #base64 인코딩 되어있으며, 디코딩없이 그대로 사용 가능 RSA_Encrypt 함수 사용 cp =  RSA_Encrypt(pub,pt)
    receivedprotocal3,msg3_len,certificate =get_data(server)
    # 통신4. ServerHelloDone 수신()
    ServerHelloDone=get_data(server)
    # 0x01 1바이트가 담겨있음.
    # 송신 (send_data 함수 사용)
    # 통신5. 난수 생성2. PreMasterSecret = 
    PreMasterSecret = gen_random(32)
    # 통신5. 생성한 난수를 서버의 인증서로 암호화 Encrypted_PreMasterSecret =  RSA_Encrypt(pub,PreMasterSecret)
    Encrypted_PreMasterSecret = RSA_Encrypt(certificate,PreMasterSecret)
    # 인증서에 들어있는 서버의 공개키로 암호화한다.
    # 이제 서버도 PreMasterSecret을 가지고 있음.

    # 통신5. ClientKeyExchange 송신(Encrypted_PreMasterSecret)
    send_data(server,protocol_str["ClientKeyExcnage"],Encrypted_PreMasterSecret)
    # // PreMasterSecret을 들키면 안되므로 암호화해서 보낸다
    # - PreMasterSecret, client_random, server_random을 활용한 MasterSecret 생성
    # //서버가 PreMasterSecret으로 일련의 과정을 거쳐 Master키를 생성한다. 이 Master키가 대칭키..
    #    Hint.   HKDF(PreMasterSecret,"master secret",client_random,server_random,48)
    MasterSecret = HKDF(PreMasterSecret,"master secret",client_random,server_random,48)

    # - MasterSecret을 활용한 KEYBLOB 생성
    #    Hint.   HKDF(MasterSecret,"key expansion",client_random,server_random,96)
    KeyBlob = HKDF(MasterSecret,"key expansion",client_random,server_random,96)
    # - KEYBLOB 분리 (Client_MAC_KEY, Server_MAC_KEY, Client_Cipher_KEY, Server_Cipher_KEY, Client_Cipher_IV, Server_Cipher_IV)
    Client_MAC_KEY = KeyBlob[0:16]
    Server_MAC_KEY = KeyBlob[16:32]
    Client_Cipher_KEY = KeyBlob[32:48]
    Server_Cipher_KEY = KeyBlob[48:64]
    Client_Cipher_IV = KeyBlob[64:80]
    Server_Cipher_IV = KeyBlob[80:96]
    # 통신6. ChangeCipherSepc 송신(0x1)
    send_data(server,protocol_str["ChangeCipherSpec"],bytes([1]))
    # 통신7. Finished 송신(0x1) 
    Finished = bytes([1]) # 0x01
    send_data(server,protocol_str["Finished"], Finished)
    
    # 수신 (get_dat 함수 사용)
    # 통신8. ChangeCipherSpec 수신(0x1)
    ChageCipherSpec = get_data(server)
    # 통신9. Finished 수신(0x1)
    Finished = get_data(server)
    
    # 핸드셰이크 종료
    
    ECHO_CLIENT(server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV)
##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
####################################################################   

####################################################################
##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
#ECHO_CLIENT START!
def ECHO_CLIENT(server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV):
    
    while True:
        #############################################
        #############################################
        #############################################
        #############################################
        #############################################
        # 구현필요
        # 메시지를 입력하기 (ex: msg = input("SendMsg:").encode())
        msg = input("SendMsg:").encode()
        # 입력한 msg를 서버에 송신(send_enc_data 사용)
        send_enc_data(server,protocol_str["ECHO Mode"],msg,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)

        # 서버에서 반환한 메시지를 수신 (get_enc_data 사용)
        #
        ##############################################
        
        # 만약 주고받은 메시지가 quit, QUIT, Quit 중 하나인경우 통신 종료
        protocol, msg_len, msg, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if protocol == protocol_str["ECHO Mode"]:
            if (msg == b"quit") or (msg == b"QUIT") or (msg == b"Quit"):
                return

##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
####################################################################


####################################################################
##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
def send_enc_data(soc:socket, protocol:int,msg:bytes,MAC_KEY, CIPHER_KEY, CIPHER_IV):
    #############################################
    #############################################
    #############################################
    #############################################
    #############################################
    # 구현필요 (send data 참고) (|| <<- 연접 기호)
    # 1. MAC값 계산용 data 생성   data = 프로토콜 || 메시지길이 || 전송하고자 하는 메시지
    # 2. data에 대한 MAC값 계산 - Calc_MAC 함수 활용(HMAC-SHA256)
    # 3. (data || MAC) 암호화    ciphertext = enc(data||mac)  - AES_CBC_Encrypt 함수 활용
    #############################################
    #############################################
    #############################################
    #############################################
    #############################################
    p = protocol.to_bytes(1,"little") # int 형 데이터를 byte로 변환
    # protocol 1바이트고 little endian.. 1바이트니까 상관없긴한데
    msg_len = len(msg).to_bytes(4,"little")
    data = p+msg_len+msg
    # 프로토콜 1바이트 + 메시지길이 4바이트 + 메시지 or 연산
    MAC = Calc_MAC(MAC_KEY,data)
    ciphertext=AES_CBC_Encrypt(CIPHER_KEY,CIPHER_IV,data+MAC)

    time.sleep(0.5) 
    soc.sendall(ciphertext)
    
    #for debug
    print_packet("Send ->",data+MAC) 
    print_packet("Send(enc) ->",ciphertext,True)
    


def get_enc_data(soc:socket,SERVER_MAC_KEY,SERVER_CIPHER_KEY,SERVER_CIPHER_IV):
    time.sleep(0.5)
    data = soc.recv(BUFFER_SIZE)    
    print_packet("Get(enc) : ",data,True)
    
    #############################################
    #############################################
    #############################################
    #############################################
    #############################################
    # 구현필요    
    #  1. 데이터 복호화 - AES_CBC_Decrypt 함수 활용
    #  2. MAC 값 검증 - Calc_MAC 함수 활용(HMAC-SHA256)
    #  3. 복호화된 데이터(프로토콜 || 메시지길이 || 메시지) 파싱 
    #############################################
    #############################################
    #############################################
    #############################################
    #############################################
    # Decrypt 함수로 그냥 복호화함
    dec = AES_CBC_Decrypt(SERVER_CIPHER_KEY,SERVER_CIPHER_IV,data)
    print_packet("Get(Dec) :",dec,False)
    dec_len = len(dec)
    mac=Calc_MAC(SERVER_MAC_KEY,dec[0:-16])
    
    pro = dec[0] # protocol 1바이트
    msg_len = dec[1:5] # 메시지길이 4바이트
    msg = dec[5:-16]
    
    return (pro, msg_len, msg, mac)

##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
####################################################################

# 이 이하로는 주요 함수 구현 예시(그대로 사용하여도 됨)

#패킷 송신용 함수 그대로 사용 가능
def send_data(soc:socket, protocol:int,msg:bytes):
    pro = protocol.to_bytes(1,"little") # int형 데이터를 byte로 변환
    msg_len = len(msg).to_bytes(4,"little") # 메시지 길이를 byte로 변환 - little endian 사용
    data = pro+msg_len+msg # 패킷 데이터 : 프로토콜 || 메시지길이 || 메시지

    time.sleep(0.5)  #패킷을 너무 빠르게 전송하면 주고받기가 되지않기에 지연시간 추가
    soc.sendall(data) # 패킷 전송
    
    #for debug
    print_packet("C>",data) # 보낸 데이터 보기용
    
#패킷 수신용 함수 그대로 사용 가능
def get_data(soc:socket):
    packetsize = 5
    time.sleep(0.5)
    data = soc.recv(BUFFER_SIZE)
    if len(data)<=packetsize: #protocol + message_len =5 
        return False # msg가 없는경우
    
    protocol= data[0] # 프로토콜 파싱
    
    msg_len = int.from_bytes(data[1:5],"little") #메시지 길이 파싱 (byte -> int)
    packetsize +=msg_len # 패킷 길이 = protocol(1바이트) + message_len(4바이트) + 실제 메시지길이
    
    msg = data[5:5+msg_len] # 메시지 파싱
        
    #for debug
    print_packet("S<",data) # 받은 데이터 보기용
    
    return (protocol, msg_len, msg)




# 안전한 난수생성기 (num byte만큼 난수 생성)
def gen_random(num):
    import os
    return os.urandom(num)


# RSA로 암호화/ 인코딩된 인증서 넣으면 자동으로 인식
def RSA_Encrypt(pub,data):
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Cipher import PKCS1_OAEP as RSA_OAEP
    
    publickey = RSA.import_key(pub)
    encryptor = RSA_OAEP.new(publickey)
    ciphertext = encryptor.encrypt(data)
    return ciphertext


#AES CBC모드 암호화
def AES_CBC_Encrypt(key:bytes,iv:bytes,data:bytes)->bytes:
    from Crypto.Cipher import AES
    if len(key) not in [16,24,32]:
        print("AES Key length error")
        exit(1)
    if len(iv) != 16:
        print("IV length error")
        exit(1)
    
    # padding
    padlen = 16-len(data)%16
    pad = bytes([padlen]*padlen)
    data = data + pad
    
    cipher = AES.new(key,AES.MODE_CBC,iv)
    return cipher.encrypt(data)   
    

#AES CBC모드 복호화
def AES_CBC_Decrypt(key:bytes,iv:bytes,data:bytes)->bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(key,AES.MODE_CBC,iv)
    pt = cipher.decrypt(data)
    
    #unpadding
    padlen = pt[-1]
    if padlen>16:
        print("padding check failed 1")
        return None
    
    pad = bytes([padlen]*padlen)
    if pt[-1*padlen : ] != pad:
        print("padding check failed 2")
        return None
    return pt[:-1*padlen]



#HMAC-SHA256 계산한 결과의 상위 16바이트 반환
def Calc_MAC(mackey,data):
    hmac_obj = hmac.new(mackey,digestmod=hashlib.sha256)
    hmac_obj.update(data)
    return hmac_obj.digest()[:16]


#HKDF 함수
def HKDF(Secret, label, c_random,s_random,outlen):
    if type(label)==str:
        label= label.encode()
    ret=b""
    seed = c_random+s_random
    while len(ret)<outlen:
        hmac_obj = hmac.new(Secret, digestmod=hashlib.sha256)
        hmac_obj.update(label+seed)
        digest =hmac_obj.digest()
        seed = digest[:]
        ret+=digest
    return ret[:outlen]


# 이 이하로 수정 금지
def main(server:socket):
    start_mini_tls(server)
    
if __name__=='__main__':
    
    HOST = "210.123.39.43"
    PORT = 55555
    ADDRESS = (HOST,PORT)
    server = socket(AF_INET, SOCK_STREAM)
    server.connect(ADDRESS)
    server.settimeout(360)
    main(server)    
    server.close()