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
          4:"ClientKeyExchange",
          5:"ChangeCipherSpec",
          6:"Finished",
          255:"Error code", 
          254:"ECHO Mode", 
          253:"Data Decryption Mode"}
protocol_str={"ClientHello":0,
            "ServerHello":1,
            "Certificate":2,
            "ServerHelloDone":3,
            "ClientKeyExchange":4,
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
        protocol={0:"ClientHello",1:"ServerHello",2:"Certificate",3:"ServerHelloDone",4:"ClientKeyExchange",5:"ChangeCipherSpec",6:"Finished",255:"Error code", 254:"ECHO Mode", 253:"Data Encryption Mode", 252:"Data Decryption Mode"}
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
    client_random=gen_random(32)
    # 통신1. Clienthello 송신(client_random)
    send_data(server,protocol_str["ClientHello"],client_random)
    
    # 수신 (get_dat 함수 사용)
    # get_data(server) 가 None이면 오류..뜸
    protocol2,msg2_len,msg2 = get_data(server)
    # 프로토콜이 맞는지 확인
    if protocol2 != protocol_str["ServerHello"]:
        print("Protocol2 Error")
        return 0
    # 통신2. ServerHello 수신(서버 난수) server_random = 
    # 서버에서 서버 난수를 받는다.
    
    server_random = msg2
    # 통신3. Certificate 수신(서버 인증서) #base64 인코딩 되어있으며, 디코딩없이 그대로 사용 가능 RSA_Encrypt 함수 사용 cp =  RSA_Encrypt(pub,pt)
    protocol3,msg3_len,msg3 = get_data(server)
    # 프로토콜 확인 후 맞으면 Certificate 수신.
    if protocol3 != protocol_str["Certificate"]:
        print("Protocol3 error")
        return 0
    Certificate = msg3
    # 통신4. ServerHelloDone 수신()
    protocol4,msg4_len,msg4 = get_data(server)
    # 프로토콜 확인
    if protocol4 != protocol_str["ServerHelloDone"]:
        print("Protocol4 error")
        return 0
    ServerHelloDone = msg4
    # 송신 (send_data 함수 사용)
    # 통신5. 난수 생성2. PreMasterSecret = 
    PreMasterSecret=gen_random(32)
    # 통신5. 생성한 난수를 서버의 인증서로 암호화 Encrypted_PreMasterSecret =  RSA_Encrypt(pub,PreMasterSecret)
    Encrypted_PreMasterSecret = RSA_Encrypt(Certificate,PreMasterSecret)
    # 통신5. ClientKeyExchange 송신(Encrypted_PreMasterSecret)
    #
    send_data(server,protocol_str["ClientKeyExchange"],Encrypted_PreMasterSecret)
    # - PreMasterSecret, client_random, server_random을 활용한 MasterSecret 생성
    #    Hint.   HKDF(PreMasterSecret,"master secret",client_random,server_random,48)
    MasterSecret = HKDF(PreMasterSecret,"master secret",client_random,server_random,48)
    # - MasterSecret을 활용한 KEYBLOB 생성
    KeyBlob = HKDF(MasterSecret,"key expansion",client_random,server_random,96)
    # client_random 이랑 server_random으로 master secret 생성..
    #    Hint.   HKDF(MasterSecret,"key expansion",client_random,server_random,96)
    # client_random 이랑 server_random으로 master secret 생성..
    # - KEYBLOB 분리 (Client_MAC_KEY, Server_MAC_KEY, Client_Cipher_KEY, Server_Cipher_KEY, Client_Cipher_IV, Server_Cipher_IV)
    Client_MAC_KEY=KeyBlob[0:16]
    Server_MAC_KEY=KeyBlob[16:32]
    Client_Cipher_KEY=KeyBlob[32:48]
    Server_Cipher_KEY=KeyBlob[48:64]
    Client_Cipher_IV=KeyBlob[64:80]
    Server_Cipher_IV=KeyBlob[80:96]
    # 통신6. ChangeCipherSepc 송신(0x1)
    #
    ChangeCipherSpec=b'\x01'
    send_data(server,protocol_str["ChangeCipherSpec"],ChangeCipherSpec)
    # 통신7. Finished 송신(0x1) 
    Finished=b'\x01'
    send_data(server,protocol_str["Finished"],Finished)
    # 수신 (get_dat 함수 사용)
    protocol8,msg8_len,msg8=get_data(server)
    if protocol8 != protocol_str["ChangeCipherSpec"]:
        print("Protocol8 error")
        return 0
    # 통신8. ChangeCipherSpec 수신(0x1)
    #
    
    # 통신9. Finished 송신(0x1) 
    protocol9,msg9_len,msg9=get_data(server)
    if protocol9 != protocol_str["Finished"]:
        print("Protocol9 error")
        return 0
    Finished = msg9
    
    # 핸드셰이크 종료
    
    padding_oracle(server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV)
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
        # 입력한 msg를 서버에 송신(send_enc_data 사용)
        # 서버에서 반환한 메시지를 수신 (get_enc_data 사용)
        #
        ##############################################
        
        # 만약 주고받은 메시지가 quit, QUIT, Quit 중 하나인경우 통신 종료
        protocol, msg_len, msg, mac = get_enc_data()
        if protocol == protocol_str["ECHO Mode"]:
            if (msg == b"quit") or (msg == b"QUIT") or (msg == b"Quit"):
                return

##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
####################################################################

# 0~255까지 16진수 데이터
hex=[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
     0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
     0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
     0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
     0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
     0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
     0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
     0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
     0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
     0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
     0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
     0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
     0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
     0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF]

iv = bytes.fromhex("34b1e9b2d225011c5ae338544fbd24fe")
ciphertext = bytes.fromhex("57b6d0daa5e288793479ba1089eb912d9086b46288a33c9ab664e05ecb919b03")
ciphertext_len = len(ciphertext)
# 블록 몇바이트인지는 .. 안구해도 되나?
c1 = ciphertext[:16] # 첫번째 블록 16바이트
c2 = ciphertext[16:] # 두번째 블록 16바이트

def padding_oracle(server,Client_MAC_KEY,Server_MAC_KEY,Client_Cipher_KEY,Server_Cipher_KEY,Client_Cipher_IV,Server_Cipher_IV):
    #pad_len 이진 검색
    send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:7]+hex[0].to_bytes(1,"little")+c1[8:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
    protocol,msg_len, question1, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
    if question1 == b"Wrong padding":
        send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+hex[0].to_bytes(1,"little")+c1[4:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, question2, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if question2 == b"Wrong padding":
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+hex[0].to_bytes(1,"little")+c1[2:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, question3, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if question3 == b"Wrong padding":
                send_enc_data(server,protocol_str["Data Decryption Mode"], hex[0].to_bytes(1,"little")+c1[1:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
                protocol,msg_len, question4, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
                if question4 == b"Wrong padding":
                    pad_len=0x10
                else:
                    pad_len=0x0F
            else:
                send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+hex[0].to_bytes(1,"little")+c1[3:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
                protocol,msg_len, question4, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
                if question4 == b"Wrong padding":
                    pad_len=0x0E
                else:
                    pad_len=0x0D
        else:
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:5]+hex[0].to_bytes(1,"little")+c1[6:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, question3, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if question3 == b"Wrong padding":
                send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+hex[0].to_bytes(1,"little")+c1[5:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
                protocol,msg_len, question4, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
                if question4 == b"Wrong padding":
                    pad_len=0x0c
                else:
                    pad_len=0x0B
            else:
                send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+hex[0].to_bytes(1,"little")+c1[3:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
                protocol,msg_len, question4, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
                if question4 == b"Wrong padding":
                    pad_len=0x0A
                else:
                    pad_len=0x09
    else:
        send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:11]+hex[0].to_bytes(1,"little")+c1[12:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, question2, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if question2 == b"Wrong padding":
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:9]+hex[0].to_bytes(1,"little")+c1[10:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, question3, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if question3 == b"Wrong padding":
                send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:8]+hex[0].to_bytes(1,"little")+c1[9:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
                protocol,msg_len, question4, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
                if question4 == b"Wrong padding":
                    pad_len=0x08
                else:
                    pad_len=0x07
            else:
                send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:10]+hex[0].to_bytes(1,"little")+c1[11:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
                protocol,msg_len, question4, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
                if question4 == b"Wrong padding":
                    pad_len=0x06
                else:
                    pad_len=0x05
        else:
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:13]+hex[0].to_bytes(1,"little")+c1[14:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, question3, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if question3 == b"Wrong padding":
                send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:12]+hex[0].to_bytes(1,"little")+c1[13:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
                protocol,msg_len, question4, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
                if question4 == b"Wrong padding":
                    pad_len=0x04
                else:
                    pad_len=0x03
            else:
                send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:14]+hex[0].to_bytes(1,"little")+c1[15:]+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
                protocol,msg_len, question4, mac = get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
                if question4 == b"Wrong padding":
                    pad_len=0x02
                else:
                    pad_len=0x01
    ##
    ##pad_len에 따른 분류    
    if pad_len == 0x01:
        I16=c1[15]^0x01
        
        I16p=I16^0x02
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:14]+j+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I15=m^0x02
    
        I15p=I15^0x03
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x03
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:13]+j+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I14=m^0x03
    
        I14p=I14^0x04
        I15p=I15^0x04
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x04
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:12]+j+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I13=m^0x04
    
        I13p=I13^0x05
        I14p=I14^0x05
        I15p=I15^0x05
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x05
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:11]+j+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I12=m^0x05
    
        I12p=I12^0x06
        I13p=I13^0x06
        I14p=I14^0x06
        I15p=I15^0x06
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x06
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:10]+j+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break    
        I11=m^0x06
    
        I11p=I11^0x07
        I12p=I12^0x07
        I13p=I13^0x07
        I14p=I14^0x07
        I15p=I15^0x07
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x07
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:9]+j+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I10=m^0x07
    
        I10p=I10^0x08
        I11p=I11^0x08
        I12p=I12^0x08
        I13p=I13^0x08
        I14p=I14^0x08
        I15p=I15^0x08
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x08
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:8]+j+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I9=m^0x08
    
        I9p=I9^0x09
        I10p=I10^0x09
        I11p=I11^0x09
        I12p=I12^0x09
        I13p=I13^0x09
        I14p=I14^0x09
        I15p=I15^0x09
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x09
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:7]+j+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I8=m^0x09
    
        I8p=I8^0x0A
        I9p=I9^0x0A
        I10p=I10^0x0A
        I11p=I11^0x0A
        I12p=I12^0x0A
        I13p=I13^0x0A
        I14p=I14^0x0A
        I15p=I15^0x0A
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0A
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:6]+j+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                print(m)             
                break
        I7=m^0x0A
    
        I7p=I7^0x0B
        I8p=I8^0x0B
        I9p=I9^0x0B
        I10p=I10^0x0B
        I11p=I11^0x0B
        I12p=I12^0x0B
        I13p=I13^0x0B
        I14p=I14^0x0B
        I15p=I15^0x0B
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0B
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:5]+j+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I6=m^0x0B
    
        I6p=I6^0x0C
        I7p=I7^0x0C
        I8p=I8^0x0C
        I9p=I9^0x0C
        I10p=I10^0x0C
        I11p=I11^0x0C
        I12p=I12^0x0C
        I13p=I13^0x0C
        I14p=I14^0x0C
        I15p=I15^0x0C
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0C
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I5=m^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5,I6,I7,I8,I9,I10,I11,I12,I13,I14,I15))
        
        p2=[]
        for i in range(15):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3],p2[4],p2[5],p2[6],p2[7],p2[8],p2[9],p2[10],p2[11],p2[12],p2[13],p2[14]))
    
    ##
    ##

    if pad_len == 0x02:
    
        I16=c1[15]^0x02
        I15=c1[14]^0x02
    
        I15p=I15^0x03
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x03
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:13]+j+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I14=m^0x03
    
        I14p=I14^0x04
        I15p=I15^0x04
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x04
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:12]+j+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I13=m^0x04
    
        I13p=I13^0x05
        I14p=I14^0x05
        I15p=I15^0x05
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x05
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:11]+j+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I12=m^0x05
    
        I12p=I12^0x06
        I13p=I13^0x06
        I14p=I14^0x06
        I15p=I15^0x06
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x06
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:10]+j+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break    
        I11=m^0x06
    
        I11p=I11^0x07
        I12p=I12^0x07
        I13p=I13^0x07
        I14p=I14^0x07
        I15p=I15^0x07
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x07
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:9]+j+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I10=m^0x07
    
        I10p=I10^0x08
        I11p=I11^0x08
        I12p=I12^0x08
        I13p=I13^0x08
        I14p=I14^0x08
        I15p=I15^0x08
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x08
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:8]+j+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I9=m^0x08
    
        I9p=I9^0x09
        I10p=I10^0x09
        I11p=I11^0x09
        I12p=I12^0x09
        I13p=I13^0x09
        I14p=I14^0x09
        I15p=I15^0x09
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x09
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:7]+j+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I8=m^0x09
    
        I8p=I8^0x0A
        I9p=I9^0x0A
        I10p=I10^0x0A
        I11p=I11^0x0A
        I12p=I12^0x0A
        I13p=I13^0x0A
        I14p=I14^0x0A
        I15p=I15^0x0A
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0A
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:6]+j+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                print(m)             
                break
        I7=m^0x0A
    
        I7p=I7^0x0B
        I8p=I8^0x0B
        I9p=I9^0x0B
        I10p=I10^0x0B
        I11p=I11^0x0B
        I12p=I12^0x0B
        I13p=I13^0x0B
        I14p=I14^0x0B
        I15p=I15^0x0B
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0B
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:5]+j+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I6=m^0x0B
    
        I6p=I6^0x0C
        I7p=I7^0x0C
        I8p=I8^0x0C
        I9p=I9^0x0C
        I10p=I10^0x0C
        I11p=I11^0x0C
        I12p=I12^0x0C
        I13p=I13^0x0C
        I14p=I14^0x0C
        I15p=I15^0x0C
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0C
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I5=m^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5,I6,I7,I8,I9,I10,I11,I12,I13,I14))
        
        p2=[]
        for i in range(14):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3],p2[4],p2[5],p2[6],p2[7],p2[8],p2[9],p2[10],p2[11],p2[12],p2[13]))
    
    ##
    ##
    if pad_len == 0x03:
        
        I16=c1[15]^0x03
        I15=c1[14]^0x03
        I14=c1[13]^0x03
    
        I14p=I14^0x04
        I15p=I15^0x04
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x04
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:12]+j+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I13=m^0x04
    
        I13p=I13^0x05
        I14p=I14^0x05
        I15p=I15^0x05
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x05
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:11]+j+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I12=m^0x05
    
        I12p=I12^0x06
        I13p=I13^0x06
        I14p=I14^0x06
        I15p=I15^0x06
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x06
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:10]+j+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break    
        I11=m^0x06
    
        I11p=I11^0x07
        I12p=I12^0x07
        I13p=I13^0x07
        I14p=I14^0x07
        I15p=I15^0x07
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x07
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:9]+j+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I10=m^0x07
    
        I10p=I10^0x08
        I11p=I11^0x08
        I12p=I12^0x08
        I13p=I13^0x08
        I14p=I14^0x08
        I15p=I15^0x08
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x08
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:8]+j+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I9=m^0x08
    
        I9p=I9^0x09
        I10p=I10^0x09
        I11p=I11^0x09
        I12p=I12^0x09
        I13p=I13^0x09
        I14p=I14^0x09
        I15p=I15^0x09
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x09
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:7]+j+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I8=m^0x09
    
        I8p=I8^0x0A
        I9p=I9^0x0A
        I10p=I10^0x0A
        I11p=I11^0x0A
        I12p=I12^0x0A
        I13p=I13^0x0A
        I14p=I14^0x0A
        I15p=I15^0x0A
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0A
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:6]+j+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                print(m)             
                break
        I7=m^0x0A
    
        I7p=I7^0x0B
        I8p=I8^0x0B
        I9p=I9^0x0B
        I10p=I10^0x0B
        I11p=I11^0x0B
        I12p=I12^0x0B
        I13p=I13^0x0B
        I14p=I14^0x0B
        I15p=I15^0x0B
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0B
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:5]+j+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I6=m^0x0B
    
        I6p=I6^0x0C
        I7p=I7^0x0C
        I8p=I8^0x0C
        I9p=I9^0x0C
        I10p=I10^0x0C
        I11p=I11^0x0C
        I12p=I12^0x0C
        I13p=I13^0x0C
        I14p=I14^0x0C
        I15p=I15^0x0C
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0C
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I5=m^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5,I6,I7,I8,I9,I10,I11,I12,I13))
        
        p2=[]
        for i in range(13):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3],p2[4],p2[5],p2[6],p2[7],p2[8],p2[9],p2[10],p2[11],p2[12]))
        
    ##
    ##
    if pad_len == 0x04:
        
        I16=c1[15]^0x04
        I15=c1[14]^0x04
        I14=c1[13]^0x04
        I13=c1[12]^0x04
    
        I13p=I13^0x05
        I14p=I14^0x05
        I15p=I15^0x05
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x05
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:11]+j+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I12=m^0x05
    
        I12p=I12^0x06
        I13p=I13^0x06
        I14p=I14^0x06
        I15p=I15^0x06
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x06
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:10]+j+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break    
        I11=m^0x06
    
        I11p=I11^0x07
        I12p=I12^0x07
        I13p=I13^0x07
        I14p=I14^0x07
        I15p=I15^0x07
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x07
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:9]+j+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I10=m^0x07
    
        I10p=I10^0x08
        I11p=I11^0x08
        I12p=I12^0x08
        I13p=I13^0x08
        I14p=I14^0x08
        I15p=I15^0x08
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x08
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:8]+j+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I9=m^0x08
    
        I9p=I9^0x09
        I10p=I10^0x09
        I11p=I11^0x09
        I12p=I12^0x09
        I13p=I13^0x09
        I14p=I14^0x09
        I15p=I15^0x09
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x09
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:7]+j+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I8=m^0x09
    
        I8p=I8^0x0A
        I9p=I9^0x0A
        I10p=I10^0x0A
        I11p=I11^0x0A
        I12p=I12^0x0A
        I13p=I13^0x0A
        I14p=I14^0x0A
        I15p=I15^0x0A
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0A
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:6]+j+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                print(m)             
                break
        I7=m^0x0A
    
        I7p=I7^0x0B
        I8p=I8^0x0B
        I9p=I9^0x0B
        I10p=I10^0x0B
        I11p=I11^0x0B
        I12p=I12^0x0B
        I13p=I13^0x0B
        I14p=I14^0x0B
        I15p=I15^0x0B
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0B
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:5]+j+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I6=m^0x0B
    
        I6p=I6^0x0C
        I7p=I7^0x0C
        I8p=I8^0x0C
        I9p=I9^0x0C
        I10p=I10^0x0C
        I11p=I11^0x0C
        I12p=I12^0x0C
        I13p=I13^0x0C
        I14p=I14^0x0C
        I15p=I15^0x0C
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0C
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I5=m^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5,I6,I7,I8,I9,I10,I11,I12))
        
        p2=[]
        for i in range(12):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3],p2[4],p2[5],p2[6],p2[7],p2[8],p2[9],p2[10],p2[11]))
        
    ##
    ##
    if pad_len == 0x05:
        
        I16=c1[15]^0x05
        I15=c1[14]^0x05
        I14=c1[13]^0x05
        I13=c1[12]^0x05
        I12=c1[11]^0x05
        
    
        I12p=I12^0x06
        I13p=I13^0x06
        I14p=I14^0x06
        I15p=I15^0x06
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x06
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:10]+j+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break    
        I11=m^0x06
    
        I11p=I11^0x07
        I12p=I12^0x07
        I13p=I13^0x07
        I14p=I14^0x07
        I15p=I15^0x07
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x07
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:9]+j+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I10=m^0x07
    
        I10p=I10^0x08
        I11p=I11^0x08
        I12p=I12^0x08
        I13p=I13^0x08
        I14p=I14^0x08
        I15p=I15^0x08
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x08
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:8]+j+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I9=m^0x08
    
        I9p=I9^0x09
        I10p=I10^0x09
        I11p=I11^0x09
        I12p=I12^0x09
        I13p=I13^0x09
        I14p=I14^0x09
        I15p=I15^0x09
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x09
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:7]+j+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I8=m^0x09
    
        I8p=I8^0x0A
        I9p=I9^0x0A
        I10p=I10^0x0A
        I11p=I11^0x0A
        I12p=I12^0x0A
        I13p=I13^0x0A
        I14p=I14^0x0A
        I15p=I15^0x0A
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0A
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:6]+j+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                print(m)             
                break
        I7=m^0x0A
    
        I7p=I7^0x0B
        I8p=I8^0x0B
        I9p=I9^0x0B
        I10p=I10^0x0B
        I11p=I11^0x0B
        I12p=I12^0x0B
        I13p=I13^0x0B
        I14p=I14^0x0B
        I15p=I15^0x0B
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0B
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:5]+j+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I6=m^0x0B
    
        I6p=I6^0x0C
        I7p=I7^0x0C
        I8p=I8^0x0C
        I9p=I9^0x0C
        I10p=I10^0x0C
        I11p=I11^0x0C
        I12p=I12^0x0C
        I13p=I13^0x0C
        I14p=I14^0x0C
        I15p=I15^0x0C
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0C
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I5=m^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5,I6,I7,I8,I9,I10,I11))
        
        p2=[]
        for i in range(11):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:X02}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3],p2[4],p2[5],p2[6],p2[7],p2[8],p2[9],p2[10]))
        ##
        ##
    if pad_len == 0x06:
        
        I16=c1[15]^0x06
        I15=c1[14]^0x06
        I14=c1[13]^0x06
        I13=c1[12]^0x06
        I12=c1[11]^0x06
        I11=c1[10]^0x06
    
        I11p=I11^0x07
        I12p=I12^0x07
        I13p=I13^0x07
        I14p=I14^0x07
        I15p=I15^0x07
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x07
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:9]+j+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I10=m^0x07
    
        I10p=I10^0x08
        I11p=I11^0x08
        I12p=I12^0x08
        I13p=I13^0x08
        I14p=I14^0x08
        I15p=I15^0x08
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x08
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:8]+j+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I9=m^0x08
    
        I9p=I9^0x09
        I10p=I10^0x09
        I11p=I11^0x09
        I12p=I12^0x09
        I13p=I13^0x09
        I14p=I14^0x09
        I15p=I15^0x09
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x09
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:7]+j+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I8=m^0x09
    
        I8p=I8^0x0A
        I9p=I9^0x0A
        I10p=I10^0x0A
        I11p=I11^0x0A
        I12p=I12^0x0A
        I13p=I13^0x0A
        I14p=I14^0x0A
        I15p=I15^0x0A
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0A
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:6]+j+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                print(m)             
                break
        I7=m^0x0A
    
        I7p=I7^0x0B
        I8p=I8^0x0B
        I9p=I9^0x0B
        I10p=I10^0x0B
        I11p=I11^0x0B
        I12p=I12^0x0B
        I13p=I13^0x0B
        I14p=I14^0x0B
        I15p=I15^0x0B
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0B
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:5]+j+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I6=m^0x0B
    
        I6p=I6^0x0C
        I7p=I7^0x0C
        I8p=I8^0x0C
        I9p=I9^0x0C
        I10p=I10^0x0C
        I11p=I11^0x0C
        I12p=I12^0x0C
        I13p=I13^0x0C
        I14p=I14^0x0C
        I15p=I15^0x0C
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0C
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I5=m^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5,I6,I7,I8,I9,I10))
        
        p2=[]
        for i in range(10):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3],p2[4],p2[5],p2[6],p2[7],p2[8],p2[9]))
        
    ##
    ##
    if pad_len == 0x07:
        
        I16=c1[15]^0x07
        I15=c1[14]^0x07
        I14=c1[13]^0x07
        I13=c1[12]^0x07
        I12=c1[11]^0x07
        I11=c1[10]^0x07
        I10=c1[9]^0x07
    
        I10p=I10^0x08
        I11p=I11^0x08
        I12p=I12^0x08
        I13p=I13^0x08
        I14p=I14^0x08
        I15p=I15^0x08
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x08
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:8]+j+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I9=m^0x08
    
        I9p=I9^0x09
        I10p=I10^0x09
        I11p=I11^0x09
        I12p=I12^0x09
        I13p=I13^0x09
        I14p=I14^0x09
        I15p=I15^0x09
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x09
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:7]+j+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I8=m^0x09
    
        I8p=I8^0x0A
        I9p=I9^0x0A
        I10p=I10^0x0A
        I11p=I11^0x0A
        I12p=I12^0x0A
        I13p=I13^0x0A
        I14p=I14^0x0A
        I15p=I15^0x0A
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0A
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:6]+j+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                print(m)             
                break
        I7=m^0x0A
    
        I7p=I7^0x0B
        I8p=I8^0x0B
        I9p=I9^0x0B
        I10p=I10^0x0B
        I11p=I11^0x0B
        I12p=I12^0x0B
        I13p=I13^0x0B
        I14p=I14^0x0B
        I15p=I15^0x0B
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0B
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:5]+j+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I6=m^0x0B
    
        I6p=I6^0x0C
        I7p=I7^0x0C
        I8p=I8^0x0C
        I9p=I9^0x0C
        I10p=I10^0x0C
        I11p=I11^0x0C
        I12p=I12^0x0C
        I13p=I13^0x0C
        I14p=I14^0x0C
        I15p=I15^0x0C
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0C
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I5=m^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5,I6,I7,I8,I9))
        
        p2=[]
        for i in range(9):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3],p2[4],p2[5],p2[6],p2[7],p2[8]))
        
        ##
        ##
    if pad_len == 0x08:
        
        I16=c1[15]^0x08
        I15=c1[14]^0x08
        I14=c1[13]^0x08
        I13=c1[12]^0x08
        I12=c1[11]^0x08
        I11=c1[10]^0x08
        I10=c1[9]^0x08
        I9=c1[8]^0x08
        
        I9p=I9^0x09
        I10p=I10^0x09
        I11p=I11^0x09
        I12p=I12^0x09
        I13p=I13^0x09
        I14p=I14^0x09
        I15p=I15^0x09
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x09
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:7]+j+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I8=m^0x09
    
        I8p=I8^0x0A
        I9p=I9^0x0A
        I10p=I10^0x0A
        I11p=I11^0x0A
        I12p=I12^0x0A
        I13p=I13^0x0A
        I14p=I14^0x0A
        I15p=I15^0x0A
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0A
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:6]+j+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                print(m)             
                break
        I7=m^0x0A
    
        I7p=I7^0x0B
        I8p=I8^0x0B
        I9p=I9^0x0B
        I10p=I10^0x0B
        I11p=I11^0x0B
        I12p=I12^0x0B
        I13p=I13^0x0B
        I14p=I14^0x0B
        I15p=I15^0x0B
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0B
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:5]+j+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I6=m^0x0B
    
        I6p=I6^0x0C
        I7p=I7^0x0C
        I8p=I8^0x0C
        I9p=I9^0x0C
        I10p=I10^0x0C
        I11p=I11^0x0C
        I12p=I12^0x0C
        I13p=I13^0x0C
        I14p=I14^0x0C
        I15p=I15^0x0C
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0C
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I5=m^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5,I6,I7,I8))
        
        p2=[]
        for i in range(8):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3],p2[4],p2[5],p2[6],p2[7]))
        
        ##
        ##
    if pad_len == 0x09:
        I16=c1[15]^0x09
        I15=c1[14]^0x09
        I14=c1[13]^0x09
        I13=c1[12]^0x09
        I12=c1[11]^0x09
        I11=c1[10]^0x09
        I10=c1[9]^0x09
        I9=c1[8]^0x09
        I8=c1[7]^0x09
    
        I8p=I8^0x0A
        I9p=I9^0x0A
        I10p=I10^0x0A
        I11p=I11^0x0A
        I12p=I12^0x0A
        I13p=I13^0x0A
        I14p=I14^0x0A
        I15p=I15^0x0A
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0A
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:6]+j+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                print(m)             
                break
        I7=m^0x0A
    
        I7p=I7^0x0B
        I8p=I8^0x0B
        I9p=I9^0x0B
        I10p=I10^0x0B
        I11p=I11^0x0B
        I12p=I12^0x0B
        I13p=I13^0x0B
        I14p=I14^0x0B
        I15p=I15^0x0B
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0B
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:5]+j+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I6=m^0x0B
    
        I6p=I6^0x0C
        I7p=I7^0x0C
        I8p=I8^0x0C
        I9p=I9^0x0C
        I10p=I10^0x0C
        I11p=I11^0x0C
        I12p=I12^0x0C
        I13p=I13^0x0C
        I14p=I14^0x0C
        I15p=I15^0x0C
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0C
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I5=m^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5,I6,I7))
        
        p2=[]
        for i in range(7):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3],p2[4],p2[5],p2[6]))
        
        ##
        ##
    if pad_len == 0x0A:
       
        I16=c1[15]^0x0A
        I15=c1[14]^0x0A
        I14=c1[13]^0x0A
        I13=c1[12]^0x0A
        I12=c1[11]^0x0A
        I11=c1[10]^0x0A
        I10=c1[9]^0x0A
        I9=c1[8]^0x0A
        I8=c1[7]^0x0A
        I7=c1[6]^0x0A
    
        I7p=I7^0x0B
        I8p=I8^0x0B
        I9p=I9^0x0B
        I10p=I10^0x0B
        I11p=I11^0x0B
        I12p=I12^0x0B
        I13p=I13^0x0B
        I14p=I14^0x0B
        I15p=I15^0x0B
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0B
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:5]+j+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I6=m^0x0B
    
        I6p=I6^0x0C
        I7p=I7^0x0C
        I8p=I8^0x0C
        I9p=I9^0x0C
        I10p=I10^0x0C
        I11p=I11^0x0C
        I12p=I12^0x0C
        I13p=I13^0x0C
        I14p=I14^0x0C
        I15p=I15^0x0C
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0C
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I5=m^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5,I6))
        
        p2=[]
        for i in range(6):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3],p2[4],p2[5]))
        
        ##
        ##
    if pad_len == 0x0B:
        I16=c1[15]^0x0B
        I15=c1[14]^0x0B
        I14=c1[13]^0x0B
        I13=c1[12]^0x0B
        I12=c1[11]^0x0B
        I11=c1[10]^0x0B
        I10=c1[9]^0x0B
        I9=c1[8]^0x0B
        I8=c1[7]^0x0B
        I7=c1[6]^0x0B
        I6=c1[5]^0x0B
    
    
        I6p=I6^0x0C
        I7p=I7^0x0C
        I8p=I8^0x0C
        I9p=I9^0x0C
        I10p=I10^0x0C
        I11p=I11^0x0C
        I12p=I12^0x0C
        I13p=I13^0x0C
        I14p=I14^0x0C
        I15p=I15^0x0C
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0C
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I5=m^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5))
        
        p2=[]
        for i in range(5):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3],p2[4]))
        
        ##
        ##
    if pad_len == 0x0C:
        I16=c1[15]^0x0C
        I15=c1[14]^0x0C
        I14=c1[13]^0x0C
        I13=c1[12]^0x0C
        I12=c1[11]^0x0C
        I11=c1[10]^0x0C
        I10=c1[9]^0x0C
        I9=c1[8]^0x0C
        I8=c1[7]^0x0C
        I7=c1[6]^0x0C
        I6=c1[5]^0x0C
        I5=c1[4]^0x0C
    
        I5p=I5^0x0D
        I6p=I6^0x0D
        I7p=I7^0x0D
        I8p=I8^0x0D
        I9p=I9^0x0D
        I10p=I10^0x0D
        I11p=I11^0x0D
        I12p=I12^0x0D
        I13p=I13^0x0D
        I14p=I14^0x0D
        I15p=I15^0x0D
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0D
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I4=m^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4))
        
        p2=[]
        for i in range(4):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2],p2[3]))
        ##
        ##
    if pad_len == 0x0D:
        
        I16=c1[15]^0x0D
        I15=c1[14]^0x0D
        I14=c1[13]^0x0D
        I13=c1[12]^0x0D
        I12=c1[11]^0x0D
        I11=c1[10]^0x0D
        I10=c1[9]^0x0D
        I9=c1[8]^0x0D
        I8=c1[7]^0x0D
        I7=c1[6]^0x0D
        I6=c1[5]^0x0D
        I5=c1[4]^0x0D
        I4=c1[3]^0x0D
    
        I4p=I4^0x0E
        I5p=I5^0x0E
        I6p=I6^0x0E
        I7p=I7^0x0E
        I8p=I8^0x0E
        I9p=I9^0x0E
        I10p=I10^0x0E
        I11p=I11^0x0E
        I12p=I12^0x0E
        I13p=I13^0x0E
        I14p=I14^0x0E
        I15p=I15^0x0E
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0E
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I3=m^0x0E
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}{:02X}".format(I1,I2,I3))
        
        p2=[]
        for i in range(3):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}{:02X}".format(p2[0],p2[1],p2[2]))
        ##
        ##
    if pad_len == 0x0E:
        
        I16=c1[15]^0x0E
        I15=c1[14]^0x0E
        I14=c1[13]^0x0E
        I13=c1[12]^0x0E
        I12=c1[11]^0x0E
        I11=c1[10]^0x0E
        I10=c1[9]^0x0E
        I9=c1[8]^0x0E
        I8=c1[7]^0x0E
        I7=c1[6]^0x0E
        I6=c1[5]^0x0E
        I5=c1[4]^0x0E
        I4=c1[3]^0x0E
        I3=c1[2]^0x0E
    
    
        I3p=I3^0x0F
        I4p=I4^0x0F
        I5p=I5^0x0F
        I6p=I6^0x0F
        I7p=I7^0x0F
        I8p=I8^0x0F
        I9p=I9^0x0F
        I10p=I10^0x0F
        I11p=I11^0x0F
        I12p=I12^0x0F
        I13p=I13^0x0F
        I14p=I14^0x0F
        I15p=I15^0x0F
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x0F
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], c1[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I2=m^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}{:02X}".format(I1,I2))
        
        p2=[]
        for i in range(2):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}{:02X}".format(p2[0],p2[1]))
    ##
    ##
    if pad_len == 0x0F:
        
        I16=c1[15]^0x0F
        I15=c1[14]^0x0F
        I14=c1[13]^0x0F
        I13=c1[12]^0x0F
        I12=c1[11]^0x0F
        I11=c1[10]^0x0F
        I10=c1[9]^0x0F
        I9=c1[8]^0x0F
        I8=c1[7]^0x0F
        I7=c1[6]^0x0F
        I6=c1[5]^0x0F
        I5=c1[4]^0x0F
        I4=c1[3]^0x0F
        I3=c1[2]^0x0F
        I2=c1[1]^0x0F
    
        I2p=I2^0x10
        I3p=I3^0x10
        I4p=I4^0x10
        I5p=I5^0x10
        I6p=I6^0x10
        I7p=I7^0x10
        I8p=I8^0x10
        I9p=I9^0x10
        I10p=I10^0x10
        I11p=I11^0x10
        I12p=I12^0x10
        I13p=I13^0x10
        I14p=I14^0x10
        I15p=I15^0x10
        I16p=I16^0x10
        c2b=I2p.to_bytes(1,"little")
        c3b=I3p.to_bytes(1,"little")
        c4b=I4p.to_bytes(1,"little")
        c5b=I5p.to_bytes(1,"little")
        c6b=I6p.to_bytes(1,"little")   
        c7b=I7p.to_bytes(1,"little") 
        c8b=I8p.to_bytes(1,"little")
        c9b=I9p.to_bytes(1,"little")
        c10b=I10p.to_bytes(1,"little")
        c11b=I11p.to_bytes(1,"little")
        c12b=I12p.to_bytes(1,"little")
        c13b=I13p.to_bytes(1,"little")
        c14b=I14p.to_bytes(1,"little")
        c15b=I15p.to_bytes(1,"little")
        I16p=I16^0x10
        c16b=I16p.to_bytes(1,"little")
        for i in hex:
            j=hex[i].to_bytes(1,"little")
            send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c2,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
            protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
            if msg != b"Wrong padding":
                m=hex[i]
                break
        I1=m^0x10
        
        I=bytes.fromhex("{:02X}".format(I1))
        
        p2=[]
        for i in range(1):
            p2.append(I[i]^ciphertext[i])
        
        pp1=bytes.fromhex("{:02X}".format(p2[0]))
    ##
    ##    
    if pad_len == 0x10:
        
        pp1=bytes.fromhex("")
    
    ####
    ####
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:15]+j+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I16=m^0x01
    
    I16p=I16^0x02
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:14]+j+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I15=m^0x02
    
    I15p=I15^0x03
    I16p=I16^0x03
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:13]+j+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I14=m^0x03
    
    I14p=I14^0x04
    I15p=I15^0x04
    I16p=I16^0x04
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:12]+j+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I13=m^0x04
    
    I13p=I13^0x05
    I14p=I14^0x05
    I15p=I15^0x05
    I16p=I16^0x05
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:11]+j+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I12=m^0x05
    
    I12p=I12^0x06
    I13p=I13^0x06
    I14p=I14^0x06
    I15p=I15^0x06
    I16p=I16^0x06
    c12b=I12p.to_bytes(1,"little")
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:10]+j+c12b+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break    
    I11=m^0x06
    
    I11p=I11^0x07
    I12p=I12^0x07
    I13p=I13^0x07
    I14p=I14^0x07
    I15p=I15^0x07
    I16p=I16^0x07
    c11b=I11p.to_bytes(1,"little")
    c12b=I12p.to_bytes(1,"little")
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:9]+j+c11b+c12b+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            print(m)
            break
    I10=m^0x07
    
    I10p=I10^0x08
    I11p=I11^0x08
    I12p=I12^0x08
    I13p=I13^0x08
    I14p=I14^0x08
    I15p=I15^0x08
    I16p=I16^0x08
    c10b=I10p.to_bytes(1,"little")
    c11b=I11p.to_bytes(1,"little")
    c12b=I12p.to_bytes(1,"little")
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:8]+j+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I9=m^0x08
    
    I9p=I9^0x09
    I10p=I10^0x09
    I11p=I11^0x09
    I12p=I12^0x09
    I13p=I13^0x09
    I14p=I14^0x09
    I15p=I15^0x09
    I16p=I16^0x09
    c9b=I9p.to_bytes(1,"little")
    c10b=I10p.to_bytes(1,"little")
    c11b=I11p.to_bytes(1,"little")
    c12b=I12p.to_bytes(1,"little")
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:7]+j+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I8=m^0x09
    
    I8p=I8^0x0A
    I9p=I9^0x0A
    I10p=I10^0x0A
    I11p=I11^0x0A
    I12p=I12^0x0A
    I13p=I13^0x0A
    I14p=I14^0x0A
    I15p=I15^0x0A
    I16p=I16^0x0A
    c8b=I8p.to_bytes(1,"little")
    c9b=I9p.to_bytes(1,"little")
    c10b=I10p.to_bytes(1,"little")
    c11b=I11p.to_bytes(1,"little")
    c12b=I12p.to_bytes(1,"little")
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:6]+j+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            print(m)             
            break
    I7=m^0x0A
    
    I7p=I7^0x0B
    I8p=I8^0x0B
    I9p=I9^0x0B
    I10p=I10^0x0B
    I11p=I11^0x0B
    I12p=I12^0x0B
    I13p=I13^0x0B
    I14p=I14^0x0B
    I15p=I15^0x0B
    I16p=I16^0x0B   
    c7b=I7p.to_bytes(1,"little") 
    c8b=I8p.to_bytes(1,"little")
    c9b=I9p.to_bytes(1,"little")
    c10b=I10p.to_bytes(1,"little")
    c11b=I11p.to_bytes(1,"little")
    c12b=I12p.to_bytes(1,"little")
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:5]+j+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I6=m^0x0B
    
    I6p=I6^0x0C
    I7p=I7^0x0C
    I8p=I8^0x0C
    I9p=I9^0x0C
    I10p=I10^0x0C
    I11p=I11^0x0C
    I12p=I12^0x0C
    I13p=I13^0x0C
    I14p=I14^0x0C
    I15p=I15^0x0C
    I16p=I16^0x0C
    c6b=I6p.to_bytes(1,"little")   
    c7b=I7p.to_bytes(1,"little") 
    c8b=I8p.to_bytes(1,"little")
    c9b=I9p.to_bytes(1,"little")
    c10b=I10p.to_bytes(1,"little")
    c11b=I11p.to_bytes(1,"little")
    c12b=I12p.to_bytes(1,"little")
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:4]+j+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I5=m^0x0C
    
    I5p=I5^0x0D
    I6p=I6^0x0D
    I7p=I7^0x0D
    I8p=I8^0x0D
    I9p=I9^0x0D
    I10p=I10^0x0D
    I11p=I11^0x0D
    I12p=I12^0x0D
    I13p=I13^0x0D
    I14p=I14^0x0D
    I15p=I15^0x0D
    I16p=I16^0x0D
    c5b=I5p.to_bytes(1,"little")
    c6b=I6p.to_bytes(1,"little")   
    c7b=I7p.to_bytes(1,"little") 
    c8b=I8p.to_bytes(1,"little")
    c9b=I9p.to_bytes(1,"little")
    c10b=I10p.to_bytes(1,"little")
    c11b=I11p.to_bytes(1,"little")
    c12b=I12p.to_bytes(1,"little")
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:3]+j+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I4=m^0x0D
    
    I4p=I4^0x0E
    I5p=I5^0x0E
    I6p=I6^0x0E
    I7p=I7^0x0E
    I8p=I8^0x0E
    I9p=I9^0x0E
    I10p=I10^0x0E
    I11p=I11^0x0E
    I12p=I12^0x0E
    I13p=I13^0x0E
    I14p=I14^0x0E
    I15p=I15^0x0E
    I16p=I16^0x0E
    c4b=I4p.to_bytes(1,"little")
    c5b=I5p.to_bytes(1,"little")
    c6b=I6p.to_bytes(1,"little")   
    c7b=I7p.to_bytes(1,"little") 
    c8b=I8p.to_bytes(1,"little")
    c9b=I9p.to_bytes(1,"little")
    c10b=I10p.to_bytes(1,"little")
    c11b=I11p.to_bytes(1,"little")
    c12b=I12p.to_bytes(1,"little")
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:2]+j+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I3=m^0x0E
    
    I3p=I3^0x0F
    I4p=I4^0x0F
    I5p=I5^0x0F
    I6p=I6^0x0F
    I7p=I7^0x0F
    I8p=I8^0x0F
    I9p=I9^0x0F
    I10p=I10^0x0F
    I11p=I11^0x0F
    I12p=I12^0x0F
    I13p=I13^0x0F
    I14p=I14^0x0F
    I15p=I15^0x0F
    I16p=I16^0x0F
    c3b=I3p.to_bytes(1,"little")
    c4b=I4p.to_bytes(1,"little")
    c5b=I5p.to_bytes(1,"little")
    c6b=I6p.to_bytes(1,"little")   
    c7b=I7p.to_bytes(1,"little") 
    c8b=I8p.to_bytes(1,"little")
    c9b=I9p.to_bytes(1,"little")
    c10b=I10p.to_bytes(1,"little")
    c11b=I11p.to_bytes(1,"little")
    c12b=I12p.to_bytes(1,"little")
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], iv[:1]+j+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I2=m^0x0F
    
    I2p=I2^0x10
    I3p=I3^0x10
    I4p=I4^0x10
    I5p=I5^0x10
    I6p=I6^0x10
    I7p=I7^0x10
    I8p=I8^0x10
    I9p=I9^0x10
    I10p=I10^0x10
    I11p=I11^0x10
    I12p=I12^0x10
    I13p=I13^0x10
    I14p=I14^0x10
    I15p=I15^0x10
    I16p=I16^0x10
    c2b=I2p.to_bytes(1,"little")
    c3b=I3p.to_bytes(1,"little")
    c4b=I4p.to_bytes(1,"little")
    c5b=I5p.to_bytes(1,"little")
    c6b=I6p.to_bytes(1,"little")   
    c7b=I7p.to_bytes(1,"little") 
    c8b=I8p.to_bytes(1,"little")
    c9b=I9p.to_bytes(1,"little")
    c10b=I10p.to_bytes(1,"little")
    c11b=I11p.to_bytes(1,"little")
    c12b=I12p.to_bytes(1,"little")
    c13b=I13p.to_bytes(1,"little")
    c14b=I14p.to_bytes(1,"little")
    c15b=I15p.to_bytes(1,"little")
    c16b=I16p.to_bytes(1,"little")
    for i in hex:
        j=hex[i].to_bytes(1,"little")
        send_enc_data(server,protocol_str["Data Decryption Mode"], j+c2b+c3b+c4b+c5b+c6b+c7b+c8b+c9b+c10b+c11b+c12b+c13b+c14b+c15b+c16b+c1,Client_MAC_KEY,Client_Cipher_KEY,Client_Cipher_IV)
        protocol,msg_len, msg, mac=get_enc_data(server,Server_MAC_KEY,Server_Cipher_KEY,Server_Cipher_IV)
        if msg != b"Wrong padding":
            m=hex[i]
            break
    I1=m^0x10
    
    I=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(I1,I2,I3,I4,I5,I6,I7,I8,I9,I10,I11,I12,I13,I14,I15,I16))
    p1=[]
    for i in range(16):
            p1.append(I[i]^iv[i])
    pp2=bytes.fromhex("{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}".format(p1[0],p1[1],p1[2],p1[3],p1[4],p1[5],p1[6],p1[7],p1[8],p1[9],p1[10],p1[11],p1[12],p1[13],p1[14],p1[15]))
    
    pt=pp2+pp1
     
    with open(r'C:\Users\tplay\OneDrive\바탕 화면\6.png',"rb") as f:
        data=f.read()
        ivf=data[:16]
        ciphertextf=data[16:]
    dec=AES_CBC_Decrypt(pt, ivf, ciphertextf)

    with open(r'C:\Users\tplay\OneDrive\바탕 화면\6.png',"wb") as f:
        f.write(dec)
    
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
    protocol = protocol.to_bytes(1,'little')
    msg_len = len(msg).to_bytes(4,'little')
    data = protocol+msg_len+msg
    MAC=Calc_MAC(MAC_KEY,data)
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
    dec = AES_CBC_Decrypt(SERVER_CIPHER_KEY,SERVER_CIPHER_IV,data)
    print_packet("Get(Dec) :",dec,False)
    dec_len = len(dec)
    mac=Calc_MAC(SERVER_MAC_KEY,dec[0:-16])
    if dec[dec_len-16:] == mac:
        pro = dec[0] # protocol 1바이트
        msg_len = dec[1:5] # 메시지길이 4바이트
        msg = dec[5:-16]
    else:
        print("MAC error")
        return 0
    return (protocol, msg_len, msg, mac)

##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!##
####################################################################

# 이 이하로는 주요 함수 구현 예시(그대로 사용하여도 됨)

#패킷 송신용 함수 그대로 사용 가능
def send_data(soc:socket, protocol:int,msg:bytes):
    p = protocol.to_bytes(1,"little") # int형 데이터를 byte로 변환
    msg_len = len(msg).to_bytes(4,"little") # 메시지 길이를 byte로 변환 - little endian 사용
    data = p+msg_len+msg # 패킷 데이터 : 프로토콜 || 메시지길이 || 메시지

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
    
    if len(data)!= packetsize: # 패킷을 비정상적으로 받은 경우
        return False
    
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
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP as RSA_OAEP
    
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
    PORT = 33333
    ADDRESS = (HOST,PORT)
    server = socket(AF_INET, SOCK_STREAM)
    server.connect(ADDRESS)
    server.settimeout(360)
    main(server)    
    server.close()
    

