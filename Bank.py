import hashlib
import hmac
import re
import secrets
import time
from Crypto.Cipher import AES
import os
import sys
import json
import base64
import socket
from Crypto.Util.Padding import pad
import signal
from Crypto.Util.Padding import unpad
import threading
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from datetime import datetime, timedelta

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # print("Error: Invalid argument", file=sys.stderr, flush=True)
        #print(255)
        sys.exit(255)


class Bank:
    def __init__(self, port=3000, auth_file='bank.auth'): #nosso atributos
        self.port = port
        self.auth_file = auth_file
        self.accounts = {}
        self.account_locks ={}
        self.lock_accounts=threading.Lock()
        self.running = True  #flag para ajustar no shutdown
        self.threads = []
        self.nonces = set()
        self.nonces_lock = threading.Lock()
        self.semaforo=threading.Semaphore(20)
        self.MAX = 10000

    def start(self):
        # Verifica se o auth file existe
        if os.path.isfile(self.auth_file):
            # print("Error: auth_file already exists")
            sys.exit(255)

        self.generateRSAKeys()
        print("created", flush=True)#nunca mais alterar authfile depois desta linha

        # Inicia socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(10)
        self.server_socket.settimeout(1) #self running é executado de segundo a segundo, quando damos kill ou ctrl+c ele espera que as threads processem.

        while self.running: #isto 
            try:
                client, addr = self.server_socket.accept() #objeto socket vindo do client, addr ip e porta do cliente, bloqueia aqui ate client se ligar
                thread = threading.Thread(target=self.client_status, args=(client,))
                thread.start()
                self.threads.append(thread)#guarda threads geradas em cada conexacao para depois dar join quando executar o SIGTERM
            except socket.timeout:                                                               # pq as threads do cliente nao bloqueiam o server e podemos dar CTR+C no server quando quisermos, pode é ser é pior porcausas das transacoes mas acho que ta tchill
                continue  
            except Exception as e:
                return "255"
                break  

    def client_status(self, client):
        with self.semaforo: #mais que 20 threads 
            with client:
                try:
                    chaveSessaoCifrada = recv_all(client) #recebe auth
                    chaveSessaoCifrada = json.loads(chaveSessaoCifrada.decode()) #JSON da session KEY e dict
                    #verifica se recebeu uma chave de sessao do cliente
                    if "session_key" not in chaveSessaoCifrada:
                        # client.sendall(json.dumps({"error": "Auth Failed"}).encode()) #manda para client primeira mensagem
                        client.sendall(json.dumps("255").encode())
                        return
                    # Decifrar com a chave privada, utilizamos codigo RSA — Cryptography 45.0.0.dev1 documentation
                    session_key = self.decrypt_with_PrivateKey(chaveSessaoCifrada["session_key"])#obtemos do lado do servidor a chave de sessao
                    if session_key==-1:
                        # client.sendall(json.dumps({"error": "Auth Failed"}).encode()) #falha na auth
                        client.sendall(json.dumps("255").encode())
                        return
                    client.sendall(json.dumps({"message": "Secure Session Made"}).encode())
                    while True:
                        pedidosCliente = recv_all(client) #recebe pedidos
                        if not pedidosCliente:
                            break 
                        #PERGUNTA
                        request = json.loads(pedidosCliente.decode()) #da decode dos bytes para JSON e de JSON para dict com loads ficando 
                        response = self.checkRequest(request,session_key)
                        if response != "255" and response != "63":
                            rollback_balance = response.get("rollback_balance") 
                            account = response.get("account") 
                            responseC = dict(response) 
                            responseC.pop("rollback_balance", None)
                            print(responseC,flush=True)
                        else:
                            responseC=response
                        #RESPOSTA
                        try:
                            response_cifrado = self.encrypt_response(responseC,session_key) #CIFRA resposta
                            client.sendall(json.dumps(response_cifrado).encode())
                            if "error" not in response:     
                                #print(response, flush=True) # temos que dar do server tb
                                pass
                        except:
                            with self.lock_accounts:
                                if rollback_balance is not None and account in self.accounts:
                                    self.accounts[account]["balance"] = rollback_balance #ROLBACK se falhar a transacao no sendall
                            print("protocol_error", flush=True)
                except socket.timeout:
                    print("protocol_error", flush=True)
                    
                except Exception:
                    print("protocol_error", flush=True)

    def encrypt_response(self, response_dict,session_key):
        aesKey,hmacKey,salt=self.derivateKeys(session_key)
        #VAMOS SER NOS A CIFRAR AQUI E FAZR O MAC SEGUIR PAPEL E ATM IMPLEMENTACAO
        iv,ct,hBin=self.aes_HMAC_Encrypt(response_dict,salt,aesKey,hmacKey)
        dictRequest={"iv":iv,"cyphertext":ct,"hash":hBin,"saltDerivation": base64.b64encode(salt).decode('utf-8')}
        return dictRequest
    
    def aes_HMAC_Encrypt(self,packageToSend,saltDerivado,aesKey,hmacKey):
        #AES
        packageToSend=json.dumps(packageToSend)#Meter em JSON
        cipher = AES.new(aesKey, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(packageToSend.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode('utf-8')
        ct = base64.b64encode(ct_bytes).decode('utf-8')
        
        #HMAC
        h = hmac.new(hmacKey,saltDerivado + cipher.iv + ct_bytes,hashlib.sha256)
        hBin = base64.b64encode(h.digest()).decode()   #mete em string base64
        return iv,ct,hBin

    def checkRequest(self, request,session_key):
        try:
            #PACOTE ENVIADO DO CLIENTE
            salt = base64.b64decode(request.get("saltDerivation"))  
            iv = base64.b64decode(request.get("iv"))
            cypertext = base64.b64decode(request.get("cyphertext"))
            hmac_client= base64.b64decode(request.get("hash"))
            #SE NAO CONTIVER ALGUM DOS PARAMETROS FALHA
            if not iv or not cypertext or not hmac_client: #ele verifica se os binarios sao null ou neste caso b
                # return {"Error": "Missing fields"}
                return "255"
            
            aesKey,hmacKey,_=self.derivateKeys(session_key,salt)  #chavesGeradas usa salt do client
            hmac_data = salt + iv + cypertext # ou entra aqui no create
            h = hmac.new(hmacKey, hmac_data, hashlib.sha256).digest()

            if not hmac.compare_digest(h, hmac_client):
                # return {"error": "HMAC verification failed"}
                return "255"
            packageClient=self.aesDecrypt(iv,cypertext,aesKey)#decifra

        except Exception as e:
                print(e, flush=True) 

        #Verificar Nounce com Lock Global ao seu set 
        data = packageClient.get("nounce")
        decoded_json = base64.b64decode(data).decode('utf-8')
        nounce_data = json.loads(decoded_json)
        timestamp_obj = datetime.strptime(nounce_data["timestamp"], "%Y-%m-%d %H:%M:%S")
        
        with self.nonces_lock:
            if nounce_data["nonce"] in self.nonces or datetime.now() - timestamp_obj > timedelta(seconds=10):
                print("protocol_error",flush=True)
                return "63"
            self.nonces.add(nounce_data["nonce"])
            if len(self.nonces) > self.MAX:
                self.nonces.clear()

        action = packageClient.get("action")
        account=packageClient.get("account")
        if action == "create":                              #CIFRAR TODO O DICT COM A CHAVE PUBLICA
            balance = packageClient.get("balance")
            HashPIN=packageClient.get("hashPIN")
            with self.lock_accounts: #Lock global no dicionario  
                if account in self.accounts:
                    # return {"error": "Account already exists"}
                    return "255"
                if balance < 10.00:
                    # return {"error": "Initial balance must be >= 10.00"}
                    return "255"
                
                self.accounts[account] = {"balance": balance,"HashPIN": HashPIN}
                self.account_locks[account] = threading.Lock()  #Adicionar um objeto Lock a cada conta
                return {"account": account, "initial_balance": balance}

        elif action == "deposit":                           #DECIFRAR TODO O DICT COM A CHAVE PRIVADA E VERIFICAR
            amount = packageClient.get("amount")
            HashPIN=packageClient.get("hashPIN")
            with self.lock_accounts:
                if account not in self.accounts:
                    # return {"error": "Account not found"}
                    return "255"
                lock = self.account_locks.get(account)
                with lock:
                    if HashPIN !=  self.accounts[account]["HashPIN"]:
                        # return {"error": "Wrong PIN"}
                        return "255"
                    if amount <= 0:
                        # return {"error": "Deposit must be > 0.00"}~
                        return "255"
                    old_balance=self.accounts[account]["balance"]
                    self.accounts[account]["balance"] += amount
                    return {"account": account, "deposit": amount,"rollback_balance": old_balance}
        
        elif action == "withdraw":
            amount = packageClient.get("amount")
            HashPIN=packageClient.get("hashPIN")
            with self.lock_accounts:
                if account not in self.accounts:
                    # return {"error": "Account not found"}
                    return "255"
                lock = self.account_locks.get(account)
                with lock:
                    if HashPIN !=  self.accounts[account]["HashPIN"]:
                        # return {"error": "Wrong PIN"}
                        return "255"
                    if amount <= 0:
                        # return {"error": "Withdraw must be > 0.00"}
                        return "255"
                    if self.accounts[account]["balance"] - amount < 0:
                        return "255"
                    
                    old_balance=self.accounts[account]["balance"]
                    self.accounts[account]["balance"] -= amount
                    return {"account": account, "withdraw": amount,"rollback_balance": old_balance}

        elif action == "get_balance":
            HashPIN=packageClient.get("hashPIN")
            with self.lock_accounts:
                if account not in self.accounts:
                    # return {"error": "Account not found"}
                    return "255"
                lock = self.account_locks.get(account)
                with lock:
                    if HashPIN !=  self.accounts[account]["HashPIN"]:
                        # return {"error": "Wrong PIN"}
                        return "255"
                    return {"account": account, "balance": self.accounts[account]["balance"]}
        
        # return {"error": "Invalid request"}
        return "255"
    
    def derivateKeys(self,session_key,salt_for_the2KeysRequest=None): 
        #MAKE two keys based on a simetricKey
        if salt_for_the2KeysRequest is None:
            salt_for_the2KeysRequest = secrets.token_bytes(16)
        aes_key,hmac_key= self.deriveAES_HMAC_keys(session_key,salt_for_the2KeysRequest)
        return aes_key,hmac_key,salt_for_the2KeysRequest
            
    def deriveAES_HMAC_keys(self,session_key,salt_for_the2Keys):
        # derive
        kdf = Argon2id(
            salt=salt_for_the2Keys,
            length=32,                #SERVER PRECISA DE EFETUAR EXATAMENTE O MESMO PARA GERAR A MESMA CHAVE
            iterations=1,
            lanes=4,
            memory_cost=64 * 1024,
            ad=None,
            secret=None,
        )
        key = kdf.derive(session_key) 
        aes_key = key[:16] #CHAVE PARA AES
        hmac_key = key[16:] #CHAVE PARA HMAC

        return aes_key,hmac_key

    def aesDecrypt(self,iv,cyphertext,aesKey):
        try:
            cipher = AES.new(aesKey, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(cyphertext), AES.block_size)
            return json.loads(pt.decode())
        except (ValueError, KeyError):

            # return {"Error": "Incorrect decryption"}
            return "255"
    
    def generateRSAKeys(self):
            private_key = rsa.generate_private_key(     #Deviamos rever os atributos pq nao sei se assim ta 100 por cento seguro e o default, chave 3072 bits
            public_exponent=65537,
            key_size=2048
        )   
            #Privada    
            with open(self.auth_file + ".key", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption() #confirmar se podemos deixar assim no enunciado
                ))
            #Publica
            public_key = private_key.public_key()
            with open(self.auth_file, "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
                
    def decrypt_with_PrivateKey(self, msg):
        try:
            encrypted_key = base64.b64decode(msg) 
            with open(self.auth_file + ".key", "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            session_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return session_key
        except (ValueError, FileNotFoundError, Exception):
            return -1            
    
    def shutdown(self, signum, frame):
        print("Exiting...", flush=True)
        sys.stdout.flush()
        self.running = False
        self.server_socket.close()

        for thread in self.threads:
            thread.join() #espera que as threads todas acabem que forem iniciados no start so depois fecha server, nao ha problemas de transacao assim.

        try:
            os.remove(self.auth_file + ".key")
            os.remove(self.auth_file)
        except:
            pass
        sys.exit(0)   

def recv_all(sock, max_length=2048):
    sock.settimeout(10)
    buffer = b""
    start = time.time()
    while len(buffer) < max_length:
        if time.time() - start > 10:
            raise socket.timeout  
        try:
            chunk = sock.recv(1)
            if not chunk:
                break
            buffer += chunk
            if buffer.endswith(b'}') or buffer.endswith(b']'):
                try:
                    json.loads(buffer.decode()) 
                    break
                except:
                    continue
        except socket.timeout:
            raise  
    return buffer


def detectar_argumentos_duplicados(argv):
    vistos = set()
    for i, arg in enumerate(argv):
        if arg.startswith('-') and arg in vistos:
            sys.exit(255)
        vistos.add(arg)

def validar_port(port_str):
    try:
        port = int(port_str)
    except ValueError:
        # raise argparse.ArgumentTypeError(f"Porta '{port_str}' deve ser um número inteiro.")
        raise argparse.ArgumentTypeError("255")
    if not (1024 <= port <= 65535):
        # raise argparse.ArgumentTypeError(f"Porta '{port}' inválida: deve estar entre 1024 e 65535.")
        raise argparse.ArgumentTypeError("255")
    return port

# Validador para nomes de arquivos (usado em auth-file e card-file)
def validar_file_name(filename):
    # O nome deve ter entre 1 e 127 caracteres, conter apenas: letras minúsculas, dígitos, underscores, hífens e pontos.
    if not (1 <= len(filename) <= 127):
        # raise argparse.ArgumentTypeError(f"O nome de arquivo '{filename}' deve ter entre 1 e 127 caracteres.")
        raise argparse.ArgumentTypeError("255")
    if filename in {".", ".."}:
        # raise argparse.ArgumentTypeError(f"O nome de arquivo '{filename}' não é permitido.")
        raise argparse.ArgumentTypeError("255")
    if not re.fullmatch(r"[_\-\.\d a-z]+".replace(" ", ""), filename):
        # Removemos o espaço extra usado para facilitar a leitura da regex.
        # raise argparse.ArgumentTypeError(f"O nome de arquivo '{filename}' contém caracteres inválidos. Permitidos: underscores, hífens, pontos, dígitos e letras minúsculas.")
        raise argparse.ArgumentTypeError("255")
    return filename

# Validador específico para arquivo de autenticação: deve ser um nome de arquivo válido que termine com ".auth"
def validar_auth_file(filename):
    filename = validar_file_name(filename)
    if not filename.endswith(".auth"):
        # raise argparse.ArgumentTypeError(f"O arquivo de autenticação '{filename}' deve terminar com '.auth'.")
        raise argparse.ArgumentTypeError("255")
    return filename

if __name__ == "__main__":
    detectar_argumentos_duplicados(sys.argv[1:])
    parser = CustomArgumentParser(description="Bank server")
    parser.add_argument("-p", "--port", type=validar_port, default=3000, help="Port to listen on")
    parser.add_argument("-s", "--auth-file", type=validar_auth_file, default="bank.auth", help="Auth file name")
    args = parser.parse_args()

    bank = Bank(port=args.port, auth_file=args.auth_file) #cria objeto Bank com port e authfile.
    #Capta logo o signal
    #Capta logo o signal 
    signal.signal(signal.SIGTERM, bank.shutdown)
    signal.signal(signal.SIGINT, bank.shutdown)
    bank.start()#liga server



