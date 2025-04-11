from asyncio import exceptions
from functools import partial
import hashlib
import hmac
import re
import os
import string
import sys
import json
import base64
import socket
import secrets
import argparse
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from argon2 import PasswordHasher
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from datetime import datetime

#MUDA O ERRO DE 2 QUE GERA O ARGPASS PARA 255
class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # print("Error: Invalid argument", file=sys.stderr, flush=True)
        #print(255)
        sys.exit(255)

class ATM:
    def __init__(self, bank_ip='127.0.0.1', bank_port=3000,auth_file='bank.auth', card_file=None):
        self.bank_ip = bank_ip
        self.bank_port = bank_port
        self.auth_file=auth_file
        self.card_file = card_file
    def generateSimetricKey(self):
        simetric_key = secrets.token_bytes(32) #chaveSimetrica de Sessão
        self.session_key = simetric_key        #Pode ser de atributo porque vai ser a mesma por toda a sessao e ATM nao tem problemas

        #Verifica que nao falha
        if self.session_key==-1:
            # print("Error:Failed to generate session Key",flush=True, file=sys.stderr)
            sys.exit(255)

    def send_request(self, request):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((self.bank_ip, self.bank_port))
            #AUTH
            session_key_encrypted=self.encrypt_with_PublicKey(self.session_key) #Cifrar chave de sessao para só o servidor saber quemé  
            auth = json.dumps({"session_key": base64.b64encode(session_key_encrypted).decode()}).encode()
            client.sendall(auth) #manda primeiro auth 
            authresponse = json.loads(recv_all(client).decode())#resposta ao auth
            #PERGUNTA
            client.sendall(json.dumps(request).encode())#depois manda pacote 
            #RESPOSTA
            responseCifrado = json.loads(recv_all(client).decode()) #Vem cifrada
            response = self.decrypt_response(responseCifrado)
            client.close()
        except Exception as e:
            sys.exit(63)
        return response
    
    def decrypt_response(self,responseCifrado):
        salt = base64.b64decode(responseCifrado.get("saltDerivation"))  
        iv = base64.b64decode(responseCifrado.get("iv"))
        cypertext = base64.b64decode(responseCifrado.get("cyphertext"))
        hmac_client= base64.b64decode(responseCifrado.get("hash"))

        if not iv or not cypertext or not hmac_client: #ele verifica se os binarios sao null ou neste caso b
            return {"Error": "Missing fields"}
        
        aesKey,hmacKey,_= self.derivateKeys(salt)

        hmac_data = salt + iv + cypertext # ou entra aqui no create
        h = hmac.new(hmacKey, hmac_data, hashlib.sha256).digest()

        if not hmac.compare_digest(h, hmac_client):
            return {"error": "HMAC verification failed"}
        
        packageClient=self.aesDecrypt(iv,cypertext,aesKey)#decifra

        return packageClient

    def aesDecrypt(self,iv,cyphertext,aesKey):
        try:
            cipher = AES.new(aesKey, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(cyphertext), AES.block_size)
            return json.loads(pt.decode())
        except (ValueError, KeyError):
            return {"Error": "Incorrect decryption"}

    def create_account(self, account, balance): #manda create, nome da conta e dinheiro 
        filename = self.card_file if self.card_file else f"{account}.card"
        aesKey,hmacKey,salt=self.derivateKeys()
        #CRIAR CARD
        PIN = ''.join(secrets.choice(string.digits) for i in range(8))
        ph = PasswordHasher() #valores default do argon que por si já sao muito seguros
        hash = ph.hash(PIN)
        account_hash = ph.hash(account)
        #escreve a hash no card
        with open(filename, "w") as f:
             f.write(json.dumps({"account_hash": account_hash, "hashPIN": hash})) #Guarda em JSON facilidae de leitura mais tarde
        #CIFRA E HMAC
        nounce=secrets.token_bytes(16)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = {
            "nonce": base64.b64encode(nounce).decode('utf-8'),
            "timestamp": timestamp,
        }
        data_json = json.dumps(data).encode('utf-8')
        data_b64 = base64.b64encode(data_json).decode('utf-8')
        packageToSend=json.dumps({"action": "create","account": account, "balance": balance,"hashPIN" : hash,"nounce":data_b64}) #Guardar em JSON pq vai ser cifrado
        iv,ct,hBin=self.aes_HMAC_Encrypt(packageToSend,salt,aesKey,hmacKey)
        dictRequest={"iv":iv,"cyphertext":ct,"hash":hBin,"saltDerivation": base64.b64encode(salt).decode('utf-8')} #salt é binario logo tem que ir numa string base 64 como o resto e depois em string
        
        return self.send_request(dictRequest)
    
    def deposit(self, account, amount):
        aesKey,hmacKey,salt=self.derivateKeys()
        try:
            filename = self.card_file if self.card_file else f"{account}.card"
            with open(filename, "r") as f:
                data = json.load(f)
            hash = data["hashPIN"]
        except:
            # print("Error:No cardfile",flush=True, file=sys.stderr)
            sys.exit(255)
        nounce=secrets.token_bytes(16)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = {
            "nonce": base64.b64encode(nounce).decode('utf-8'),
            "timestamp": timestamp,
        }
        data_json = json.dumps(data).encode('utf-8')
        data_b64 = base64.b64encode(data_json).decode('utf-8')
        packageToSend=json.dumps({"action": "deposit","account": account, "amount": amount,"hashPIN" : hash,"nounce":data_b64})
        iv,ct,hBin=self.aes_HMAC_Encrypt(packageToSend,salt,aesKey,hmacKey)
        dictRequest={"iv":iv,"cyphertext":ct,"hash":hBin,"saltDerivation": base64.b64encode(salt).decode('utf-8')} #salt é binario logo tem que ir numa string base 64 como o resto e depois em string
        
        return self.send_request(dictRequest)
           
    def withdraw(self, account, amount):
        aesKey,hmacKey,salt=self.derivateKeys()
        try:
            filename = self.card_file if self.card_file else f"{account}.card"
            with open(filename, "r") as f:
                data = json.load(f)
            hash = data["hashPIN"]
        except:
            # print("Error:No cardfile",flush=True, file=sys.stderr)
            sys.exit(255)
        nounce=secrets.token_bytes(16)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = {
            "nonce": base64.b64encode(nounce).decode('utf-8'),
            "timestamp": timestamp,
        }
        data_json = json.dumps(data).encode('utf-8')
        data_b64 = base64.b64encode(data_json).decode('utf-8')
        packageToSend=json.dumps({"action": "withdraw","account": account, "amount": amount,"hashPIN" : hash,"nounce":data_b64})
        iv,ct,hBin=self.aes_HMAC_Encrypt(packageToSend,salt,aesKey,hmacKey)
        dictRequest={"iv":iv,"cyphertext":ct,"hash":hBin,"saltDerivation": base64.b64encode(salt).decode('utf-8')} #salt é binario logo tem que ir numa string base 64 como o resto e depois em string
        
        return self.send_request(dictRequest)
    
    def get_balance(self, account):
        aesKey,hmacKey,salt=self.derivateKeys()
        try:
            filename = self.card_file if self.card_file else f"{account}.card"
            with open(filename, "r") as f:
                data = json.load(f)
            hash = data["hashPIN"]
        except:
            # print("Error:No cardfile",flush=True, file=sys.stderr)
            sys.exit(255)
        nounce=secrets.token_bytes(16)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = {
            "nonce": base64.b64encode(nounce).decode('utf-8'),
            "timestamp": timestamp,
        }
        data_json = json.dumps(data).encode('utf-8')
        data_b64 = base64.b64encode(data_json).decode('utf-8')
        packageToSend=json.dumps({"action": "get_balance","account": account,"hashPIN" : hash,"nounce":data_b64})
        iv,ct,hBin=self.aes_HMAC_Encrypt(packageToSend,salt,aesKey,hmacKey)
        dictRequest={"iv":iv,"cyphertext":ct,"hash":hBin,"saltDerivation": base64.b64encode(salt).decode('utf-8')} #salt é binario logo tem que ir numa string base 64 como o resto e depois em string
        
        return self.send_request(dictRequest)

    def encrypt_with_PublicKey(self,sessionKey):
        try:
            with open(self.auth_file, "rb") as f:
                    public_key = serialization.load_pem_public_key(f.read())
            encrypted_key = public_key.encrypt(
                    sessionKey,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            return encrypted_key
        except Exception as e:
            # print(f"Error: {e}",flush=True,file=sys.stderr)
            sys.exit(255)
            return -1
        
    def derivateKeys(self,salt_for_the2KeysRequest=None):
        #MAKE two keys based on a simetricKey
        if salt_for_the2KeysRequest is None:
            salt_for_the2KeysRequest = secrets.token_bytes(16)
        aes_key,hmac_key= self.deriveAES_HMAC_keys(self.session_key,salt_for_the2KeysRequest)

        return aes_key,hmac_key,salt_for_the2KeysRequest
    
    def aes_HMAC_Encrypt(self,packageToSend,saltDerivado,aesKey,hmacKey):
        #AES
        cipher = AES.new(aesKey, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(packageToSend.encode(), AES.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        #HMAC
        h = hmac.new(hmacKey,saltDerivado + cipher.iv + ct_bytes,hashlib.sha256)
        hBin = base64.b64encode(h.digest()).decode()   #mete em string base64

        return iv,ct,hBin
    
    def deriveAES_HMAC_keys(self,session_key,salt_for_the2Keys):
        # derive
        kdf = Argon2id(
            salt=salt_for_the2Keys,
            length=32,                              #SERVER PRECISA DE EFETUAR EXATAMENTE O MESMO PARA GERAR A MESMA CHAVE
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

def check_total_length(args_list):
    if sum(len(arg) for arg in args_list) > 4096:
        raise ValueError("Os argumentos da linha de comando não podem exceder 4096 caracteres.")
# Validador para números decimais com duas casas (montantes) no formato "inteiro.fração"
# O inteiro deve ser "0" ou não iniciar com 0 e a fração deve ter exatamente 2 dígitos.
def validar_amount(valor):
    if not re.fullmatch(r"(0|[1-9][0-9]*)\.[0-9]{2}", valor):
        raise argparse.ArgumentTypeError(
            f"O valor '{valor}' não é um montante válido. Ele deve ser um número decimal positivo no formato 'inteiro.fração' (por exemplo, 42.00), "
            "onde o inteiro é '0' ou não inicia com 0 e a fração tem exatamente 2 dígitos."
        )
    # Converter para float e verificar o intervalo: 0.00 a 4294967295.99 inclusivamente.
    valor_float = float(valor)
    if not (0.00 <= valor_float <= 4294967295.99):
        raise argparse.ArgumentTypeError(f"O valor '{valor}' está fora do intervalo permitido (0.00 a 4294967295.99).")
    return valor_float

# Validador para nomes de arquivos (usado em auth-file e card-file)
def validar_file_name(filename):
    # O nome deve ter entre 1 e 127 caracteres, conter apenas: letras minúsculas, dígitos, underscores, hífens e pontos.
    if not (1 <= len(filename) <= 127):
        raise argparse.ArgumentTypeError(f"O nome de arquivo '{filename}' deve ter entre 1 e 127 caracteres.")
    if filename in {".", ".."}:
        raise argparse.ArgumentTypeError(f"O nome de arquivo '{filename}' não é permitido.")
    if not re.fullmatch(r"[_\-\.\d a-z]+".replace(" ", ""), filename):
        # Removemos o espaço extra usado para facilitar a leitura da regex.
        raise argparse.ArgumentTypeError(
            f"O nome de arquivo '{filename}' contém caracteres inválidos. Permitidos: underscores, hífens, pontos, dígitos e letras minúsculas."
        )
    return filename

# Validador específico para arquivo de autenticação: deve ser um nome de arquivo válido que termine com ".auth"
def validar_auth_file(filename):
    filename = validar_file_name(filename)
    if not filename.endswith(".auth"):
        raise argparse.ArgumentTypeError(f"O arquivo de autenticação '{filename}' deve terminar com '.auth'.")
    return filename

# Validador específico para arquivo de cartão: nome de arquivo válido
def validar_card_file(filename, account):
    if not filename.endswith(".card"):
        raise argparse.ArgumentTypeError("O ficheiro deve terminar em .card")

   
    return filename



# Validador para nomes de conta: caracteres permitidos são os mesmos de nomes de arquivo,
# mas o tamanho permitido é de 1 a 122 caracteres e os nomes "." e ".." são válidos.
def validar_account_name(name):
    if not (1 <= len(name) <= 122):
        raise argparse.ArgumentTypeError(f"O nome da conta '{name}' deve ter entre 1 e 122 caracteres.")
    if not re.fullmatch(r"[_\-\.\d a-z]+".replace(" ", ""), name):
        raise argparse.ArgumentTypeError(
            f"O nome da conta '{name}' contém caracteres inválidos. Permitidos: underscores, hífens, pontos, dígitos e letras minúsculas."
        )
    return name

# Validador para endereços IP: IPv4 no formato dotted-decimal
def validar_ip(ip):
    partes = ip.split('.')
    if len(partes) != 4:
        raise argparse.ArgumentTypeError(f"IP '{ip}' inválido: deve conter 4 octetos separados por pontos.")
    for octeto in partes:
        if not octeto.isdigit():
            raise argparse.ArgumentTypeError(f"IP '{ip}' inválido: cada octeto deve ser numérico.")
        valor = int(octeto)
        if not (0 <= valor <= 255):
            raise argparse.ArgumentTypeError(f"IP '{ip}' inválido: cada octeto deve estar entre 0 e 255.")
    return ip

# Validador para portas: números entre 1024 e 65535 inclusivamente
def validar_port(port_str):
    try:
        port = int(port_str)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Porta '{port_str}' deve ser um número inteiro.")
    if not (1024 <= port <= 65535):
        raise argparse.ArgumentTypeError(f"Porta '{port}' inválida: deve estar entre 1024 e 65535.")
    return port


def detectar_argumentos_duplicados(argv):
    vistos = set()
    for i, arg in enumerate(argv):
        if arg.startswith('-') and arg in vistos:
            sys.exit(255)
        vistos.add(arg)

def parse_args():
    # Modificar sys.argv para aceitar argumentos juntos (ex: "-i4000", com ou sem espaços extras)
    fixed_argv = []
    for arg in sys.argv[1:]:  # Ignorar o primeiro elemento (nome do script)
        # Permitir espaços extras entre a flag e o valor, removendo espaços em branco
        arg = arg.strip()
        match = re.match(r"^(-[sipac])\s*([\S]+)$", arg)
        if match:
            fixed_argv.extend([match.group(1), match.group(2)])
        else:
            fixed_argv.append(arg)
    
    # Verificar o comprimento total dos argumentos
    check_total_length(fixed_argv)

    # Cria o parser sem a opção '--'
    parser = CustomArgumentParser(
        description="ATM Client for Bank Communication", 
        allow_abbrev=False,
        add_help=True
    )
    
    # Definir os argumentos obrigatórios iniciais
    parser.add_argument("-s", "--auth-file", type=validar_auth_file, default="bank.auth",
                        help="Arquivo de autenticação (deve terminar com .auth)")
    parser.add_argument("-i", "--ip", type=validar_ip, default="127.0.0.1",
                        help="Endereço IP obrigatório (IPv4 em notação dotted-decimal)")
    parser.add_argument("-p", "--port", type=validar_port, default=3000,
                        help="Porta obrigatória (entre 1024 e 65535)")
    parser.add_argument("-a", "--account", type=validar_account_name, required=True,
                        help="Nome da conta obrigatório (1 a 122 caracteres; permitidos: underscores, hífens, pontos, dígitos e letras minúsculas)")
    
    # Primeiro parse para capturar a conta e definir o nome padrão do arquivo de cartão
    args, unknown = parser.parse_known_args(fixed_argv)
    default_card_file = f"{args.account}.card"
    
    
    # Adicionar argumento para arquivo de cartão
    parser.add_argument("-c", "--card-file", type=partial(validar_card_file, account=args.account), default=default_card_file, help=f"Arquivo do cartão ")

    # Grupo de ações mutuamente exclusivas para transações
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("-n", "--new", type=validar_amount,
                              help="Criar conta com saldo inicial (montante no formato inteiro.fração, ex: 42.00)")
    action_group.add_argument("-d", "--deposit", type=validar_amount,
                              help="Depositar quantia na conta (montante no formato inteiro.fração, ex: 42.00)")
    action_group.add_argument("-w", "--withdraw", type=validar_amount,
                              help="Sacar quantia da conta (montante no formato inteiro.fração, ex: 42.00)")
    action_group.add_argument("-g", "--get-balance", action="store_true",
                              help="Verificar saldo da conta")
    
    # Parse final dos argumentos
    detectar_argumentos_duplicados(fixed_argv)
    args = parser.parse_args(fixed_argv)
    if args.card_file is None:
        args.card_file = f"{args.account}.card"
    if not args.new and os.path.exists(args.card_file):
        try:
            with open(args.card_file, "r") as f:
                data = json.load(f)
            ph = PasswordHasher()
            ph.verify(data["account_hash"], args.account)
        except:
            sys.exit(255)


    return args

if __name__ == "__main__":
    try:
        args = parse_args()
    except Exception as e:
                # print("Error: Protocol_error", flush=True, file=sys.stderr)
                #print(255)
                sys.exit(255)
                
    atm = ATM(bank_ip=args.ip, bank_port=args.port, auth_file=args.auth_file, card_file=args.card_file)#cria objeto ATM
    atm.generateSimetricKey()
    #TODAS AS VALIDACOES QUE FIZERMOS AQUI VAMOS TER QUE VERIFICAR NO SERVIDOR.
    if args.new is not None: 
        if not os.path.isfile(args.card_file):
            if args.new < 10.00:
                # print("Error: Initial balance must be at least 10.00",flush=True,file=sys.stderr)
                #print(255)
                sys.exit(255)
            else:
                request=json.dumps(atm.create_account(args.account, args.new)) #manda ficheiro no modo para enviar
                if request != "\"255\"" and request != "\"63\"":
                    print(request,flush=True)
                elif request == "\"63\"":
                    sys.exit(63)
                else:
                    print(255,flush=True)
        else:
            # print("Error: Already have a card",flush=True,file=sys.stderr)  #confirmar
            sys.exit(255)
    elif args.deposit is not None:
        if args.deposit <= 0:
            # print("Error: Deposit amount must be greater than 0",flush=True,file=sys.stderr)
            sys.exit(255)
        else:
            request=json.dumps(atm.deposit(args.account, args.deposit))
            if request != "\"255\"" and request != "\"63\"":
                print(request,flush=True)
            elif request == "\"63\"":
                    sys.exit(63)
            else:
                print(255,flush=True)
    elif args.withdraw is not None:
        if args.withdraw <= 0:
            # print("Error: Withdraw amount must be greater than 0",flush=True,file=sys.stderr)
            sys.exit(255)
        else: 
            request=json.dumps(atm.withdraw(args.account, args.withdraw))
            if request != "\"255\"" and request != "\"63\"":
                print(request,flush=True)
            elif request == "\"63\"":
                    sys.exit(63)
            else:
                #print(255,flush=True)
                sys.exit(255)
    elif args.get_balance:
        request=json.dumps(atm.get_balance(args.account))
        if request != "\"255\"" and request != "\"63\"":
            print(request,flush=True)
        elif request == "\"63\"":
            sys.exit(63)
        else:
            #print(255,flush=True)
            sys.exit(255)
    else:
        sys.exit(255)