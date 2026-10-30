import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

nome = ""

# Funções auxiliares inicio
def cabeçalho():
    print("====================================")
    print("          GUISA CRYPTO              ")
    print("====================================")
    if nome:
        print(f"Usuário atual: {nome}")

def limpar_tela():
    import os
    os.system('cls' if os.name == 'nt' else 'clear')
# Funções auxiliares fim

# Gera um par de chaves RSA (privada e pública) e salva em arquivos
def gerar_chaves_rsa():
    limpar_tela()
    cabeçalho()

    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    #extrai a chave pública da chave privada
    chave_publica = chave_privada.public_key()

    # Salvar chaves em arquivos
    with open(f"{nome}.pr", "wb") as f:
        f.write(
            chave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(), #A chave privada não será criptografada com senha
            )
        )
    with open(f"{nome}.pu", "wb") as f:
        f.write(
            chave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    print("Par de chaves RSA gerado com sucesso!")
    print(f"Chave privada salva em '{nome}.pr'")
    print(f"Chave pública salva em '{nome}.pu'")
    input("\nPressione ENTER para voltar...")

# Criptografa um arquivo de texto usando AES e salva a chave e IV em um arquivo
def criptografar_arquivo():
    limpar_tela()
    cabeçalho()
    diretorio_programa = Path(__file__).resolve().parent
    print("\nDigite o nome do arquivo (lembre do sufixo '.txt' e que o arquivo deve estar no diretório do programa). ")

    arquivos_txt = [f.name for f in diretorio_programa.glob("*.txt")]
    print("\nArquivos .txt disponíveis:")
    for i, arquivo in enumerate(arquivos_txt, start=1):
        print(f"-> {arquivo}")
    print()

    nome_arquivo = input("----->").strip()
    caminho_arquivo = diretorio_programa / nome_arquivo

    if (
        not nome_arquivo
        or Path(nome_arquivo).name != nome_arquivo
        or Path(nome_arquivo).suffix.lower() != ".txt"
    ):
        print("Arquivo inexistente ou nome informado icorretamente. Certifique-se de que o arquivo está no diretório do programa e que o nome está correto.")
        input("Pressione ENTER para voltar...")
        return

    try:
        texto = caminho_arquivo.read_bytes()
    except FileNotFoundError:
        print(f"Erro: o arquivo '{nome_arquivo}' não foi encontrado.")
        input("Pressione ENTER para voltar...")
        return

    while True:
        limpar_tela()
        cabeçalho()
        print(f"\nArquivo: {nome_arquivo} de ({len(texto)} bytes) selecionado.")
        print("\nEscolha o tamanho da chave AES: ")
        print ("1 para 128 bits ou 2 para 256 bits")
        opcao = input("\nDigite sua escolha (1 ou 2): ").strip()
        if opcao in ("1", "2"):
            tamanho_chave = "128" if opcao == "1" else "256" if opcao == "2" else None
            break
        print("Opção inválida. Digite 1 ou 2.")
        input("Pressione ENTER para tentar novamente...")

    chave = os.urandom(int(tamanho_chave) // 8)
    iv = os.urandom(16)

    cifrador = Cipher(algorithms.AES(chave), modes.CTR(iv)).encryptor()
    texto_cifrado = cifrador.update(texto) + cifrador.finalize()

    caminho_chave = diretorio_programa / "k.txt"
    caminho_saida = diretorio_programa / "y.txt"
    caminho_chave.write_text(
        f"{iv.hex()}\n{chave.hex()}\n",
        encoding="ascii",
    )
    caminho_saida.write_text(texto_cifrado.hex(), encoding="ascii")

    limpar_tela()
    cabeçalho()
    print("\nArquivo criptografado com sucesso!")
    print("IV e chave salvos em 'k.txt' (IV na primeira linha).")
    print("Texto criptografado salvo em 'y.txt'.")
    input("Pressione ENTER para voltar...")

def criptografar_chave_iv_rsa():
    limpar_tela()
    cabeçalho()
    diretorio_programa = Path(__file__).resolve().parent
    print("\nDigite o nome do arquivo contendo a chave e IV (lembre do sufixo '.txt' e que o arquivo deve estar no diretório do programa). ")

    arquivos_txt = [f.name for f in diretorio_programa.glob("*.txt")] # coloca todos os arquivos .txt do diretório do programa em uma lista
    print("\nArquivos .txt disponíveis:")
    for i, arquivo in enumerate(arquivos_txt, start=1):
        print(f"-> {arquivo}")
    print()

    nome_arquivo = input("----->").strip()
    caminho_arquivo = diretorio_programa / nome_arquivo

    if (
        not nome_arquivo
        or Path(nome_arquivo).name != nome_arquivo
        or Path(nome_arquivo).suffix.lower() != ".txt"
    ):
        print("Arquivo inexistente ou nome informado icorretamente. Certifique-se de que o arquivo está no diretório do programa e que o nome está correto.")
        input("Pressione ENTER para voltar...")
        return

    try:
        with open(caminho_arquivo, "r") as f:
            iv_hex, chave_hex = f.read().splitlines()
            iv = bytes.fromhex(iv_hex)
            chave = bytes.fromhex(chave_hex)
    except FileNotFoundError:
        print(f"Erro: o arquivo '{nome_arquivo}' não foi encontrado.")
        input("Pressione ENTER para voltar...")
        return
    except ValueError:
        print(f"Erro: o arquivo '{nome_arquivo}' não contém IV e chave válidos.")
        input("Pressione ENTER para voltar...")
        return

    limpar_tela()
    cabeçalho()
    print(f"\nArquivo: {nome_arquivo} de ({len(iv) + len(chave)} bytes) selecionado.")
    print("\nDigite o nome do arquivo da chave pública RSA (lembre do sufixo '.pu' e que o arquivo deve estar no diretório do programa). ")
    print("\nArquivos .pu disponíveis:")
    arquivos_pu = [f.name for f in diretorio_programa.glob("*.pu")]
    for i, arquivo in enumerate(arquivos_pu, start=1):
        print(f"-> {arquivo}")
    caminho_chave_publica = diretorio_programa / input("\n----->").strip()

    if not caminho_chave_publica.exists():
        print(f"Erro: a chave pública '{caminho_chave_publica.name}' não foi encontrada. Certifique-se de que o arquivo está no diretório do programa e foi digitado corretamente.")
        input("Pressione ENTER para voltar...")
        return

    with open(caminho_chave_publica, "rb") as f:
        chave_publica = serialization.load_pem_public_key(f.read())

    iv_chave_concatenados = iv + chave
    iv_chave_cifrado = chave_publica.encrypt(
        iv_chave_concatenados,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(diretorio_programa / "k_y.txt", "wb") as f:
        f.write(iv_chave_cifrado)

    limpar_tela()
    cabeçalho()
    print("\nIV e chave criptografados com sucesso!")
    print("Foram salvos em 'k_y.txt'.")
    input("Pressione ENTER para voltar...")

def descriptografar_chave_iv_rsa():
    limpar_tela()
    cabeçalho()
    diretorio_programa = Path(__file__).resolve().parent
    print("\nDigite o nome do arquivo contendo a chave e IV criptografados (lembre do sufixo '.txt' e que o arquivo deve estar no diretório do programa). ")

    arquivos_txt = [f.name for f in diretorio_programa.glob("*.txt")]
    print("\nArquivos .txt disponíveis:")
    for i, arquivo in enumerate(arquivos_txt, start=1):
        print(f"-> {arquivo}")
    print()

    nome_arquivo = input("----->").strip()
    caminho_arquivo = diretorio_programa / nome_arquivo

    if (
        not nome_arquivo
        or Path(nome_arquivo).name != nome_arquivo
        or Path(nome_arquivo).suffix.lower() != ".txt"
    ):
        print("Arquivo inexistente ou nome informado icorretamente. Certifique-se de que o arquivo está no diretório do programa e que o nome está correto.")
        input("Pressione ENTER para voltar...")
        return

    try:
        with open(caminho_arquivo, "rb") as f:
            iv_chave_cifrado = f.read()
    except FileNotFoundError:
        print(f"Erro: o arquivo '{nome_arquivo}' não foi encontrado.")
        input("Pressione ENTER para voltar...")
        return

    limpar_tela()
    cabeçalho()
    print(f"\nArquivo: {nome_arquivo} de ({len(iv_chave_cifrado)} bytes) selecionado.")
    print("\nDigite o nome do arquivo da chave privada RSA (lembre do sufixo '.pr' e que o arquivo deve estar no diretório do programa). ")
    print("\nArquivos .pr disponíveis:")
    arquivos_pr = [f.name for f in diretorio_programa.glob("*.pr")]
    for i, arquivo in enumerate(arquivos_pr, start=1):
        print(f"-> {arquivo}")
    caminho_chave_privada = diretorio_programa / input("\n----->").strip()

    if not caminho_chave_privada.exists():
        print(f"Erro: a chave privada '{caminho_chave_privada.name}' não foi encontrada. Certifique-se de que o arquivo está no diretório do programa e foi digitado corretamente.")
        input("Pressione ENTER para voltar...")
        return

    with open(caminho_chave_privada, "rb") as f:
        chave_privada = serialization.load_pem_private_key(f.read(), password=None)

    iv_chave_descriptografado = chave_privada.decrypt(
        iv_chave_cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #checa se um arquivo k.txt já existe, se existir, cria k2.txt, k3.txt, etc.
    contador = 1
    modificador = ""
    while (diretorio_programa / f"k{modificador}.txt").exists():
        contador += 1
        modificador = f"{contador}" if contador > 1 else ""

    with open(diretorio_programa / f"k{modificador}.txt", "w") as f:
        f.write(f"{iv_chave_descriptografado[:16].hex()}\n{iv_chave_descriptografado[16:].hex()}\n")

    limpar_tela()
    cabeçalho()
    print("\nIV e chave descriptografados com sucesso!")
    print(f"Foram salvos em 'k{modificador}.txt'.")
    input("Pressione ENTER para voltar...")

def descriptografar_arquivo():
    limpar_tela()
    cabeçalho()
    diretorio_programa = Path(__file__).resolve().parent
    print("\nDigite o nome do arquivo a ser descriptografado (lembre do sufixo '.txt' e que o arquivo deve estar no diretório do programa). ")
    print("\nArquivos .txt disponíveis:")
    arquivos_txt = [f.name for f in diretorio_programa.glob("*.txt")]
    for i, arquivo in enumerate(arquivos_txt, start=1):
        print(f"-> {arquivo}")
    nome_arquivo = input("\n-----> ").strip()

    caminho_arquivo = diretorio_programa / nome_arquivo

    if (
        not nome_arquivo
        or Path(nome_arquivo).name != nome_arquivo
        or Path(nome_arquivo).suffix.lower() != ".txt"
    ):
        print("Arquivo inexistente ou nome informado icorretamente. Certifique-se de que o arquivo está no diretório do programa e que o nome está correto.")
        input("Pressione ENTER para voltar...")
        return

    try:
        with open(caminho_arquivo, "r") as f:
            texto_cifrado_hex = f.read().strip()
            texto_cifrado = bytes.fromhex(texto_cifrado_hex)
    except FileNotFoundError:
        print(f"Erro: o arquivo '{nome_arquivo}' não foi encontrado.")
        input("Pressione ENTER para voltar...")
        return

    limpar_tela()
    cabeçalho()
    print(f"\nArquivo: {nome_arquivo} de ({len(texto_cifrado)} bytes) selecionado.")
    print("\nDigite o nome do arquivo contendo a chave e IV (lembre do sufixo '.txt' e que o arquivo deve estar no diretório do programa). ")
    print("\nArquivos .txt disponíveis:")    
    arquivos_txt = [f.name for f in diretorio_programa.glob("*.txt")]
    for i, arquivo in enumerate(arquivos_txt, start=1):
        print(f"-> {arquivo}")
    nome_arquivo_chave_iv = input("\n-----> ").strip()
    caminho_arquivo_chave_iv = diretorio_programa / nome_arquivo_chave_iv

    if not caminho_arquivo_chave_iv.exists():
        print(f"Erro: o arquivo '{nome_arquivo_chave_iv}' não foi encontrado. Certifique-se de que o arquivo está no diretório do programa e foi digitado corretamente.")
        input("Pressione ENTER para voltar...")
        return

    with open(caminho_arquivo_chave_iv, "r") as f:
        iv_hex, chave_hex = f.read().splitlines()
        iv = bytes.fromhex(iv_hex)
        chave = bytes.fromhex(chave_hex)

    decryptor = Cipher(algorithms.AES(chave), modes.CTR(iv)).decryptor()

    texto_descriptografado = decryptor.update(texto_cifrado) + decryptor.finalize()

    with open(diretorio_programa / "x.txt", "wb") as f:
        f.write(texto_descriptografado)

    limpar_tela()
    cabeçalho()
    print("\nArquivo descriptografado com sucesso!")
    print("Texto descriptografado salvo em 'x.txt'.")
    input("Pressione ENTER para voltar...")


def menu():
    cabeçalho()
    print("\nEscolha uma opção:")
    print("1. Gerar par de chaves RSA")
    print("2. Criptografar arquivo de texto (AES)")
    print("3. Criptografar chave e IV com uma chave pública RSA")
    print("4. Descriptografar chave e IV com uma chave privada RSA")
    print("5. Descriptografar arquivo de texto (AES)")
    print("6. Sair")


def main():
    cabeçalho()
    print("Bem-vindo ao Guisa Crypto! Para começar, informe seu nome.")
    global nome
    nome = input("Digite seu nome: ")

    while True:
        limpar_tela()
        menu()
        opcao = input("\nDigite o número da opção desejada: ")
        match opcao:
            case "1":
                gerar_chaves_rsa()
            case "2":
                criptografar_arquivo()
            case "3":
                criptografar_chave_iv_rsa()
            case "4":
                descriptografar_chave_iv_rsa()
            case "5":
                descriptografar_arquivo()
            case "6":
                limpar_tela()
                cabeçalho()
                print("\nSaindo do programa...")
                break


main()