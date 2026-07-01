import os
import time
import math
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes

# =====================================================================
# 1. MÓDULO GERADOR DE ARQUIVOS DE TESTE (Item 3.1)
# =====================================================================
class FileGenerator:
    @staticmethod
    def generate_repetitive_csv(filepath, size_bytes):
        """Gera um arquivo CSV altamente repetitivo (baixa entropia)."""
        row = b"1,John Doe,Director,Marketing,Active,2026-01-01\n"
        with open(filepath, 'wb') as f:
            written = 0
            while written < size_bytes:
                f.write(row)
                written += len(row)

    @staticmethod
    def generate_bmp_image(filepath, width=512, height=512):
        """Gera uma imagem BMP não comprimida com padrões geométricos claros."""
        image = Image.new("RGB", (width, height), "white")
        # Desenha um quadrado azul no centro para criar padrão visual evidente
        for x in range(width // 4, 3 * width // 4):
            for y in range(height // 4, 3 * height // 4):
                image.putpixel((x, y), (0, 0, 255))
        image.save(filepath, "BMP")

# =====================================================================
# 2. MÓDULO DE CIFRAGEM (Item 3.2)
# =====================================================================
class CustomSymmetricModes:
    """Implementação manual dos modos em cima das primitivas de bloco."""
    
    @staticmethod
    def _xor_bytes(b1, b2):
        return bytes(a ^ b for a, b in zip(b1, b2))

    @classmethod
    def encrypt_cbc(cls, cipher_algo, key, iv, plaintext):
        # Garante padding PKCS7 manual simples para fins de blocos fixos
        block_size = cipher_algo.block_size // 8
        padding_len = block_size - (len(plaintext) % block_size)
        plaintext += bytes([padding_len] * padding_len)
        
        backend_cipher = Cipher(cipher_algo(key), modes.ECB())
        encryptor = backend_cipher.encryptor()
        
        ciphertext = b""
        prev_block = iv
        
        for i in range(0, len(plaintext), block_size):
            block = plaintext[i:i+block_size]
            xored = cls._xor_bytes(block, prev_block)
            ct_block = encryptor.update(xored)
            ciphertext += ct_block
            prev_block = ct_block
            
        return ciphertext

    @classmethod
    def encrypt_ctr(cls, cipher_algo, key, nonce, plaintext):
        block_size = cipher_algo.block_size // 8
        backend_cipher = Cipher(cipher_algo(key), modes.ECB())
        encryptor = backend_cipher.encryptor()
        
        ciphertext = b""
        counter = int.from_bytes(nonce, byteorder='big')
        
        for i in range(0, len(plaintext), block_size):
            block = plaintext[i:i+block_size]
            keystream_block = encryptor.update(counter.to_bytes(block_size, byteorder='big'))
            ciphertext += cls._xor_bytes(block, keystream_block[:len(block)])
            counter += 1
            
        return ciphertext

class CustomRSAModes:
    """Adaptação do RSA para modos de bloco e fluxo (Evitando overflow)."""
    
    @staticmethod
    def encrypt_ecb_rsa(private_key, plaintext):
        # Blocos menores que o módulo para evitar overflow (ex: 245 bytes para 2048)
        max_block_size = 200 
        public_key = private_key.public_key()
        ciphertext = b""
        
        for i in range(0, len(plaintext), max_block_size):
            block = plaintext[i:i+max_block_size]
            ct_block = public_key.encrypt(
                block,
                asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            ciphertext += ct_block
        return ciphertext

    @staticmethod
    def encrypt_ctr_rsa(private_key, nonce, plaintext):
        """Transforma o RSA em cifrador de fluxo cifrando o contador."""
        max_block_size = 200
        public_key = private_key.public_key()
        ciphertext = b""
        counter = int.from_bytes(nonce, byteorder='big')
        
        for i in range(0, len(plaintext), max_block_size):
            block = plaintext[i:i+max_block_size]
            keystream_input = counter.to_bytes(32, byteorder='big') # Bloco controlado fixo
            
            keystream_block = public_key.encrypt(
                keystream_input,
                asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            # XOR do fluxo gerado pelo RSA com o texto claro
            xored = bytes(a ^ b for a, b in zip(block, keystream_block[:len(block)]))
            ciphertext += xored
            counter += 1
            
        return ciphertext

# =====================================================================
# 3. MÓDULO DE MÉTRICAS (Item 3.3)
# =====================================================================
class MetricsCalculator:
    @staticmethod
    def calculate_shannon_entropy(data):
        """Calcula a Entropia de Shannon dos bytes (0 a 8)."""
        if not data:
            return 0
        entropy = 0
        total_len = len(data)
        counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        for count in counts:
            if count > 0:
                p = count / total_len
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def detect_residual_patterns(data, block_size=16):
        """Retorna True se detectar blocos idênticos repetidos (Vulnerabilidade ECB)."""
        chunks = [data[i:i+block_size] for i in range(0, len(data), block_size) if i+block_size <= len(data)]
        if len(chunks) == 0:
            return False
        return len(chunks) != len(set(chunks))

# =====================================================================
# 4. EXECUÇÃO DO FLUXO PRINCIPAL / MATRIZ DE TESTES (Item 4)
# =====================================================================
def run_experiments():
    print("=== INICIANDO EXPERIMENTOS CRIPTOGRÁFICOS ===")
    
    # Criando diretório temporário para testes
    os.makedirs("test_files", exist_ok=True)
    
    # Gerando as chaves de teste
    aes_key = os.urandom(32)   # Para AES-256
    des_key = os.urandom(8)    # Para DES (64 bits)
    iv_16 = os.urandom(16)
    iv_8 = os.urandom(8)
    
    print("Gerando chaves RSA (isso pode demorar alguns segundos)...")
    rsa_2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    
    # Matriz de Testes Simulando o Escopo do Relatório
    # Formato: (Algoritmo, Modo, Tamanho do Arquivo de Teste)
    test_matrix = [
        ("AES-256", "CBC", 1024 * 1024),       # 1 MB
        ("AES-256", "CTR", 1024 * 1024),       # 1 MB
        ("DES", "CBC", 1024 * 500),            # 500 KB (Reduzido para agilidade)
        ("RSA-2048", "ECB", 1024 * 2),         # 2 KB (Demonstrativo Acadêmico)
        ("RSA-2048", "CTR", 1024 * 10)         # 10 KB
    ]
    
    print("\n" + "="*80)
    print(f"{'Algoritmo':<12} | {'Modo':<6} | {'Tamanho':<10} | {'Tempo (s)':<10} | {'Throughput':<14} | {'Entropia':<8} | {'Padrões?'}")
    print("="*80)

    for algo, modo, size in test_matrix:
        # 1. Gerar arquivo temporário para o teste
        filepath = f"test_files/temp_{algo}_{modo}.csv"
        FileGenerator.generate_repetitive_csv(filepath, size)
        
        with open(filepath, 'rb') as f:
            data = f.read()
            
        # 2. Executar a Cifragem medindo o desempenho (Média de 3 repetições para agilizar)
        start_time = time.time()
        
        for _ in range(3):
            if algo == "AES-256":
                if modo == "CBC":
                    ct = CustomSymmetricModes.encrypt_cbc(algorithms.AES, aes_key, iv_16, data)
                elif modo == "CTR":
                    ct = CustomSymmetricModes.encrypt_ctr(algorithms.AES, aes_key, iv_16, data)
            elif algo == "DES":
                if modo == "CBC":
                    ct = CustomSymmetricModes.encrypt_cbc(algorithms.DES, des_key, iv_8, data)
            elif algo == "RSA-2048":
                if modo == "ECB":
                    ct = CustomRSAModes.encrypt_ecb_rsa(rsa_2048, data)
                elif modo == "CTR":
                    ct = CustomRSAModes.encrypt_ctr_rsa(rsa_2048, iv_16, data)
                    
        end_time = time.time()
        mean_time = (end_time - start_time) / 3
        
        # 3. Calcular Métricas
        throughput = (size / (1024 * 1024)) / mean_time if mean_time > 0 else 0
        entropy = MetricsCalculator.calculate_shannon_entropy(ct)
        patterns = "Sim" if MetricsCalculator.detect_residual_patterns(ct) else "Não"
        
        print(f"{algo:<12} | {modo:<6} | {size/(1024):>6.0f} KB | {mean_time:<10.5f} | {throughput:>8.2f} MB/s | {entropy:<8.4f} | {patterns}")
        
        # Limpeza
        if os.path.exists(filepath):
            os.remove(filepath)

    # 5. TESTE ESPECIAL VISUAL (Item 3.4 - Imagem BMP)
    print("\nExecutando teste visual com arquivo BMP (Análise de vazamento de padrões)...")
    bmp_path = "test_files/input_padrao.bmp"
    FileGenerator.generate_bmp_image(bmp_path)
    
    with open(bmp_path, 'rb') as f:
        header = f.read(54) # Preserva o cabeçalho BMP para a imagem continuar abrindo
        pixel_data = f.read()
        
    # Cifragem Simétrica Pura em ECB para fins de teste visual comparativo
    cipher_ecb = Cipher(algorithms.AES(aes_key), modes.ECB())
    encryptor = cipher_ecb.encryptor()
    # Padding manual para alinhar ao bloco do AES
    padded_pixels = pixel_data + b"\x00" * (16 - len(pixel_data) % 16)
    ct_pixels_ecb = encryptor.update(padded_pixels)
    
    # Salva imagem resultante do modo ECB
    with open("test_files/resultado_ECB_vazado.bmp", "wb") as f:
        f.write(header + ct_pixels_ecb[:len(pixel_data)])
        
    print("-> Imagem original criada em: test_files/input_padrao.bmp")
    print("-> Imagem cifrada em ECB (com vazamento estrutural) criada em: test_files/resultado_ECB_vazado.bmp")
    print("\n=== EXPERIMENTOS CONCLUÍDOS COM SUCESSO ===")

if __name__ == "__main__":
    run_experiments()