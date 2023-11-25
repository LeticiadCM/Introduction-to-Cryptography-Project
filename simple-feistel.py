# -*- coding: utf-8 -*-
"""
Created on Fri Nov 24 21:04:52 2023

@author: erick
"""
import os
import base64
import hashlib

class Feistel(object):
    def __init__(self):
        pass

    def _xor(self, a, b):
        return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))
    
    def feistel_round(self, left, right, round_key):
        '''
        Camadas da Cifra
        '''
        
        new_right = self._xor(left, round_key) 
        new_left = right
        return new_left, new_right
    
    
    def feistel_cipher(self, plain_text, num_rounds, key):
        '''
        Encriptar
        '''
        
        left, right = plain_text[:len(plain_text)//2], plain_text[len(plain_text)//2:]
    
        for round_num in range(num_rounds):
            round_key = self.generate_round_key(key, round_num) #Nova Chave da Rodada
            left, right = self.feistel_round(left, right, round_key) #Execução das camadas da Cifra 
    
        cipher_text = right + left
        return cipher_text
    
    def generate_round_key(self, master_key, round_num):
        '''
        Geração da Chave
        '''
        round_key = master_key #TODO: Criar Tratamento pra Chave
        
        return round_key
    
    def generate_key_opt1(self,key,key_size):
        '''
        Escalona a chave para um tamanho especifico
        Parâmetros ->
            key: Chave a ser dimensionada
            key_size: Tamanho da chave desejado
        Retorno -> 
            new_key: Chave de tamanho = key_size
        '''

        # Verifico se a chave tem o tamanho correto
        if len(key) < key_size:
            raise ValueError("A chave deve ser de tamanho maior ou igual a %d." % key_size)
        elif len(key) > key_size:
            #Se a Chave original for maior do que a nova, preencho os bits com 0
            new_key = bytes([0] * (len(key) - key_size))
            
        # Concatena os bytes da chave original.
        new_key += bytes(key.encode())[:key_size]
        return new_key.decode('utf-8')
    
    def generate_key_opt2(self,key_size) -> bytes:
        '''
        Cria aleatóriamente uma chave de tamano N = key_size
        Parâmetros ->
            key_size: Tamanho da chave desejado
        Retorno -> 
            new_key: Chave de tamanho = key_size
        '''
        new_key = base64.urlsafe_b64encode(os.urandom(key_size))
        return new_key.decode('utf-8')
    
    def generate_key_opt3(self, key, n_rounds, key_block_size) -> bytes:
        '''
        Cria aleatóriamente uma chave de tamano N = key_size
        Parâmetros ->
            key: Chave original
            n_rounds: Numero da rodada
            key_block_size: Tamanho do bloco de chaves
        Retorno -> 
            xx: Chave de tamanho = key_size
        '''
        half_block_size = key_block_size // 2

        # Gera um sub_chave com metade do tamanho do bloco para cada rodada
        # e mais dois blocos para 
        # + 2 blocos para comparação
        key_data = hashlib.pbkdf2_hmac('sha256', key, b'Teste', 500, dklen = (4 + n_rounds) * half_block_size)

        # [Original: 64] [R x Sub-chaves: 32] [Nova chave: 64]
        keys = {
            "prekey" : key_data[0:key_block_size],
            "roundkeys" : [key_data[key_block_size + (half_block_size * a): key_block_size + half_block_size + (half_block_size * a)] for a in range(n_rounds)],
            "postkey" : key_data[-key_block_size:],
        }
      
        return keys

    def feistel_decipher(self, cipher_text, num_rounds, key):
        '''
        Decriptar
        '''
        
        left, right = cipher_text[:len(cipher_text)//2], cipher_text[len(cipher_text)//2:]
    
        for round_num in reversed(range(num_rounds)): #A mesma coisa, só que na ordem reversa
            round_key = self.generate_round_key(key, round_num)
            left, right = self.feistel_round(left, right, round_key)
    
        text = right + left
        return text

feistel = Feistel()
    
# Exemplo de uso:
text = "0010111101110100" #Entrada
master_key = "1010101010101010" #Chave
n_rounds = 9
teste_key_1 = feistel.generate_key_opt1(master_key,15)
teste_key_2 = feistel.generate_key_opt2(64)
teste_key_3 = feistel.generate_key_opt3(bytes(master_key, 'utf-8'),n_rounds,64)


cipher_text = feistel.feistel_cipher(text, n_rounds, master_key)
print("Texto cifrado:\t\t", cipher_text)

print("-----------Chaves-----------")
print("Chave Original:\t\t", master_key)
print("Opção de esc 1:\t\t", teste_key_1)
print("Opção de esc 2:\t\t", teste_key_2)
print("Opção de esc 3:\t\t", teste_key_3)
print("----------------------------")


decrypted_text = feistel.feistel_decipher(cipher_text, n_rounds, master_key)
print("Texto descripto:\t", decrypted_text)
print("Texto original:\t\t", text)
