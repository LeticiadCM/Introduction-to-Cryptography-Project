# -*- coding: utf-8 -*-
"""
Created on Fri Nov 24 21:04:52 2023

@author: erick
"""

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

cipher_text = feistel.feistel_cipher(text, n_rounds, master_key)
print("Texto cifrado:\t\t", cipher_text)

decrypted_text = feistel.feistel_decipher(cipher_text, n_rounds, master_key)
print("Texto descripto:\t", decrypted_text)
print("Texto original:\t\t", text)
