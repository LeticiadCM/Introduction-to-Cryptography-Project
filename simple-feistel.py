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

        new_right = self.funcao_feister(left)
        #print('DEBUG: Valor da cadeia pós função:'+new_right)
        new_right = self._xor(new_right, round_key)
        #print('DEBUG: Valor da cadeia pós XOR:'+new_right)

        new_left = right
        return new_left, new_right

    def funcao_feister(self, left):
        left_list = list(left)
        for contador in range(len(left_list)):
            if self.is_primo(contador+1):
                if left_list[contador] == '0':
                    left_list[contador] = '1'
                else:
                    left_list[contador] = '0'
        return ''.join(left_list)

    def is_primo(self, n):
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    def feistel_cipher(self, plain_text, num_rounds, key):
        '''
        Encriptar
        '''

        left, right = plain_text[:len(plain_text) // 2], plain_text[len(plain_text) // 2:]

        for round_num in range(num_rounds):
            print('Codigo na rodada ' + str(round_num+1) + ':  ' + left+right)
            print('Chave:               ' + str(key))

            round_key = self.generate_round_key(key, round_num)  # Nova Chave da Rodada
            left, right = self.feistel_round(left, right, round_key)  # Execução das camadas da Cifra

        cipher_text = left+right
        print('\nCodigo na rodada final:  ' + left+right)

        return cipher_text

    def generate_round_key(self, master_key, round_num):
        '''
        Geração da Chave
        '''
        round_key = master_key  # TODO: Criar Tratamento pra Chave

        return round_key

    def feistel_decipher(self, cipher_text, num_rounds, key):
        '''
        Decriptar
        '''

        left, right = cipher_text[:len(cipher_text) // 2], cipher_text[len(cipher_text) // 2:]

        for round_num in reversed(range(num_rounds)):  # A mesma coisa, só que na ordem reversa
            round_key = self.generate_round_key(key, round_num)
            right, left = self.feistel_round(left, right, round_key)

        text = right + left
        return text


feistel = Feistel()

# Exemplo de uso:
text       = "0010111101110101"  # Entrada
master_key = "1010101010101010"  # Chave
n_rounds = 3

cipher_text = feistel.feistel_cipher(text, n_rounds, master_key)
print("Texto cifrado:\t\t\t", cipher_text)

decrypted_text = feistel.feistel_decipher(cipher_text, n_rounds, master_key)
print("\nTexto descripto:\t", decrypted_text)
print("Texto original:\t\t", text)