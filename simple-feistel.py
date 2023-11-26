# -*- coding: utf-8 -*-

import hashlib  # Biblioteca utilizada na função generate_round_key https://docs.python.org/3/library/hashlib.html

key_block_size = 16

class Feistel(object):
    def __init__(self):
        pass

    def _xor(self, a, b):
        return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))

    def feistel_round(self, left, right, round_key):
        '''
        Camadas da Cifra
        '''

        new_right = self.funcao_sbox(left)
        #print('DEBUG: Valor da cadeia pós função:'+new_right)
        new_right = self._xor(new_right, round_key)
        #print('DEBUG: Valor da cadeia pós XOR:'+new_right)

        new_left = right
        return new_left, new_right

    def funcao_sbox(self, left):
        left_list = list(left)
        for contador in range(0, len(left_list), 2):
            c1, c2 = self.sbox_subs(left_list[contador], left_list[contador+1])
            left_list[contador] = c1
            left_list[contador + 1] = c2
        return ''.join(left_list)

    def sbox_subs(self, c1, c2):
        if(c1 == '1' and c2 == '1'):
            c1 = '0' ; c2 = '1'
        elif (c1 == '0' and c2 == '1'):
            c1 = '0' ; c2 = '0'
        elif (c1 == '1' and c2 == '0'):
            c1 = '1' ; c2 = '0'
        else:
            c1 = '1' ; c2 = '1'
        return c1, c2

    # 11 -> 01 #
    # 01 -> 00 #
    # 10 -> 10 #
    # 00 -> 11 #

    def sbox_subs_decipher(self, c1, c2):
        if(c1 == '1' and c2 == '1'):
            c1 = '0' ; c2 = '0'
        elif (c1 == '0' and c2 == '1'):
            c1 = '1' ; c2 = '1'
        elif (c1 == '1' and c2 == '0'):
            c1 = '1' ; c2 = '0'
        else:
            c1 = '0' ; c2 = '1'
        return c1, c2


    def feistel_cipher(self, plain_text, num_rounds, key):
        '''
        Encriptar
        '''

        left, right = plain_text[:len(plain_text) // 2], plain_text[len(plain_text) // 2:]
        
        round_keys = self.generate_round_key(key, num_rounds, key_block_size)  # Nova Chave da Rodada
        
        for round_num in range(num_rounds):
            print('Codigo na rodada ' + str(round_num+1) + ':  ' + left+right)
            print('Chave:               ' + str(key))

            round_key = round_keys[round_num]  # Ajuste para acessar a subchave correta
            left, right = self.feistel_round(left, right, round_key)  # Execução das camadas da Cifra

        cipher_text = left+right
        print('\nCodigo na rodada final:  ' + left+right)

        return cipher_text

    def generate_round_key(self, master_key, n_rounds, key_block_size):

        # O bloco é dividido em duas partes iguais e cada parte é processada separadamente em cada rodada.
        half_block_size = key_block_size // 2

        # A função é aplicada para derivar uma chave estendida (key_data) com base na chave mestra (master_key)
        key_data = hashlib.pbkdf2_hmac('sha256', master_key, b'Teste', 500, dklen=(4 + n_rounds) * half_block_size)

        #  Cria uma lista de subchaves para cada rodada
        roundkeys = [
            key_data[key_block_size + (half_block_size * a): key_block_size + half_block_size + (half_block_size * a)]
            for a in range(n_rounds)]
        
        return roundkeys

    def feistel_decipher(self, cipher_text, num_rounds, key):
        '''
        Decriptar
        '''

        left, right = cipher_text[:len(cipher_text) // 2], cipher_text[len(cipher_text) // 2:]
        
        round_keys = self.generate_round_key(key, num_rounds, key_block_size)
        for round_num in reversed(range(num_rounds)):  # A mesma coisa, só que na ordem reversa
            round_key = round_keys[round_num]
            left, right = self.feistel_round_decipher(left, right, round_key)

        text = left + right
        return text

    def feistel_round_decipher(self, left, right, round_key):
        '''
        Camadas da Cifra
        '''
        new_left = self._xor(right, round_key)
        new_left = self.funcao_sbox_decipher(new_left)

        new_right = left
        return new_left, new_right

    def funcao_sbox_decipher(self, left):
        left_list = list(left)
        for contador in range(0, len(left_list), 2):
            if contador + 1 < len(left_list):  # Verifica se há elementos suficientes para acessar
                c1, c2 = self.sbox_subs_decipher(left_list[contador], left_list[contador+1])
                left_list[contador] = c1
                left_list[contador + 1] = c2
        return ''.join(left_list)

feistel = Feistel()

# Exemplo de uso:
text       = "0010111101110101"  # Entrada
master_key = b'010101010101010'  # Chave
n_rounds = 3

cipher_text = feistel.feistel_cipher(text, n_rounds, master_key)
print("Texto cifrado:\t\t", cipher_text)

decrypted_text = feistel.feistel_decipher(cipher_text, n_rounds, master_key)
print("\nTexto descripto:\t", decrypted_text)
print("Texto original:\t\t", text)

