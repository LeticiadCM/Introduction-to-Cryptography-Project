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

        new_right = self._xor(left, round_key)
        new_left = right
        return new_left, new_right

    def feistel_cipher(self, plain_text, num_rounds, key):
        '''
        [b'1010101010101010', 0, 128]
        Encriptar
        '''

        left, right = plain_text[:len(plain_text) // 2], plain_text[len(plain_text) // 2:]

        round_keys = self.generate_round_key(key, num_rounds, key_block_size)  # Nova Chave da Rodada
        for round_num in range(num_rounds):
            round_key = round_keys[round_num]  # Ajuste para acessar a subchave correta
            left, right = self.feistel_round(left, right, round_key)  # Execução das camadas da Cifra

        cipher_text = right + left
        return cipher_text

    def generate_round_key(self, master_key, n_rounds, key_block_size):

        half_block_size = key_block_size // 2

        # Gera um sub_chave com metade do tamanho do bloco para cada rodada
        # + 2 blocos para comparação

        key_data = hashlib.pbkdf2_hmac('sha256', master_key, b'Teste', 500, dklen=(4 + n_rounds) * half_block_size)

        # Creio que não seja necessário retornar a prekey e postkey, apenas para debugar

        # [Original: 64] [R x Sub-chaves: 32] [Nova chave: 64]
        # keys = {
        #     "prekey" : key_data[0:key_block_size],
        #     "roundkeys" : [key_data[key_block_size + (half_block_size * a): key_block_size + half_block_size + (half_block_size * a)] for a in range(n_rounds)],
        #     "postkey" : key_data[-key_block_size:],
        # }

        # Pelo que entendi, basta rodar a função apenas uma vez,
        # no final da linha há um for para gerar todas as rodadas
        roundkeys = [
            key_data[key_block_size + (half_block_size * a): key_block_size + half_block_size + (half_block_size * a)]
            for a in range(n_rounds)]
        return roundkeys

        '''
        Geração da Chave
        '''

    def feistel_decipher(self, cipher_text, num_rounds, key):
        '''
        Decriptar
        '''

        left, right = cipher_text[:len(cipher_text) // 2], cipher_text[len(cipher_text) // 2:]

        round_keys = self.generate_round_key(key, num_rounds, key_block_size)
        for round_num in reversed(range(num_rounds)):  # A mesma coisa, só que na ordem reversa
            round_key = round_keys[round_num]  # Ajuste para acessar a subchave correta
            left, right = self.feistel_round(left, right, round_key)

        text = right + left
        return text


feistel = Feistel()

# Exemplo de uso:
text = "0010111101110100"  # Entrada
master_key = b"1010101010101010"  # Chave
n_rounds = 9

cipher_text = feistel.feistel_cipher(text, n_rounds, master_key)
print("Texto cifrado:\t\t", cipher_text)

decrypted_text = feistel.feistel_decipher(cipher_text, n_rounds, master_key)
print("Texto descripto:\t", decrypted_text)
print("Texto original:\t\t", text)
