#  Universidad Cenfotec
#  MSEG01 - Principios de Criptografia
#  Author: Ing. Jose Andres Artavia
#  Python version: 2.7


from collections import deque
from itertools import repeat
from sys import version_info
import unicodedata
import commands
import codecs
import subprocess


all_bytes = dict([("%02X" % i, i) for i in range(256)])


def _hex_to_bytes(s):
    return [all_bytes[s[i:i+2].upper()] for i in range(0, len(s), 2)]


def hex_to_bits(s):
    return [(b >> i) & 1 for b in _hex_to_bytes(s)
            for i in range(8)]


def bits_to_hex(b):
    return "".join(["%02X" % sum([b[i + j] << j for j in range(8)])
                    for i in range(0, len(b), 8)])


class color:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    OKYELLOW = '\033[33m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Trivium:
    def __init__(self, key, iv):
        """in the beginning we need to transform the key as well as the IV.
        Afterwards we initialize the state."""
        self.state = None
        self.counter = 0
        self.key = key  # self._setLength(key)
        self.iv = iv  # self._setLength(iv)

        # Initialize state
        # len 100
        init_list = list(map(int, list(self.key)))
        init_list += list(repeat(0, 20))
        # len 84
        init_list += list(map(int, list(self.iv)))
        init_list += list(repeat(0, 4))
        # len 111
        init_list += list(repeat(0, 108))
        init_list += list([1, 1, 1])
        self.state = deque(init_list)

		# Se realizan 4 corridas y se descarta su salida
        for i in range(4*288):
            self._gen_keystream()

    def encrypt(self, message, output):
		plaintext = remove_accents(message).upper()
		plaintext_hex = plaintext.encode('hex').upper()
		plaintext_bin = hex_to_bits(plaintext_hex)
		ciphertext = []
		for i in range(len(plaintext_bin)):
			ciphertext.append(self._gen_keystream() ^ plaintext_bin[i])

		if output == 'b' or output == 'B':
			return ''.join(map(str,ciphertext))
		else:
			return bits_to_hex(ciphertext)


    def decrypt(self, cipher):
		ciphertext_bin = []
		plaintext_bin = []
		if (any(c.isalpha() for c in cipher)):
			ciphertext_bin = hex_to_bits(cipher)
			for i in range(len(ciphertext_bin)):
				plaintext_bin.append(self._gen_keystream() ^ ciphertext_bin[i])
		else:
			ciphertext_bin = list(str(cipher))
			for i in range(len(ciphertext_bin)):
				plaintext_bin.append(self._gen_keystream() ^ int(ciphertext_bin[i]))

		plaintext_hex = bits_to_hex(plaintext_bin)
		plaintext = plaintext_hex.decode('hex').upper()
		return plaintext

    def keystream(self):
        """output keystream
        only use this when you know what you are doing!!"""
        while self.counter < 2**64:
            self.counter += 1
            yield self._gen_keystream()

    def _setLength(self, input_data):
        """we cut off after 80 bits, alternatively we pad these with zeros."""
        input_data = "{0:080b}".format(input_data)
        if len(input_data) > 80:
            input_data = input_data[:(len(input_data)-81):-1]
        else:
            input_data = input_data[::-1]
        return input_data

	#====================================
	# Metodo para generar los keystreams
	#====================================
    def _gen_keystream(self):
        """this method generates triviums keystream"""

        a_1 = self.state[90] & self.state[91]
        a_2 = self.state[181] & self.state[182]
        a_3 = self.state[292] & self.state[293]

        t_1 = self.state[65] ^ self.state[92]
        t_2 = self.state[168] ^ self.state[183]
        t_3 = self.state[249] ^ self.state[294]

        out = t_1 ^ t_2 ^ t_3

        s_1 = a_1 ^ self.state[177] ^ t_1
        s_2 = a_2 ^ self.state[270] ^ t_2
        s_3 = a_3 ^ self.state[68] ^ t_3

        self.state.rotate(1)

        self.state[0] = s_3
        self.state[100] = s_1
        self.state[184] = s_2

        return out

def remove_accents(input_str):
	input_str = input_str.replace(u"\u2018", "\"").replace(u"\u2019", "\"").replace(u"\u201c","\"").replace(u"\u201d", "\"")
	nkfd_form = unicodedata.normalize('NFKD', unicode(input_str))
	return u"".join([c for c in nkfd_form if not unicodedata.combining(c)])

def main():
	print subprocess.call('cls', shell=True)
	print color.OKBLUE
	print ('+-----------------------------------------------+')
	print ('| MSEG02 - PRINCIPIOS DE CRIPTOGRAFIA          |')
	print ('| LABORATORIO DE TRIVIUM                        |')
	print ('| ING. JOSE ANDRES ARTAVIA                      |')
	print ('+-----------------------------------------------+')
	print color.ENDC


	print color.OKYELLOW + 'DIGITE EL MENSAJE (TEXTO PLANO O CIFRADO)' + color.ENDC
	mensaje = unicode(raw_input(), "utf-8")
	print
	print color.OKYELLOW + 'DIGITE LA LLAVE (KEY)' + color.ENDC
	llave = raw_input()
	print
	print color.OKYELLOW + 'DIGITE EL VECTOR DE INICIALIZACION (IV)' + color.ENDC
	vector_ini = raw_input()
	key_hex = llave.encode('hex').upper()
	iv_hex = vector_ini.encode('hex').upper()
	KEY = hex_to_bits(key_hex)[::-1]
	IV = hex_to_bits(iv_hex)[::-1]
	# Si es mayor de 80 bits se completa con ceros
	if len(KEY) < 80:
		for k in range(80-len(KEY)):
			KEY.append(0)
	if len(IV) < 80:
		for i in range(80-len(IV)):
			IV.append(0)

	# Se crea el objeto Trivium
	trivium = Trivium(KEY, IV)

	# Pregunta si se desea encriptar o desencriptar el mensaje
	print color.OKYELLOW
	opcion = raw_input('SELECCIONE [E] ENCRIPTAR | [D] DESENCRIPTAR: ')
	print color.ENDC
	if opcion == 'e' or opcion == 'E':
		print color.OKYELLOW
		salida = raw_input('FORMATO DE SALIDA DEL CIFRADO [B] BINARIO | [H] HEXADECIMAL: ')
		print color.ENDC
		if salida == 'b' or salida == 'B' or salida == 'h' or salida == 'H':
			print color.BOLD + 'MENSAJE ENCRIPTADO' + color.ENDC
			print color.OKGREEN
			print trivium.encrypt(mensaje,salida)
			print color.ENDC
		else:
			main()
	elif opcion == 'd' or opcion == 'D':
			print color.BOLD + 'MENSAJE DESENCRIPTADO' + color.ENDC
			print color.OKGREEN
			print trivium.decrypt(mensaje)
			print color.ENDC
	else:
		main()


if __name__ == "__main__":
	main()
