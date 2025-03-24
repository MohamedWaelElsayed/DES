from DES import DES
from FormatingDES import Formatter

r1 = 0b_00011111_10011001_11100111_10000011
# r1 = 0b11100000_01000000_00110000_11010000

k2 = 0b011110001100101001001011101111110001100000010011


des_round_two = DES(r1, k2)
des_round_two.perform_all_steps()
Formatter.format_full_round(des_round_two)
# print("PlainText")
# print(DES.format_binary(f"{r1:032b}", 6))
# print("Output")
# print(cipherText)
# s_box = DES.des_s_box(0b01001100101000001101010001001000)
# print(DES.format_binary(s_box[1], 4))
# xor = des_round_two.des_xor(0b000011_111010_011001_111001_001110_000111, k2)
# print(DES.format_binary(xor[1], 6))
# s_box = DES.des_s_box(0b000000_001100_100001_001011_101001_010000_111010_110010)
# print(DES.format_binary(s_box[1], 4))
# p_box = DES.des_p_box(0b1110_0110_0001_1111_0001_0000_0101_0110)
# print(DES.format_binary(p_box[1], 4))
