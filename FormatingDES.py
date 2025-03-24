from DES import DES

class Formatter:
    @staticmethod
    def format_binary(binary_str: str, segment_length: int) -> str:
        """
        Formats a binary string into 4-bit segments separated by '-'.
        :param segment_length: the chunk's length
        :param binary_str: A string of binary digits.
        :return: A formatted string with '-' separating every 4 bits.
        """
        return "-".join(
            [binary_str[i:i + segment_length] for i in range(0, len(binary_str), segment_length)])

    @classmethod
    def format_full_round(cls, des_round: DES) -> None:
        print("After Expansion")
        print(cls.format_binary(des_round.expansion_output[1], 6))
        print("After XOR")
        print(cls.format_binary(des_round.xor_output[1], 6))
        print("After S-Box")
        print(cls.format_binary(des_round.sbox_output[1], 4))
        print("After P-Box")
        print(cls.format_binary(des_round.pbox_output[1], 4))