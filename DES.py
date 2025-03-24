class DES:

  def __init__(self, input_value, round_key) -> None:
    """
    Initialize a new instance of DES one round
    inputs: plain_text, round_key, cipher_text, expansion_output, xor_output, s-box_output, p-box_output
    """
    self.plain_text = input_value
    self.expansion_output = 0
    self.xor_output = 0
    self.sbox_output = 0
    self.pbox_output = 0
    self.cipherText = 0
    self.round_key = round_key

  @staticmethod
  def des_s_box(input_48_bits: int)-> tuple[int, str]:
    """
    Applies the S-Box substitution in the DES algorithm.

    :param input_48_bits: A 48-bit integer (after Expansion Permutation and XOR with the subkey).
    :return: A tuple containing a 32-bit integer and its binary string after applying all 8 S-Boxes.
    """
    # Define all 8 S-Boxes (Each is a 4-row × 16-column table)
    s_boxes = [
        # S1
        [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
        # S2
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 10, 7, 2, 8, 14, 12, 0, 11, 5, 6, 15, 1, 9],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 5, 4, 3],
         [0, 6, 10, 1, 13, 8, 9, 4, 2, 12, 5, 11, 15, 3, 7, 14]],
        # S3
        [[10, 0, 9, 14, 15, 6, 3, 13, 1, 7, 12, 11, 4, 2, 8, 5],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 9, 0, 1, 11, 10, 4, 3, 14, 15, 8, 5, 2, 12, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
        # S4
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
        # S5
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 5, 4, 3]],
        # S6
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
        # S7
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
        # S8
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
    ]

    # Convert input to binary string (48-bits)
    input_bin = f"{input_48_bits:048b}"
    output_bits = ""

    # Process each 6-bit chunk through the corresponding S-Box
    for i in range(8):  # 8 S-Boxes
      chunk = input_bin[i * 6:(i + 1) * 6]  # Get 6-bit chunk
      row = int(chunk[0] + chunk[5],
                2)  # First and last bit form the row index
      col = int(chunk[1:5], 2)  # Middle four bits form the column index
      s_box_value = s_boxes[i][row][col]  # Get the substituted value
      output_bits += f"{s_box_value:04b}"  # Convert to 4-bit binary and append

    # Convert output binary string to integer
    return int(output_bits, 2), output_bits

  @staticmethod
  def des_p_box(input_bits: int)-> tuple[int, str]:
    """
    Performs the P-box permutation in the DES algorithm.

    :param input_bits: A 32-bit integer representing the output from the S-boxes.
    :return: A 32-bit integer after applying the P-box permutation.
    """
    # P-box permutation table
    p_box = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24,
        14, 11, 13, 6, 4, 19, 30, 27, 3, 9, 22, 25, 32
    ]
    # Convert input_bits to a 32-bit binary string
    input_bin = f"{input_bits:032b}"

    # Apply the P-box permutation
    output_bin = "".join(input_bin[i - 1] for i in p_box)

    # Convert the permuted binary string back to an integer
    output_bits = int(output_bin, 2)

    return output_bits, output_bin

  @staticmethod
  def des_expansion_permutation(input_32_bits: int)-> tuple[int, str]:
    """
    Applies the Expansion Permutation in the DES algorithm.

    :param input_32_bits: A 32-bit integer (right half of the block).
    :return: A 48-bit integer after expansion.
    """
    # Expansion Permutation Table (from image)
    e_bit = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14,
        15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26,
        27, 28, 29, 28, 29, 30, 31, 32, 1
    ]

    # Convert input to binary string (32-bit)
    input_bin = f"{input_32_bits:032b}"

    # Apply expansion using E-Box table
    output_bin = "".join(input_bin[i - 1]
                         for i in e_bit)  # -1 to adjust for 0-based indexing

    # Convert output binary string to integer
    return int(output_bin, 2), output_bin

  @staticmethod
  def des_xor(input_48_bits, key:int) -> tuple[int, str]:
    """
    Perform XOR operation on two integers, representing binary values.

    Returns:
        int: The result of XOR operation as an integer.
    """
    # Perform the XOR operation using the bitwise XOR operator
    input_48_bits = f"{input_48_bits:048b}"
    # print(input_48_bits)
    round_key = f"{key:048b}"
    # print(round_key)
    output_bin = "".join('1' if i != j else '0'
                         for i, j in zip(input_48_bits, round_key))
    return int(output_bin, 2), output_bin



  def perform_all_steps(self)-> None:
    """
    A simple method performs all the 4 steps of a single round
    :return: two strings: plainText, cipherText
    """
    self.expansion_output =  self.des_expansion_permutation(self.plain_text)
    # print("After Expansion")
    # print(self.format_binary(self.expansion_output[1], 6))
    # assert expanded_output[
    #     1] == "011110100001010101010101011110100001010101010101"
    self.xor_output = self.des_xor(self.expansion_output[0], self.round_key)
    # print("After Xor")
    # print(self.format_binary(self.xor_output[1], 6))
    # assert xored_with_key[
    #     1] == "011000010001011110111010100001100110010100100111"
    self.sbox_output = self.des_s_box(
        self.xor_output[0])
    # print('After S-Boxes')
    # print(self.format_binary(self.sbox_output[1], 4))
    # assert s_boxes[1] == "01101111001110110100011100110110"
    self.pbox_output = self.des_p_box(self.sbox_output[0])
    # print("After P-Boxes")
    # print(self.format_binary(self.pbox_output[1], 4))
    # assert p_box[1] == "00100011010010101010100110111011"
    self.cipherText = self.pbox_output[1]
    # return self.format_binary(f"{self.plain_text:064b}", 4), self.format_binary(
    #     self.pbox_output[1], 4)
