import string
import unittest
import cryptopals.set1

class TestSet1(unittest.TestCase):

    def test_hex_to_base64(self):
        s = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        expected_result = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
        result = cryptopals.set1.hex_to_base64(s)
        self.assertEqual(result, expected_result)

    def test_fixed_xor(self):
        left = '1c0111001f010100061a024b53535009181c'
        right = '686974207468652062756c6c277320657965'
        expected_result = '746865206b696420646f6e277420706c6179'
        result = cryptopals.set1.fixed_xor(left, right)
        self.assertEqual(result, expected_result)

    def test_single_byte_xor(self):
        message = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        k = 'X'
        expected_result = '436f6f6b696e67204d432773206c696b65206120706f756e64206f66206261636f6e'
        result = cryptopals.set1.single_byte_xor(message, k)
        self.assertEqual(result, expected_result)

    def test_probability_english(self):
        s = 'ETAOI'  # As in "ETAOIN SHRDLU"
        expected_result = 0.5
        result = cryptopals.set1.probability_english(s)
        self.assertGreaterEqual(result, expected_result)

    def test_letter_histogram(self):
        s = string.printable
        expected_result = { letter:1/len(s) for letter in s }
        result = cryptopals.set1.letter_histogram(s)
        self.assertEqual(result, expected_result)

    def test_repeating_key_xor(self):
        message = (
            'Burning \'em, if you ain\'t quick and nimble\n'
            'I go crazy when I hear a cymbal'
        )
        key = 'ICE'
        expected_result = (
            '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'
            'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
        )
        result = cryptopals.set1.repeating_key_xor(message, key)
        self.assertEqual(result, expected_result)

    def test_hamming_distance(self):
        left = b'this is a test'
        right = b'wokka wokka!!!'
        expected_result = 37
        result = cryptopals.set1.hamming_distance(left, right)
        self.assertEqual(result, expected_result)

    @unittest.expectedFailure
    def test_avg_hamming_distance(self):
        # As seen in https://docs.python.org/3/library/unittest.html
        self.fail('TODO...')

    def test_split(self):
        data = b'abcde'
        block_size = 3
        expected_result = [b'abc', b'de']
        result = cryptopals.set1.split(data, block_size)
        self.assertEqual(result, expected_result)

    def test_transpose(self):
        blocks = [b'abc', b'de']
        expected_result = [b'ad', b'be', b'c']
        result = cryptopals.set1.transpose(blocks)
        self.assertEqual(result, expected_result)

if __name__ == '__main__':
    unittest.main()