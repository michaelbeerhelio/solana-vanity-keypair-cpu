from array import array

B58_DIGITS = array('B', [
    49, 50, 51, 52, 53, 54, 55, 56, 57,  # 1-9
    65, 66, 67, 68, 69, 70, 71, 72, 74,  # A-H,J
    75, 76, 77, 78, 80, 81, 82, 83, 84,  # K-N,P-T
    85, 86, 87, 88, 89, 90, 97, 98, 99,  # U-Z,a-c
    100, 101, 102, 103, 104, 105, 106,   # d-j
    107, 109, 110, 111, 112, 113, 114,   # k,m-r
    115, 116, 117, 118, 119, 120, 121,   # s-z
    122                                   # z
])

def b58_encode(data):
    # Count leading zeros
    zeros = 0
    for b in data:
        if b == 0:
            zeros += 1
        else:
            break
    
    # Convert to integer
    n = 0
    for byte in data:
        n = n * 256 + byte
    
    # Special case for zero
    if n == 0:
        result = array('B', [49] * max(1, zeros))
        return result
    
    # Convert to base58
    result = array('B')
    while n > 0:
        n, r = divmod(n, 58)
        result.append(B58_DIGITS[r])
    
    # Add leading '1's for zeros
    if zeros > 0:
        prefix = array('B', [49] * zeros)
        result = prefix + result
    
    # Reverse the array
    result.reverse()
    return result

def test_b58_encode():
    # Test vectors from Bitcoin's base58 implementation
    test_vectors = [
        ("00", "1"),
        ("0000", "11"),
        ("000000", "111"),
        ("2CF24DBA5FB0A30E", "8X3Ac75Kx29"),
        ("0123456789ABCDEF", "C3CPq7c8PY"),
    ]

    for hex_str, expected_b58 in test_vectors:
        # Convert hex to bytes in correct order (big-endian)
        test_data = array('B', bytes.fromhex(hex_str))
        
        result = b58_encode(test_data)
        result_str = ''.join(chr(b) for b in result)
        
        print(f"Input hex: {hex_str}")
        print(f"Expected b58: {expected_b58}")
        print(f"Got b58: {result_str}")
        print(f"Match: {result_str == expected_b58}\n")
        assert result_str == expected_b58, f"Expected {expected_b58}, got {result_str}"

if __name__ == "__main__":
    test_b58_encode()