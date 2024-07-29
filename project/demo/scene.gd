extends Node

func _ready() -> void:
    print("Hello GDScript!")
    print("keccak ", OpenSSL.keccak256('foobar'.to_utf8_buffer()).hex_encode())
    print(OpenSSL.hmac_sha512("VotreMessage".to_utf8_buffer(), "VotreCleSecrete".to_utf8_buffer()).hex_encode())
    print(OpenSSL.pbkdf2_hmac_sha512("motdepasse".to_utf8_buffer(), "sel".to_utf8_buffer(), 1000, 64).hex_encode())
    var byte_array: PackedByteArray = PackedByteArray()
    byte_array.resize(8)
    byte_array.encode_u64(0, 20)
    var modulo: PackedByteArray = PackedByteArray()
    modulo.resize(8)
    modulo.encode_u64(0, 3)
    print(OpenSSL.mod(byte_array, modulo).decode_u64(0))
    print(OpenSSL.add_mod(byte_array, byte_array, modulo).decode_u64(0))
    var private_key = PackedByteArray([0x86, 0xe4, 0xbd, 0xa2, 0x14, 0xf9, 0x2e, 0xd5, 0xf7, 0x09, 0xbc, 0x4a, 0x08, 0xf6, 0x05, 0x1c, 0xb0, 0x92, 0xc1, 0x67, 0xd4, 0x1a, 0x98, 0x06, 0x06, 0x88, 0x22, 0xa4, 0x2f, 0xa9, 0x61, 0xe3])
    var public_key = OpenSSL.calculate_public_key(private_key)
    print("PK ", private_key.hex_encode())
    print("pub ", public_key.hex_encode())

    var message = "foobar"
    var message_bytes = message.to_utf8_buffer()
    var prefix = "\u0019Ethereum Signed Message:\n" + str(message_bytes.size())
    var prefixed_message = prefix.to_utf8_buffer() + message_bytes

    var data: PackedByteArray = OpenSSL.keccak256(prefixed_message)
    print("Data: ", data.hex_encode())
    var signature: PackedByteArray = OpenSSL.sign(private_key, data)
    print("sig ", signature.hex_encode())