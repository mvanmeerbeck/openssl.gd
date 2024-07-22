extends Node

func _ready() -> void:
	print("Hello GDScript!")
	print(OpenSSL.keccak256('toto').hex_encode())
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
