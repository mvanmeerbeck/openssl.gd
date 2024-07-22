extends Node

func _ready() -> void:
	print("Hello GDScript!")
	print(OpenSSL.keccak256('toto').hex_encode())
	print(OpenSSL.hmac_sha512("VotreMessage", "VotreCleSecrete").hex_encode())
