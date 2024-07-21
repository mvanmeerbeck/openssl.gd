extends Node

func _ready() -> void:
	print("Hello GDScript!")
	MySingleton.hello_singleton()
	print(MySingleton.hashKeccak256('toto').hex_encode())
