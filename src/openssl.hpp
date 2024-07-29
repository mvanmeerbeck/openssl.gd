#pragma once

#include <godot_cpp/classes/object.hpp>
#include <godot_cpp/core/class_db.hpp>

using namespace godot;

class OpenSSL : public Object
{
	GDCLASS(OpenSSL, Object);

	static OpenSSL *singleton;

protected:
	static void _bind_methods();

public:
	static OpenSSL *get_singleton();

	OpenSSL();
	~OpenSSL();

	PackedByteArray keccak256(const PackedByteArray &input);
	PackedByteArray hmac_sha512(const PackedByteArray &data, const PackedByteArray &key);
	PackedByteArray pbkdf2_hmac_sha512(const PackedByteArray &password, const PackedByteArray &salt, int iterations, int key_length);
	PackedByteArray mod(PackedByteArray number_bytes, PackedByteArray mod_bytes);
	PackedByteArray add_mod(PackedByteArray a_bytes, PackedByteArray b_bytes, PackedByteArray mod_bytes);
	PackedByteArray calculate_public_key(const PackedByteArray &private_key_bytes);
	PackedByteArray sign(const PackedByteArray &priv_key_bytes, const PackedByteArray &data);
};
