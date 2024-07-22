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

	PackedByteArray keccak256(const String& data);
	PackedByteArray hmac_sha512(const String& data, const String& key);
};
