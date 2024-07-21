#include "my_singleton.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include <openssl/evp.h>
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/variant/utility_functions.hpp>
#include <openssl/sha.h>

using namespace godot;

MySingleton *MySingleton::singleton = nullptr;

void MySingleton::_bind_methods()
{
	ClassDB::bind_method(D_METHOD("hello_singleton"), &MySingleton::hello_singleton);
	ClassDB::bind_method(D_METHOD("hashKeccak256", "data"), &MySingleton::hashKeccak256);
}

MySingleton *MySingleton::get_singleton()
{
	return singleton;
}

MySingleton::MySingleton()
{
	ERR_FAIL_COND(singleton != nullptr);
	singleton = this;

    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();	
}

MySingleton::~MySingleton()
{
	ERR_FAIL_COND(singleton != this);
	singleton = nullptr;
}

void MySingleton::hello_singleton()
{
	UtilityFunctions::print("Hello GDExtension Singleton!");
}

PackedByteArray MySingleton::hashKeccak256(const String& data) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    std::vector<unsigned char> md_value(EVP_MAX_MD_SIZE);
    unsigned int md_len;

    // Tente de charger dynamiquement l'algorithme Keccak256
    // Remplacez "KECCAK256" par le nom correct si différent
    md = EVP_MD_fetch(NULL, "KECCAK256", NULL);
    if (!md) {
        // Si Keccak256 n'est pas disponible, utilisez SHA3-256 comme fallback
        md = EVP_sha3_256();
    }

    mdctx = EVP_MD_CTX_new();
    if (!mdctx || !md) {
        // Gérer l'erreur, libérer les ressources si nécessaire
        if (md) EVP_MD_free((EVP_MD*)md); // Libérer l'algorithme si chargé
        return PackedByteArray(); // Retourner un tableau vide ou gérer l'erreur autrement
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL) ||
        1 != EVP_DigestUpdate(mdctx, data.utf8().get_data(), data.length()) ||
        1 != EVP_DigestFinal_ex(mdctx, md_value.data(), &md_len)) {
        // Gérer l'erreur, libérer les ressources
        EVP_MD_CTX_free(mdctx);
        if (md) EVP_MD_free((EVP_MD*)md); // Libérer l'algorithme si chargé
        return PackedByteArray(); // Retourner un tableau vide ou gérer l'erreur autrement
    }

    EVP_MD_CTX_free(mdctx);
    if (md) EVP_MD_free((EVP_MD*)md); // Libérer l'algorithme après utilisation

    md_value.resize(md_len); // Ajuste la taille du vecteur au résultat réel

    PackedByteArray result;
    for (size_t i = 0; i < md_len; ++i) {
        result.append(md_value[i]);
    }

    return result;
}