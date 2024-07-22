#include "openssl.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include <openssl/evp.h>
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/variant/utility_functions.hpp>
#include <openssl/sha.h>
#include <openssl/provider.h>


using namespace godot;

OpenSSL *OpenSSL::singleton = nullptr;

void OpenSSL::_bind_methods()
{
	ClassDB::bind_method(D_METHOD("keccak256", "data"), &OpenSSL::keccak256);
    ClassDB::bind_method(D_METHOD("hmac_sha512", "data"), &OpenSSL::hmac_sha512);
}

OpenSSL *OpenSSL::get_singleton()
{
	return singleton;
}

OpenSSL::OpenSSL()
{
	ERR_FAIL_COND(singleton != nullptr);
	singleton = this;

    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();	
}

OpenSSL::~OpenSSL()
{
	ERR_FAIL_COND(singleton != this);
	singleton = nullptr;
}

PackedByteArray OpenSSL::keccak256(const String& data) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    std::vector<unsigned char> md_value(EVP_MAX_MD_SIZE);
    unsigned int md_len;

    // Tente de charger dynamiquement l'algorithme Keccak256
    // Remplacez "KECCAK256" par le nom correct si différent
    md = EVP_MD_fetch(NULL, "KECCAK-256", NULL);

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

PackedByteArray OpenSSL::hmac_sha512(const String& data, const String& key) {
    const EVP_MD* md = EVP_sha512();
    unsigned int len = EVP_MD_size(md);
    std::vector<unsigned char> hmac_value(len);

    HMAC(md, key.utf8().get_data(), key.length(), reinterpret_cast<const unsigned char*>(data.utf8().get_data()), data.length(), hmac_value.data(), &len);

    PackedByteArray result;
    for (size_t i = 0; i < len; ++i) {
        result.append(hmac_value[i]);
    }

    return result;
}