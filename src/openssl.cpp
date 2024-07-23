#include "openssl.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include <openssl/evp.h>
#include <godot_cpp/core/class_db.hpp>
#include <godot_cpp/variant/utility_functions.hpp>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

using namespace godot;

OpenSSL *OpenSSL::singleton = nullptr;

void OpenSSL::_bind_methods()
{
	ClassDB::bind_method(D_METHOD("keccak256", "data"), &OpenSSL::keccak256);
    ClassDB::bind_method(D_METHOD("hmac_sha512", "data"), &OpenSSL::hmac_sha512);
    ClassDB::bind_method(D_METHOD("pbkdf2_hmac_sha512", "password", "salt", "iterations", "key_length"), &OpenSSL::pbkdf2_hmac_sha512);
    ClassDB::bind_method(D_METHOD("mod", "number_bytes", "mod_bytes"), &OpenSSL::mod);
    ClassDB::bind_method(D_METHOD("add_mod", "a_bytes", "b_bytes", "mod_bytes"), &OpenSSL::add_mod);
    ClassDB::bind_method(D_METHOD("calculate_public_key", "private_key_bytes"), &OpenSSL::calculate_public_key);
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

PackedByteArray OpenSSL::hmac_sha512(const PackedByteArray& data, const PackedByteArray& key) {
    const EVP_MD* md = EVP_sha512();
    unsigned int len = EVP_MD_size(md);
    std::vector<unsigned char> hmac_value(len);

    HMAC(md, key.ptr(), key.size(), data.ptr(), data.size(), hmac_value.data(), &len);

    PackedByteArray result;
    result.resize(len);
    memcpy(result.ptrw(), hmac_value.data(), len);

    return result;
}

PackedByteArray OpenSSL::pbkdf2_hmac_sha512(const PackedByteArray& password, const PackedByteArray& salt, int iterations, int key_length) {
    PackedByteArray key;
    key.resize(key_length);
    const unsigned char* password_data = password.ptr();
    const unsigned char* salt_data = salt.ptr();
    unsigned char* key_data = key.ptrw();

    int success = PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(password_data), password.size(), reinterpret_cast<const unsigned char*>(salt_data), salt.size(), iterations, EVP_sha512(), key_length, key_data);

    if (!success) {
        // Handle error: PKCS5_PBKDF2_HMAC failed
        key.resize(0); // Clear the key if operation failed
    }

    return key;
}

PackedByteArray OpenSSL::mod(PackedByteArray number_bytes, PackedByteArray mod_bytes) {
    BIGNUM *bn_number = BN_new();
    BIGNUM *bn_mod = BN_new();
    BIGNUM *result = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // Convertit PackedByteArray en BIGNUM
    BN_bin2bn(number_bytes.ptr(), number_bytes.size(), bn_number);
    BN_bin2bn(mod_bytes.ptr(), mod_bytes.size(), bn_mod);

    // Effectue l'opération de modulo
    BN_mod(result, bn_number, bn_mod, ctx);

    // Vérifie si le résultat est 0
    if (BN_is_zero(result)) {
        // Nettoyage
        BN_free(bn_number);
        BN_free(bn_mod);
        BN_free(result);
        BN_CTX_free(ctx);

        // Retourne un PackedByteArray contenant un seul octet de valeur 0
        PackedByteArray zero_array;
        zero_array.append(0);
        return zero_array;
    }

    // Convertit le résultat en PackedByteArray
    int num_bytes = BN_num_bytes(result);
    PackedByteArray result_array;
    result_array.resize(num_bytes);
    BN_bn2bin(result, result_array.ptrw());

    // Nettoyage
    BN_free(bn_number);
    BN_free(bn_mod);
    BN_free(result);
    BN_CTX_free(ctx);

    return result_array;
}

PackedByteArray OpenSSL::add_mod(PackedByteArray a_bytes, PackedByteArray b_bytes, PackedByteArray mod_bytes) {
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *mod = BN_new();
    BIGNUM *result = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    BN_bin2bn(a_bytes.ptr(), a_bytes.size(), a);
    BN_bin2bn(b_bytes.ptr(), b_bytes.size(), b);
    BN_bin2bn(mod_bytes.ptr(), mod_bytes.size(), mod);

    BN_mod_add(result, a, b, mod, ctx);

    int num_bytes = BN_num_bytes(result);
    PackedByteArray result_array;
    result_array.resize(num_bytes);
    BN_bn2bin(result, result_array.ptrw());

    BN_free(a);
    BN_free(b);
    BN_free(mod);
    BN_free(result);
    BN_CTX_free(ctx);

    return result_array;
}

PackedByteArray OpenSSL::calculate_public_key(const PackedByteArray &private_key_bytes) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key) {
        // Gestion des erreurs
        return PackedByteArray();
    }

    BIGNUM *priv_key_bn = BN_bin2bn(private_key_bytes.ptr(), private_key_bytes.size(), nullptr);
    if (!priv_key_bn) {
        // Gestion des erreurs
        EC_KEY_free(ec_key);
        return PackedByteArray();
    }

    if (!EC_KEY_set_private_key(ec_key, priv_key_bn)) {
        // Gestion des erreurs
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        return PackedByteArray();
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *pub_key_point = EC_POINT_new(group);
    if (!pub_key_point) {
        // Gestion des erreurs
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        return PackedByteArray();
    }

    if (!EC_POINT_mul(group, pub_key_point, priv_key_bn, nullptr, nullptr, nullptr)) {
        // Gestion des erreurs
        EC_POINT_free(pub_key_point);
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        return PackedByteArray();
    }

    if (!EC_KEY_set_public_key(ec_key, pub_key_point)) {
        // Gestion des erreurs
        EC_POINT_free(pub_key_point);
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        return PackedByteArray();
    }

    // Obtenir la longueur de la clé publique compressée
    size_t compressed_pub_key_len = EC_POINT_point2oct(group, pub_key_point, POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
    if (compressed_pub_key_len == 0) {
        // Gestion des erreurs
        EC_POINT_free(pub_key_point);
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        return PackedByteArray();
    }

    // Allouer de la mémoire pour la clé publique compressée
    PackedByteArray pub_key_bytes;
    pub_key_bytes.resize(compressed_pub_key_len);
    unsigned char *pub_key_data = pub_key_bytes.ptrw();

    // Remplir la clé publique compressée
    if (EC_POINT_point2oct(group, pub_key_point, POINT_CONVERSION_COMPRESSED, pub_key_data, compressed_pub_key_len, nullptr) != compressed_pub_key_len) {
        // Gestion des erreurs
        EC_POINT_free(pub_key_point);
        BN_free(priv_key_bn);
        EC_KEY_free(ec_key);
        return PackedByteArray();
    }

    // Nettoyage
    EC_POINT_free(pub_key_point);
    BN_free(priv_key_bn);
    EC_KEY_free(ec_key);

    return pub_key_bytes;
}