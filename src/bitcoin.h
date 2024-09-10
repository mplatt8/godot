#ifndef BITCOIN_H
#define BITCOIN_H

#include "core/object/ref_counted.h"
#include "core/string/ustring.h"
#include "core/variant/dictionary.h"
#include "core/templates/hash_map.h"
#include "core/class_db.hpp"
#include "core/object/class_db.h"
#ifdef __cplusplus
extern "C" {
#endif

#include "sha512.h"
#include "sha256.h"

#ifdef __cplusplus
}
#endif

#include <random>

namespace godot {

class BitcoinWallet : public RefCounted {
    GDCLASS(BitcoinWallet, RefCounted);

protected:
    static void _bind_methods();

private:
    PackedByteArray sha512(const PackedByteArray &p_data);
    PackedByteArray sha256(const PackedByteArray &data);
    String bytes_to_binary(const PackedByteArray &bytes);
    String bytes_to_hex(const PackedByteArray &bytes);
    int binary_to_int(const String &binary);
    PackedByteArray pbkdf2_hmac_sha512(const String& password, const PackedByteArray& salt, int iterations, int key_length);
    PackedByteArray hmac_sha512(const PackedByteArray &key, const PackedByteArray &data);
    PackedByteArray int_to_bytes(int value);
    bool seed_to_keys(const PackedByteArray& vchEntropy, String& strMasterKey, String& strChainCode);
    String hex_to_dec(const String &hex);
    PackedByteArray hex_to_bytes(const String &hex);
    PackedByteArray generate_random_bytes(int length);
    bool is_valid_mnemonic(const String &word);
    String fast_create();
    PackedByteArray derive_child_key(const PackedByteArray &parent_key, int index);
    Dictionary generate_sidechain_starters(const String &master_seed_hex, const String &master_mnemonic, const Array &sidechain_slots);
public:
    Dictionary generate_wallet(const String &input_string, const String &passphrase = "");
    PackedByteArray derive_seed(const String &mnemonic, const String &passphrase);
    String entropy_to_mnemonic(const PackedByteArray& entropy);
    PackedByteArray mnemonic_to_entropy(const String& mnemonic);

    BitcoinWallet();
    ~BitcoinWallet();
};

}

#endif // BITCOIN_H