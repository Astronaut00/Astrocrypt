#pragma once

#ifndef ASTROCRYPT_H
#define ASTROCRYPT_H

#include <aes.h>
#include <sha.h>
#include <modes.h>
#include <base64.h>
#include <hex.h>
#include <dh.h>
#include <rsa.h>
#include <osrng.h>
#include <pssr.h>
#include <random>
#pragma comment (lib, "cryptlib.lib")

namespace astrocrypt
{
	using namespace CryptoPP;

	inline std::string aes_encrypt(const std::string str_in,
		const std::string key,
		const std::string iv)
	{
		std::string str_out;

		CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryption((byte*)key.c_str(), key.length(), (byte*)iv.c_str());
		CryptoPP::StringSource encryptor(str_in, true,
			new CryptoPP::StreamTransformationFilter(encryption,
				new CryptoPP::Base64Encoder(
					new CryptoPP::StringSink(str_out),
					CryptoPP::BlockPaddingSchemeDef::NO_PADDING

				)
			)
		);

		return str_out;
	}

	inline std::string aes_decrypt(const std::string str_in,
		const std::string key,
		const std::string iv)
	{
		std::string str_out;


		CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryption((byte*)key.c_str(), key.length(), (byte*)iv.c_str());
		CryptoPP::StringSource decryptor(str_in, true,
			new CryptoPP::Base64Decoder(
				new CryptoPP::StreamTransformationFilter(decryption,
					new CryptoPP::StringSink(str_out)
				)
			)
		);

		return str_out;
	}

	inline std::string base64_encode(const char* data,
		const char* ALPHABET = NULL)
	{

		if (ALPHABET == NULL)
			ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		std::string encoded;
		auto base64 = new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		);

		CryptoPP::AlgorithmParameters p1 = CryptoPP::MakeParameters(CryptoPP::Name::EncodingLookupArray(), (const byte*)ALPHABET);
		base64->IsolatedInitialize(p1);

		CryptoPP::StringSource ss(data, true,
			base64
		);

		return encoded;
	}

	inline std::string base64_decode(std::string encoded_data,
		const char* ALPHABET = NULL)
	{

		if (ALPHABET == NULL)
			ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		std::string destination;

		auto base64 = new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(destination)
		);

		int lookup[256];
		CryptoPP::Base64Decoder::InitializeDecodingLookupArray(lookup, (const CryptoPP::byte*)ALPHABET, 64, false /*insensitive*/);

		CryptoPP::AlgorithmParameters p2 = CryptoPP::MakeParameters(CryptoPP::Name::DecodingLookupArray(), (const int*)lookup);
		base64->IsolatedInitialize(p2);

		CryptoPP::StringSource ss(encoded_data, true, base64);

		return destination;
	}

	inline std::string base64_encode(unsigned char* data, size_t size)
	{
		std::string encoded;

		CryptoPP::StringSource ss(data, size, true,
			new CryptoPP::Base64Encoder(
				new CryptoPP::StringSink(encoded)
			)
		);

		return encoded;
	}

	inline bool base64_decode(std::string encoded_data, unsigned char* data)
	{
		try {
			std::string destination;
			CryptoPP::StringSource ss(encoded_data, true, new CryptoPP::Base64Decoder(new CryptoPP::StringSink(destination)));
			memcpy_s(data, destination.size(), destination.data(), destination.size());
		}
		catch (...)
		{
			return false;
		}

		return true;
	}

	inline std::string sha256_hash(const std::string str_in)
	{
		CryptoPP::SHA256 hash;
		byte digest[CryptoPP::SHA256::DIGESTSIZE];
		hash.CalculateDigest(digest, (byte*)str_in.c_str(), str_in.length());

		CryptoPP::HexEncoder encoder;
		std::string output;
		encoder.Attach(new CryptoPP::StringSink(output));
		encoder.Put(digest, sizeof(digest));
		encoder.MessageEnd();

		return output;
	}

	inline std::string serialize_rsa_key(CryptoPP::RSA::PublicKey& pubKey)
	{
		std::string public_key_serialized;
		CryptoPP::Base64Encoder sink(new CryptoPP::StringSink(public_key_serialized));
		pubKey.DEREncode(sink);
		sink.MessageEnd();

		return public_key_serialized.c_str();
	}

	inline bool unserialize_rsa_key(std::string& public_key_serialized, CryptoPP::RSA::PublicKey* pubKey)
	{
		CryptoPP::StringSource ss(public_key_serialized.c_str(), true, new CryptoPP::Base64Decoder);
		pubKey->BERDecode(ss);

		return true;
	}

	inline std::string rsa_encrypt(CryptoPP::RSA::PublicKey& public_key, std::string plain)
	{
		std::string cipher;
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::RSAES_OAEP_SHA_Encryptor e(public_key);

		CryptoPP::StringSource ss(plain, true,
			new CryptoPP::PK_EncryptorFilter(rng, e,
				new CryptoPP::Base64Encoder(new CryptoPP::StringSink(cipher))) // PK_EncryptorFilter
		); // StringSource

		return cipher;
	}

	inline bool rsa_decrypt(CryptoPP::RSA::PrivateKey& private_key,
		std::string& cipher,
		std::string* decrypted)
	{
		try
		{
			std::string recovered;
			CryptoPP::AutoSeededRandomPool rng;
			CryptoPP::RSAES_OAEP_SHA_Decryptor d(private_key);

			std::string decoded;
			CryptoPP::StringSource ss_b64(cipher, true,
				new CryptoPP::Base64Decoder(
					new CryptoPP::StringSink(decoded)
				)
			);

			CryptoPP::StringSource ss_df(decoded, true,
				new CryptoPP::PK_DecryptorFilter(rng, d,
					new CryptoPP::StringSink(recovered)
				)
			);
			*decrypted = recovered;
			//ss_b64.MessageEnd();
			//ss_df.MessageEnd();
		}
		catch (...)
		{
			return false;
		}
		return true;
	}




	std::vector<unsigned char> encrypt_decrypt_data(std::vector<unsigned char> data,
		std::vector<unsigned char> key)
	{
		int n1 = 15;
		int n2 = 17;
		int ns = 358;
		for (int I = 0; I <= key.size() - 1; I++)
		{
			ns += ns % (key[I] + 1);
		}
		std::vector<unsigned char> out(data.size());
		for (int I = 0; I <= data.size() - 1; I++)
		{
			ns = key[I % key.size()] + ns;
			n1 = (ns + 5) * (n1 & 255) + (n1 >> 8);
			n2 = (ns + 7) * (n2 & 255) + (n2 >> 8);
			ns = ((n1 << 8) + n2) & 255;

			out[I] = static_cast<unsigned char>(data[I] ^ static_cast<unsigned char>(ns));
		}
		return out;
	}

	//"ABCDFGHJKLMNPQRSTVWXZbcdfghjklmnpqrstvwxz"
	//"0123456789"
	//"¯ﬁ¬Å3ö∆xIÚ™m'+ˇÕ„"
	std::string random_string(int len, const std::string allowed_chars)
	{
		static thread_local std::default_random_engine randomEngine(std::random_device{}());
		static thread_local std::uniform_int_distribution<int> randomDistribution(0, allowed_chars.size() - 1);
		std::string id(len ? len : 32, '\0');
		for (std::string::value_type& c : id) {
			c = allowed_chars[randomDistribution(randomEngine)];
		}
		return id;
	}
}

#endif