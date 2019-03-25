#pragma once

/*
* Adapted from the reference code implementation
*   Copyright 2017-2019 Dustin J Sparks
*   Using CC0 1.0 license, this code is released under the same.
* ===========================================================================
* Argon2 reference source code package - reference C implementations
*
* Copyright 2015
* Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
*
* You may use this work under the terms of a Creative Commons CC0 1.0
* License/Waiver or the Apache Public License 2.0, at your option. The terms of
* these licenses can be found at:
*
* - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
* - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
*
* You should have received a copy of both of these licenses along with this
* software. If not, they may be obtained at the above URLs.
*/

using namespace System;

#define IV0	0x6a09e667f3bcc908ULL
#define IV1	0xbb67ae8584caa73bULL
#define IV2	0x3c6ef372fe94f82bULL
#define IV3	0xa54ff53a5f1d36f1ULL
#define IV4	0x510e527fade682d1ULL
#define IV5	0x9b05688c2b3e6c1fULL
#define IV6	0x1f83d9abfb41bd6bULL
#define IV7	0x5be0cd19137e2179ULL

#define BLAKE2B_BLOCKBYTES		128
#define BLAKE2B_OUTBYTES		64
#define BLAKE2B_KEYBYTES		64
#define BLAKE2B_SALTBYTES		16
#define BLAKE2B_PERSONALBYTES	16

namespace Argon2Managed
{

	/*uint8_t digest_length;                    1 
	uint8_t key_length;                       2 
	uint8_t fanout;                           3 
	uint8_t depth;                            4 
	uint32_t leaf_length;                     8 
	uint64_t node_offset;                     16 
	uint8_t node_depth;                       17 
	uint8_t inner_length;                     18 
	uint8_t reserved[14];                     32 
	uint8_t salt[BLAKE2B_SALTBYTES];          48 
	uint8_t personal[BLAKE2B_PERSONALBYTES];  64 */

	/* Function that securely cleans the memory. This ignores any flags set
	* regarding clearing memory. Usually one just calls clear_internal_memory.
	* @param mem Pointer to the memory
	*/
#ifndef METHOD_SECURE_WIPE_BYTES
#define METHOD_SECURE_WIPE_BYTES
	static void secure_wipe_memory(array<Byte>^ data)
	{
		if (data == nullptr) return;
#if !_DEBUG
		try {
#endif
			Byte lm = 0;
			for (int i = 0; i < data->Length; i++)
			{
				data[i] &= lm ^ data[i] ^ data[i];
			}
			data[0] ^= data[data->Length - 1];
#if !_DEBUG
		}
		catch (...) {}
#endif
	}
#endif // secure_wipe_bytes

#ifndef METHOD_SECURE_WIPE_QWORDS
#define METHOD_SECURE_WIPE_QWORDS
	static void secure_wipe_memory(array<UInt64>^ data)
	{
		if (data == nullptr) return;
#if !_DEBUG
		try {
#endif
			Byte lm = 0;
			for (int i = 0; i < data->Length* sizeof(UInt64); i++)
			{
				Buffer::SetByte(data, i, lm & (Byte)data[0]);
			}
			data[0] ^= data[data->Length - 1];
#if !_DEBUG
		}
		catch (...) {}
#endif
	}
#endif // secure_wipe_qwords

	private ref class Blake2bState
	{
	public:
		Byte			OutputByteLen;
		array<UInt64>^	H = gcnew array<UInt64>(8); // primary state
		array<UInt64>^	M = gcnew array<UInt64>(16); // internal memory
		array<UInt64>^	T = gcnew array<UInt64>(2); // counters
		array<UInt64>^	F = gcnew array<UInt64>(2); // finalization flags
		array<Byte>^	Buffer = gcnew array<Byte>(BLAKE2B_BLOCKBYTES);
		Byte			BufferLen = 0;
		Byte			LastNode = 0;
		Blake2bState(const Byte keyLength, array<const Byte>^ salt, array<const Byte>^ personalization, const Byte outputLenByteCount)
		{
			if (keyLength > BLAKE2B_KEYBYTES)
				throw gcnew ArgumentOutOfRangeException(L"key",
					L"The key, when used, must be no more than " + BLAKE2B_KEYBYTES + " bytes in length!");
			if (salt != nullptr && salt->Length > BLAKE2B_SALTBYTES)
				throw gcnew ArgumentOutOfRangeException(L"salt",
					L"The salt, when used, must be no more than " + BLAKE2B_SALTBYTES + " bytes in length!");
			if (personalization != nullptr && personalization->Length > BLAKE2B_PERSONALBYTES)
				throw gcnew ArgumentOutOfRangeException(L"personalization",
					L"The personalization array, when used, must be no more than " + BLAKE2B_PERSONALBYTES + " bytes in length!");
			if (outputLenByteCount < 1 || outputLenByteCount > BLAKE2B_OUTBYTES)
				throw gcnew ArgumentOutOfRangeException(L"outputLenByteCount",
					L"The output byte length must be at least 1, and less than (or equal to) " + BLAKE2B_OUTBYTES + "!");
			this->OutputByteLen = outputLenByteCount;
			this->H[0] = IV0; this->H[1] = IV1; this->H[2] = IV2; this->H[3] = IV3; this->H[4] = IV4; this->H[5] = IV5; this->H[6] = IV6; this->H[7] = IV7; 
			this->H[0] ^= outputLenByteCount + (keyLength << 8) + 0x0000000001010000ULL; // fanout and depth = 1, node offset = 0
			array<UInt64>^ temp = gcnew array<UInt64>(4);
			if (salt != nullptr) // absorb salt into state
				Buffer::BlockCopy(salt, 0, temp, 0, salt->Length);
			if (personalization != nullptr) // absorb personalization into state
				Buffer::BlockCopy(personalization, 0, temp, 16, personalization->Length);
			this->H[4] ^= temp[0];
			this->H[5] ^= temp[1];
			this->H[6] ^= temp[2];
			this->H[7] ^= temp[3];
			
		}

		void Clear()
		{
			// MEMORY DESTRUCTION HERE!
			secure_wipe_memory(H);
			secure_wipe_memory(M);
			secure_wipe_memory(T);
			secure_wipe_memory(F);
		}

		~Blake2bState()
		{
			Clear();
		}
	};

	public ref class Blake2b
	{
	internal:
		bool _isInitialized = false;
		Blake2bState^ S;

		static void blake2b_compress(Blake2bState^ S, array<const Byte>^ block, int start);
		static void blake2b_update(Blake2bState^ S, array<const Byte>^ block);
		static void blake2b_update(Blake2bState^ S, array<const Byte>^ block, int position, int length);
		static array<Byte>^ blake2b_final(Blake2bState^ S);
		static Blake2bState^ blake2b_init(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount);
	public:
		Blake2b();
		Blake2b(Byte outputLenByteCount);
		Blake2b(array<const Byte>^ key, Byte outputLenByteCount);
		Blake2b(array<const Byte>^ key, array<const Byte>^ salt, Byte outputLenByteCount);
		Blake2b(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount);
		void Init(Byte outputLenByteCount);
		void Init(array<const Byte>^ key, Byte outputLenByteCount);
		void Init(array<const Byte>^ key, array<const Byte>^ salt, Byte outputLenByteCount);
		void Init(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount);
		void Update(array<const Byte>^ data);
		void Update(array<const Byte>^ data, int index, int length);
		array<Byte>^ Finish();
		array<Byte>^ ComputeHash(array<const Byte>^ data);
		~Blake2b();
	};
}

