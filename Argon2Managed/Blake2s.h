#pragma once

/*
* Adapted from the reference code implementation
*   Copyright 2017 Dustin J Sparks
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

#define IV0S	0x6A09E667UL
#define IV1S	0xBB67AE85UL
#define IV2S	0x3C6EF372UL
#define IV3S	0xA54FF53AUL
#define IV4S	0x510E527FUL
#define IV5S	0x9B05688CUL
#define IV6S	0x1F83D9ABUL
#define IV7S	0x5BE0CD19UL

#define BLAKE2S_BLOCKBYTES		64
#define BLAKE2S_OUTBYTES		32
#define BLAKE2S_KEYBYTES		32
#define BLAKE2S_SALTBYTES		8
#define BLAKE2S_PERSONALBYTES	8

namespace Argon2Managed
{

	/* from the ref C, since we are not doing any tree hashing, we care about '+' of the following:
	typedef struct __blake2s_param
	{
	uint8_t  digest_length; // 1 +
	uint8_t  key_length;    // 2 +
	uint8_t  fanout;        // 3 =1
	uint8_t  depth;         // 4 =1
	uint32_t leaf_length;   // 8 =0
	uint8_t  node_offset[6];// 14 =0
	uint8_t  node_depth;    // 15 =0
	uint8_t  inner_length;  // 16 =0
	uint8_t  salt[BLAKE2S_SALTBYTES]; // 24 +
	uint8_t  personal[BLAKE2S_PERSONALBYTES];  // 32 +
	} blake2s_param;
	//*/

	private ref class Blake2sState
	{
	public:
		Byte			OutputByteLen;
		array<UInt32>^	H = gcnew array<UInt32>(8); // primary state
		array<UInt32>^	M = gcnew array<UInt32>(16); // internal memory
		array<UInt32>^	T = gcnew array<UInt32>(2); // counters
		array<UInt32>^	F = gcnew array<UInt32>(2); // finalization flags
		array<Byte>^	Buffer = gcnew array<Byte>(BLAKE2S_BLOCKBYTES);
		Byte			BufferLen = 0;
		Byte			LastNode = 0;
		Blake2sState(const Byte keyLength, array<const Byte>^ salt, array<const Byte>^ personalization, const Byte outputLenByteCount)
		{
			if (keyLength > BLAKE2S_KEYBYTES)
				throw gcnew ArgumentOutOfRangeException(L"key",
					L"The key, when used, must be no more than " + BLAKE2S_KEYBYTES + " bytes in length!");
			if (salt != nullptr && salt->Length > BLAKE2S_SALTBYTES)
				throw gcnew ArgumentOutOfRangeException(L"salt",
					L"The salt, when used, must be no more than " + BLAKE2S_SALTBYTES + " bytes in length!");
			if (personalization != nullptr && personalization->Length > BLAKE2S_PERSONALBYTES)
				throw gcnew ArgumentOutOfRangeException(L"personalization",
					L"The personalization array, when used, must be no more than " + BLAKE2S_PERSONALBYTES + " bytes in length!");
			if (outputLenByteCount < 1 || outputLenByteCount > BLAKE2S_OUTBYTES)
				throw gcnew ArgumentOutOfRangeException(L"outputLenByteCount",
					L"The output byte length must be at least 1, and less than (or equal to) " + BLAKE2S_OUTBYTES + "!");
			this->OutputByteLen = outputLenByteCount;
			this->H[0] = IV0S; this->H[1] = IV1S; this->H[2] = IV2S; this->H[3] = IV3S; this->H[4] = IV4S; this->H[5] = IV5S; this->H[6] = IV6S; this->H[7] = IV7S;
			this->H[0] ^= outputLenByteCount + (keyLength << 8) + 0x01010000UL; // fanout and depth = 1, node offset = 0
			array<UInt32>^ temp = gcnew array<UInt32>(4);
			if (salt != nullptr) // absorb salt into state
				Buffer::BlockCopy(salt, 0, temp, 0, salt->Length);
			if (personalization != nullptr) // absorb personalization into state
				Buffer::BlockCopy(personalization, 0, temp, 8, personalization->Length);
			this->H[4] ^= temp[0];
			this->H[5] ^= temp[1];
			this->H[6] ^= temp[2];
			this->H[7] ^= temp[3];

		}

		~Blake2sState()
		{
			// MEMORY DESTRUCTION HERE!
		}
	};

	public ref class Blake2s
	{
	internal:
		bool _isInitialized = false;
		Blake2sState^ S;

		static void blake2s_compress(Blake2sState^ S, array<const Byte>^ block, int start);
		static void blake2s_update(Blake2sState^ S, array<const Byte>^ block);
		static array<Byte>^ blake2s_final(Blake2sState^ S);
		static Blake2sState^ blake2s_init(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount);
	public:
		Blake2s();
		Blake2s(Byte outputLenByteCount);
		Blake2s(array<const Byte>^ key, Byte outputLenByteCount);
		Blake2s(array<const Byte>^ key, array<const Byte>^ salt, Byte outputLenByteCount);
		Blake2s(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount);
		void Init(Byte outputLenByteCount);
		void Init(array<const Byte>^ key, Byte outputLenByteCount);
		void Init(array<const Byte>^ key, array<const Byte>^ salt, Byte outputLenByteCount);
		void Init(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount);
		array<Byte>^ ComputeHash(array<const Byte>^ data);
		~Blake2s();
	};
}

