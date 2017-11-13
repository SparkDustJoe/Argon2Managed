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

#include "Blake2s.h"
#include "Blake2s_Compress.cpp"
using namespace System;

namespace Argon2Managed
{
	void Blake2s::blake2s_update(Blake2sState^ S, array<const Byte>^ data)
	{
		int inputPtr = 0;
		int inLen = data->Length;
		if (data->Length == 0) {
			return;
		}

		/* Is this a reused state? */
		if (S->F[0] != 0) {
			throw gcnew InvalidOperationException("FLAG0");
		}

		if (S->BufferLen + inLen> BLAKE2S_BLOCKBYTES) {
			/* Complete current block */
			int left = S->BufferLen;
			int fill = BLAKE2S_BLOCKBYTES - left;
			Buffer::BlockCopy(data, inputPtr, S->Buffer, left, fill);

			S->T[0] += BLAKE2S_BLOCKBYTES;
			S->T[1] += (S->T[0] < BLAKE2S_BLOCKBYTES);

			blake2s_compress(S, (array<const Byte>^)S->Buffer, 0);
			S->BufferLen = 0;
			inLen -= fill;
			inputPtr += fill;
			/* Avoid buffer copies when possible */
			while (inLen > BLAKE2S_BLOCKBYTES) {
				S->T[0] += BLAKE2S_BLOCKBYTES;
				S->T[1] += (S->T[0] < BLAKE2S_BLOCKBYTES);
				blake2s_compress(S, data, inputPtr);
				inLen -= BLAKE2S_BLOCKBYTES;
				inputPtr += BLAKE2S_BLOCKBYTES;
			}
		}
		Buffer::BlockCopy(data, inputPtr, S->Buffer, S->BufferLen, inLen);
		S->BufferLen += (unsigned int)inLen;
	}

	array<Byte>^ Blake2s::blake2s_final(Blake2sState^ S) {
		array<Byte>^ out = gcnew array<Byte>(S->OutputByteLen);
		array<Byte>^ buffer = gcnew array<Byte>(BLAKE2S_OUTBYTES);

		/* Is this a reused state? */
		if (S->F[0] != 0) {
			throw gcnew InvalidOperationException("FLAG0");
		}

		S->T[0] += S->BufferLen;
		S->T[1] += (S->T[0] < S->BufferLen);

		if (S->LastNode) {
			S->F[1] = 0xFFFFFFFFUL;
		}
		S->F[0] = 0xFFFFFFFFUL;

		for (Byte i = S->BufferLen; i <  BLAKE2S_BLOCKBYTES; i++) // padding
			Buffer::SetByte(S->Buffer, i, 0);
		blake2s_compress(S, (array<const Byte>^)S->Buffer, 0);

		Buffer::BlockCopy(S->H, 0, buffer, 0, buffer->Length);
		Buffer::BlockCopy(buffer, 0, out, 0, S->OutputByteLen);

		//clear_internal_memory(buffer, sizeof(buffer));
		//clear_internal_memory(_buf, sizeof(_buf));
		//clear_internal_memory(_h, sizeof(_h));

		return out;
	}

	Blake2sState^ Blake2s::blake2s_init(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount)
	{
		Byte keyLength = (Byte)(key != nullptr ? key->Length : 0);
		Blake2sState^ S = gcnew Blake2sState(keyLength, salt, personalization, outputLenByteCount);
		if (key != nullptr && key->Length > 0)
		{
			array<Byte>^ block = gcnew array<Byte>(BLAKE2S_BLOCKBYTES);
			Buffer::BlockCopy(key, 0, block, 0, key->Length);
			Blake2s::blake2s_update(S, (array<const Byte>^)block);
		}
		return S;
	}

	Blake2s::Blake2s() {
		// do nothing, initialized = false, so nothing can be processed
	}

	Blake2s::Blake2s(Byte outputLenByteCount) {
		Init(nullptr, nullptr, nullptr, outputLenByteCount);
	}
	Blake2s::Blake2s(array<const Byte>^ key, Byte outputLenByteCount) {
		Init(key, nullptr, nullptr, outputLenByteCount);
	}
	Blake2s::Blake2s(array<const Byte>^ key, array<const Byte>^ salt, Byte outputLenByteCount) {
		Init(key, salt, nullptr, outputLenByteCount);
	}
	Blake2s::Blake2s(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount) {
		Init(key, salt, personalization, outputLenByteCount);
	}
	void Blake2s::Init(Byte outputLenByteCount) {
		Init(nullptr, nullptr, nullptr, outputLenByteCount);
	}
	void Blake2s::Init(array<const Byte>^ key, Byte outputLenByteCount) {
		Init(key, nullptr, nullptr, outputLenByteCount);
	}
	void Blake2s::Init(array<const Byte>^ key, array<const Byte>^ salt, Byte outputLenByteCount) {
		Init(key, salt, nullptr, outputLenByteCount);
	}

	// All init roads lead to here
	void Blake2s::Init(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount) {
		S = blake2s_init(key, salt, personalization, outputLenByteCount);
		_isInitialized = true;
	}

	array<Byte>^ Blake2s::ComputeHash(array<const Byte>^ data) {
		if (_isInitialized == false)
			throw gcnew InvalidOperationException(L"Object not initialized! Call the appropriate Init method first!");
		blake2s_update(S, data);
		return blake2s_final(S);
	}

	Blake2s::~Blake2s() {

	}
}

