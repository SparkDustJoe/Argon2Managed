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

#include "Blake2b.h"
#include "Blake2b_Compress.cpp"
using namespace System;

namespace Argon2Managed
{
	void Blake2b::blake2b_update(Blake2bState^ S, array<const Byte>^ data, int position, int length)
	{
		int inputPtr = position;
		int inLen = length;
		if (position + length > data->Length)
			throw gcnew IndexOutOfRangeException("Blake2b::update->Indicated position and length are beyond the bounds of the provided array.");
		if (data->Length == 0 || length == 0) {
			return;
		}

		/* Is this a reused state? */
		if (S->F[0] != 0) {
			throw gcnew InvalidOperationException("FLAG0");
		}

		if (S->BufferLen + inLen> BLAKE2B_BLOCKBYTES) {
			/* Complete current block */
			int left = S->BufferLen;
			int fill = BLAKE2B_BLOCKBYTES - left;
			Buffer::BlockCopy(data, inputPtr, S->Buffer, left, fill);

			S->T[0] += BLAKE2B_BLOCKBYTES;
			S->T[1] += (S->T[0] < BLAKE2B_BLOCKBYTES);

			blake2b_compress(S, (array<const Byte>^)S->Buffer, 0);
			S->BufferLen = 0;
			inLen -= fill;
			inputPtr += fill;
			/* Avoid buffer copies when possible */
			while (inLen > BLAKE2B_BLOCKBYTES) {
				S->T[0] += BLAKE2B_BLOCKBYTES;
				S->T[1] += (S->T[0] < BLAKE2B_BLOCKBYTES);
				blake2b_compress(S, data, inputPtr);
				inLen -= BLAKE2B_BLOCKBYTES;
				inputPtr += BLAKE2B_BLOCKBYTES;
			}
		}
		Buffer::BlockCopy(data, inputPtr, S->Buffer, S->BufferLen, inLen);
		S->BufferLen += (unsigned int)inLen;
	}

	void Blake2b::blake2b_update(Blake2bState^ S, array<const Byte>^ data)
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

		if (S->BufferLen + inLen> BLAKE2B_BLOCKBYTES) { 
			/* Complete current block */
			int left = S->BufferLen;
			int fill = BLAKE2B_BLOCKBYTES - left;
			Buffer::BlockCopy(data, inputPtr, S->Buffer, left, fill);

			S->T[0] += BLAKE2B_BLOCKBYTES;
			S->T[1] += (S->T[0] < BLAKE2B_BLOCKBYTES);

			blake2b_compress(S, (array<const Byte>^)S->Buffer, 0);
			S->BufferLen = 0;
			inLen -= fill;
			inputPtr += fill;
			/* Avoid buffer copies when possible */
			while (inLen > BLAKE2B_BLOCKBYTES) {
				S->T[0] += BLAKE2B_BLOCKBYTES;
				S->T[1] += (S->T[0] < BLAKE2B_BLOCKBYTES);
				blake2b_compress(S, data, inputPtr);
				inLen -= BLAKE2B_BLOCKBYTES;
				inputPtr += BLAKE2B_BLOCKBYTES;
			}
		}
		Buffer::BlockCopy(data, inputPtr, S->Buffer, S->BufferLen, inLen);
		S->BufferLen += (unsigned int)inLen;
	}

	array<Byte>^ Blake2b::blake2b_final(Blake2bState^ S) {
		array<Byte>^ out = gcnew array<Byte>(S->OutputByteLen);		
		array<Byte>^ buffer = gcnew array<Byte>(BLAKE2B_OUTBYTES);

		/* Is this a reused state? */
		if (S->F[0] != 0) {
			throw gcnew InvalidOperationException("FLAG0");
		}

		S->T[0] += S->BufferLen;
		S->T[1] += (S->T[0] < S->BufferLen);
		
		if (S->LastNode) {
			S->F[1] = 0xFFFFFFFFFFFFFFFFULL;
		}
		S->F[0] = 0xFFFFFFFFFFFFFFFFULL;

		for (Byte i = S->BufferLen; i < BLAKE2B_BLOCKBYTES; i++) // padding
			Buffer::SetByte(S->Buffer, i, 0);
		blake2b_compress(S, (array<const Byte>^)S->Buffer, 0);

		Buffer::BlockCopy(S->H, 0, buffer, 0, buffer->Length);
		Buffer::BlockCopy(buffer, 0, out, 0, S->OutputByteLen);

		//clear_internal_memory(buffer, sizeof(buffer));
		//clear_internal_memory(_buf, sizeof(_buf));
		//clear_internal_memory(_h, sizeof(_h));

		return out;
	}

	Blake2bState^ Blake2b::blake2b_init(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount)
	{
		Byte keyLength = (Byte)(key != nullptr ? key->Length : 0);
		Blake2bState^ S = gcnew Blake2bState(keyLength, salt, personalization, outputLenByteCount);
		if (key != nullptr && key->Length > 0)
		{
			array<Byte>^ block = gcnew array<Byte>(BLAKE2B_BLOCKBYTES);
			Buffer::BlockCopy(key, 0, block, 0, key->Length);
			Blake2b::blake2b_update(S, (array<const Byte>^)block);
		}
		return S;
	}

	Blake2b::Blake2b() {
		// do nothing, initialized = false, so nothing can be processed
	}

	Blake2b::Blake2b(Byte outputLenByteCount) {
		Init(nullptr, nullptr, nullptr, outputLenByteCount);
	}
	Blake2b::Blake2b(array<const Byte>^ key, Byte outputLenByteCount) {
		Init(key, nullptr, nullptr, outputLenByteCount);
	}
	Blake2b::Blake2b(array<const Byte>^ key, array<const Byte>^ salt, Byte outputLenByteCount) {
		Init(key, salt, nullptr, outputLenByteCount);
	}
	Blake2b::Blake2b(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount) {
		Init(key, salt, personalization, outputLenByteCount);
	}
	void Blake2b::Init(Byte outputLenByteCount) {
		Init(nullptr, nullptr, nullptr, outputLenByteCount);
	}
	void Blake2b::Init(array<const Byte>^ key, Byte outputLenByteCount) {
		Init(key, nullptr, nullptr, outputLenByteCount);
	}
	void Blake2b::Init(array<const Byte>^ key, array<const Byte>^ salt, Byte outputLenByteCount) {
		Init(key, salt, nullptr, outputLenByteCount);
	}

	void Blake2b::Init(array<const Byte>^ key, array<const Byte>^ salt, array<const Byte>^ personalization, Byte outputLenByteCount) {
		S = blake2b_init(key, salt, personalization, outputLenByteCount);
		_isInitialized = true;
	}

	array<Byte>^ Blake2b::ComputeHash(array<const Byte>^ data) {
		if (_isInitialized == false)
			throw gcnew InvalidOperationException(L"Object not initialized! Call the appropriate Init method first!");
		blake2b_update(S, data);
		return blake2b_final(S);
	}

	void Blake2b::Update(array<const Byte>^ data)
	{
		blake2b_update(S, data);
	}

	void Blake2b::Update(array<const Byte>^ data, int index, int length)
	{
		blake2b_update(S, data, index, length);
	}

	array<Byte>^ Blake2b::Finish()
	{
		return blake2b_final(S);
	}

	Blake2b::~Blake2b() {

	}
}
