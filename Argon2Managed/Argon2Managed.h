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
using namespace System::Runtime::InteropServices;

#include "Argon2ErrorCodes.h"
#include "Blake2s.cpp"
#include "Blake2b.cpp"
#include "ArgonCore.cpp"

namespace Argon2Managed 
{
	public ref class Argon2
	{
	internal:
		static int argon2_hash(
			array<const Byte>^ password, array<const Byte>^ salt, const UInt32 outputLengthBytes,
			const Argon2Type type,
			array<const Byte>^ secret,
			array<const Byte>^ additionalData,
			const UInt32 timeCost, const UInt32 memoryKb, const UInt32 lanes,
			array<Byte>^ output, Context^% ctx);
	public:
		static int ComputeHash(
			array<const Byte>^ password,
			array<const Byte>^ salt,
			const UInt32 outputLengthBytes, // these parameters optional
			const Argon2Type type,
			const UInt32 timeCost,
			const UInt32 memoryKb,
			const UInt32 lanes,
			[Out]array<Byte>^% output);
		static int ComputeEncodedHash(
			array<const Byte>^ password,
			array<const Byte>^ salt,
			const UInt32 outputLengthBytes, // these parameters optional
			const Argon2Type type,
			const UInt32 timeCost,
			const UInt32 memoryKb,
			const UInt32 lanes,
			[Out]array<Byte>^% output,
			[Out]String^% encodedOutput);
		static int ComputeHash(
			array<const Byte>^ password,
			array<const Byte>^ salt,
			const UInt32 outputLengthBytes,
			const Argon2Type type,
			array<const Byte>^ secret,
			array<const Byte>^ additionalData,
			const UInt32 timeCost,
			const UInt32 memoryKb,
			const UInt32 lanes,
			[Out]array<Byte>^% output);
		static int ComputeEncodedHash(
			array<const Byte>^ password,
			array<const Byte>^ salt,
			const UInt32 outputLengthBytes,
			const Argon2Type type,
			array<const Byte>^ secret,
			array<const Byte>^ additionalData,
			const UInt32 timeCost,
			const UInt32 memoryKb,
			const UInt32 lanes,
			[Out]array<Byte>^% output,
			[Out]String^% encodedOutput);
		static int VerifyEncodedHash(array<const Byte>^ password, const String^ encodedData);
		static int VerifyEncodedHash(
			array<const Byte>^ password, 
			array<const Byte>^ secret,
			array<const Byte>^ additionalData,
			const String^ encodedOutput);
		static String^ ErrorMessage(int errorCode)
		{
			switch (errorCode) {
			case ARGON2_OK:
				return "OK";
			case ARGON2_OUTPUT_PTR_NULL:
				return "Output pointer is NULL";
			case ARGON2_OUTPUT_TOO_SHORT:
				return "Output is too short";
			case ARGON2_OUTPUT_TOO_LONG:
				return "Output is too long";
			case ARGON2_PWD_TOO_SHORT:
				return "Password is too short";
			case ARGON2_PWD_TOO_LONG:
				return "Password is too long";
			case ARGON2_SALT_TOO_SHORT:
				return "Salt is too short";
			case ARGON2_SALT_TOO_LONG:
				return "Salt is too long";
			case ARGON2_AD_TOO_SHORT:
				return "Associated data is too short";
			case ARGON2_AD_TOO_LONG:
				return "Associated data is too long";
			case ARGON2_SECRET_TOO_SHORT:
				return "Secret is too short";
			case ARGON2_SECRET_TOO_LONG:
				return "Secret is too long";
			case ARGON2_TIME_TOO_SMALL:
				return "Time cost is too small";
			case ARGON2_TIME_TOO_LARGE:
				return "Time cost is too large";
			case ARGON2_MEMORY_TOO_LITTLE:
				return "Memory cost is too small";
			case ARGON2_MEMORY_TOO_MUCH:
				return "Memory cost is too large";
			case ARGON2_LANES_TOO_FEW:
				return "Too few lanes";
			case ARGON2_LANES_TOO_MANY:
				return "Too many lanes";
			case ARGON2_PWD_PTR_MISMATCH:
				return "Password pointer is NULL, but password length is not 0";
			case ARGON2_SALT_PTR_MISMATCH:
				return "Salt pointer is NULL, but salt length is not 0";
			case ARGON2_SECRET_PTR_MISMATCH:
				return "Secret pointer is NULL, but secret length is not 0";
			case ARGON2_AD_PTR_MISMATCH:
				return "Associated data pointer is NULL, but ad length is not 0";
			case ARGON2_MEMORY_ALLOCATION_ERROR:
				return "Memory allocation error";
			case ARGON2_FREE_MEMORY_CBK_NULL:
				return "The free memory callback is NULL";
			//case ARGON2_ALLOCATE_MEMORY_CBK_NULL:
			//	return "The allocate memory callback is NULL";
			case ARGON2_INCORRECT_PARAMETER:
				return "Argon2_Context context is NULL";
			case ARGON2_INCORRECT_TYPE:
				return "There is no such version of Argon2";
			case ARGON2_OUT_PTR_MISMATCH:
				return "Output pointer mismatch";
			case ARGON2_THREADS_TOO_FEW:
				return "Not enough threads";
			case ARGON2_THREADS_TOO_MANY:
				return "Too many threads";
			case ARGON2_MISSING_ARGS:
				return "Missing arguments";
			case ARGON2_ENCODING_FAIL:
				return "Encoding failed";
			case ARGON2_DECODING_FAIL:
				return "Decoding failed";
			case ARGON2_THREAD_FAIL:
				return "Threading failure";
			case ARGON2_DECODING_LENGTH_FAIL:
				return "Some of encoded parameters are too long or too short";
			case ARGON2_VERIFY_MISMATCH:
				return "The password does not match the supplied hash";
			default:
				return "Unknown error code";
			}
		}
	};

}
