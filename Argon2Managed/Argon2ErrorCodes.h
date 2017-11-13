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

namespace Argon2Managed
{
	/* Error codes */
	typedef enum Argon2_ErrorCodes {
		ARGON2_OK = 0,

		ARGON2_OUTPUT_PTR_NULL = -1,

		ARGON2_OUTPUT_TOO_SHORT = -2,
		ARGON2_OUTPUT_TOO_LONG = -3,

		ARGON2_PWD_TOO_SHORT = -4,
		ARGON2_PWD_TOO_LONG = -5,

		ARGON2_SALT_TOO_SHORT = -6,
		ARGON2_SALT_TOO_LONG = -7,

		ARGON2_AD_TOO_SHORT = -8,
		ARGON2_AD_TOO_LONG = -9,

		ARGON2_SECRET_TOO_SHORT = -10,
		ARGON2_SECRET_TOO_LONG = -11,

		ARGON2_TIME_TOO_SMALL = -12,
		ARGON2_TIME_TOO_LARGE = -13,

		ARGON2_MEMORY_TOO_LITTLE = -14,
		ARGON2_MEMORY_TOO_MUCH = -15,

		ARGON2_LANES_TOO_FEW = -16,
		ARGON2_LANES_TOO_MANY = -17,

		ARGON2_PWD_PTR_MISMATCH = -18,    /* NULL ptr with non-zero length */
		ARGON2_SALT_PTR_MISMATCH = -19,   /* NULL ptr with non-zero length */
		ARGON2_SECRET_PTR_MISMATCH = -20, /* NULL ptr with non-zero length */
		ARGON2_AD_PTR_MISMATCH = -21,     /* NULL ptr with non-zero length */

		ARGON2_MEMORY_ALLOCATION_ERROR = -22,

		ARGON2_FREE_MEMORY_CBK_NULL = -23,
		ARGON2_ALLOCATE_MEMORY_CBK_NULL = -24,

		ARGON2_INCORRECT_PARAMETER = -25,
		ARGON2_INCORRECT_TYPE = -26,

		ARGON2_OUT_PTR_MISMATCH = -27,

		ARGON2_THREADS_TOO_FEW = -28,
		ARGON2_THREADS_TOO_MANY = -29,

		ARGON2_MISSING_ARGS = -30,

		ARGON2_ENCODING_FAIL = -31,

		ARGON2_DECODING_FAIL = -32,

		ARGON2_THREAD_FAIL = -33,

		ARGON2_DECODING_LENGTH_FAIL = -34,

		ARGON2_VERIFY_MISMATCH = -35
	} argon2_error_codes;
}
