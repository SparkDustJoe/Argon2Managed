#pragma once

/* Adapted from the reference code implementation
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

/*
Here we implement an abstraction layer for the simpĺe requirements
of the Argon2 code. We only require 3 primitives---thread creation,
joining, and termination---so full emulation of the pthreads API
is unwarranted. Currently we wrap pthreads and Win32 threads.

The API defines 2 types: the function pointer type,
argon2_thread_func_t,
and the type of the thread handle---argon2_thread_handle_t.
*/
#include <process.h>
typedef unsigned(__stdcall *argon2_thread_func_t)(void *);
typedef uintptr_t argon2_thread_handle_t;

/* Creates a thread
* @param handle pointer to a thread handle, which is the output of this
* function. Must not be NULL.
* @param func A function pointer for the thread's entry point. Must not be
* NULL.
* @param args Pointer that is passed as an argument to @func. May be NULL.
* @return 0 if @handle and @func are valid pointers and a thread is successfully
* created.
*/
int argon2_thread_create(argon2_thread_handle_t *handle,
	argon2_thread_func_t func, void *args) {
	if (nullptr == handle || func == nullptr) {
		return -1;
	}
	*handle = _beginthreadex(nullptr, 0, func, args, 0, nullptr);
	return *handle != 0 ? 0 : -1;
}

/* Waits for a thread to terminate
* @param handle Handle to a thread created with argon2_thread_create.
* @return 0 if @handle is a valid handle, and joining completed successfully.
*/
int argon2_thread_join(argon2_thread_handle_t handle) {
	if (WaitForSingleObject((HANDLE)handle, INFINITE) == WAIT_OBJECT_0) {
		return CloseHandle((HANDLE)handle) != 0 ? 0 : -1;
	}
	return -1;
}

/* Terminate the current thread. Must be run inside a thread created by
* argon2_thread_create.
*/
void argon2_thread_exit(void) {
	_endthreadex(0);
}
