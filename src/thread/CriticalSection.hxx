/*
 * Copyright (C) 2009-2013 Max Kellermann <max@duempel.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * - Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * FOUNDATION OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef MPD_THREAD_CRITICAL_SECTION_HXX
#define MPD_THREAD_CRITICAL_SECTION_HXX

#include <windows.h>

/**
 * Wrapper for a CRITICAL_SECTION, backend for the Mutex class.
 */
class CriticalSection {
	friend class WindowsCond;

	CRITICAL_SECTION critical_section;

public:
	CriticalSection() {
		::InitializeCriticalSection(&critical_section);
	}

	~CriticalSection() {
		::DeleteCriticalSection(&critical_section);
	}

	CriticalSection(const CriticalSection &other) = delete;
	CriticalSection &operator=(const CriticalSection &other) = delete;

	void lock() {
		::EnterCriticalSection(&critical_section);
	};

	bool try_lock() {
		return ::TryEnterCriticalSection(&critical_section) != 0;
	};

	void unlock() {
		::LeaveCriticalSection(&critical_section);
	}
};

#endif
