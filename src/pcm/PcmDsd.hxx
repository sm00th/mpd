/*
 * Copyright (C) 2003-2013 The Music Player Daemon Project
 * http://www.musicpd.org
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef MPD_PCM_DSD_HXX
#define MPD_PCM_DSD_HXX

#include "check.h"
#include "PcmBuffer.hxx"

#include <stdint.h>

/**
 * Wrapper for the dsd2pcm library.
 */
struct PcmDsd {
	PcmBuffer buffer;

	struct dsd2pcm_ctx_s *dsd2pcm[32];

	PcmDsd();
	~PcmDsd();

	void Reset();

	const float *ToFloat(unsigned channels, bool lsbfirst,
			     const uint8_t *src, size_t src_size,
			     size_t *dest_size_r);
};

#endif
