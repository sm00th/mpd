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

#include "config.h"
#include "PcmChannels.hxx"
#include "PcmBuffer.hxx"
#include "PcmUtils.hxx"

#include <assert.h>

template<typename D, typename S>
static void
MonoToStereo(D dest, S src, S end)
{
	while (src != end) {
		const auto value = *src++;

		*dest++ = value;
		*dest++ = value;
	}

}

static void
pcm_convert_channels_16_2_to_1(int16_t *restrict dest,
			       const int16_t *restrict src,
			       const int16_t *restrict src_end)
{
	while (src < src_end) {
		int32_t a = *src++, b = *src++;

		*dest++ = (a + b) / 2;
	}
}

static void
pcm_convert_channels_16_n_to_2(int16_t *restrict dest,
			       unsigned src_channels,
			       const int16_t *restrict src,
			       const int16_t *restrict src_end)
{
	unsigned c;

	assert(src_channels > 0);

	while (src < src_end) {
		int32_t sum = 0;
		int16_t value;

		for (c = 0; c < src_channels; ++c)
			sum += *src++;
		value = sum / (int)src_channels;

		/* XXX this is actually only mono ... */
		*dest++ = value;
		*dest++ = value;
	}
}

const int16_t *
pcm_convert_channels_16(PcmBuffer &buffer,
			unsigned dest_channels,
			unsigned src_channels, const int16_t *src,
			size_t src_size, size_t *dest_size_r)
{
	assert(src_size % (sizeof(*src) * src_channels) == 0);

	size_t dest_size = src_size / src_channels * dest_channels;
	*dest_size_r = dest_size;

	int16_t *dest = (int16_t *)buffer.Get(dest_size);
	const int16_t *src_end = pcm_end_pointer(src, src_size);

	if (src_channels == 1 && dest_channels == 2)
		MonoToStereo(dest, src, src_end);
	else if (src_channels == 2 && dest_channels == 1)
		pcm_convert_channels_16_2_to_1(dest, src, src_end);
	else if (dest_channels == 2)
		pcm_convert_channels_16_n_to_2(dest, src_channels, src,
					       src_end);
	else
		return NULL;

	return dest;
}

static void
pcm_convert_channels_24_2_to_1(int32_t *restrict dest,
			       const int32_t *restrict src,
			       const int32_t *restrict src_end)
{
	while (src < src_end) {
		int32_t a = *src++, b = *src++;

		*dest++ = (a + b) / 2;
	}
}

static void
pcm_convert_channels_24_n_to_2(int32_t *restrict dest,
			       unsigned src_channels,
			       const int32_t *restrict src,
			       const int32_t *restrict src_end)
{
	unsigned c;

	assert(src_channels > 0);

	while (src < src_end) {
		int32_t sum = 0;
		int32_t value;

		for (c = 0; c < src_channels; ++c)
			sum += *src++;
		value = sum / (int)src_channels;

		/* XXX this is actually only mono ... */
		*dest++ = value;
		*dest++ = value;
	}
}

const int32_t *
pcm_convert_channels_24(PcmBuffer &buffer,
			unsigned dest_channels,
			unsigned src_channels, const int32_t *src,
			size_t src_size, size_t *dest_size_r)
{
	assert(src_size % (sizeof(*src) * src_channels) == 0);

	size_t dest_size = src_size / src_channels * dest_channels;
	*dest_size_r = dest_size;

	int32_t *dest = (int32_t *)buffer.Get(dest_size);
	const int32_t *src_end = (const int32_t *)
		pcm_end_pointer(src, src_size);

	if (src_channels == 1 && dest_channels == 2)
		MonoToStereo(dest, src, src_end);
	else if (src_channels == 2 && dest_channels == 1)
		pcm_convert_channels_24_2_to_1(dest, src, src_end);
	else if (dest_channels == 2)
		pcm_convert_channels_24_n_to_2(dest, src_channels, src,
					       src_end);
	else
		return NULL;

	return dest;
}

static void
pcm_convert_channels_32_2_to_1(int32_t *restrict dest,
			       const int32_t *restrict src,
			       const int32_t *restrict src_end)
{
	while (src < src_end) {
		int64_t a = *src++, b = *src++;

		*dest++ = (a + b) / 2;
	}
}

static void
pcm_convert_channels_32_n_to_2(int32_t *dest,
			       unsigned src_channels, const int32_t *src,
			       const int32_t *src_end)
{
	unsigned c;

	assert(src_channels > 0);

	while (src < src_end) {
		int64_t sum = 0;
		int32_t value;

		for (c = 0; c < src_channels; ++c)
			sum += *src++;
		value = sum / (int64_t)src_channels;

		/* XXX this is actually only mono ... */
		*dest++ = value;
		*dest++ = value;
	}
}

const int32_t *
pcm_convert_channels_32(PcmBuffer &buffer,
			unsigned dest_channels,
			unsigned src_channels, const int32_t *src,
			size_t src_size, size_t *dest_size_r)
{
	assert(src_size % (sizeof(*src) * src_channels) == 0);

	size_t dest_size = src_size / src_channels * dest_channels;
	*dest_size_r = dest_size;

	int32_t *dest = (int32_t *)buffer.Get(dest_size);
	const int32_t *src_end = (const int32_t *)
		pcm_end_pointer(src, src_size);

	if (src_channels == 1 && dest_channels == 2)
		MonoToStereo(dest, src, src_end);
	else if (src_channels == 2 && dest_channels == 1)
		pcm_convert_channels_32_2_to_1(dest, src, src_end);
	else if (dest_channels == 2)
		pcm_convert_channels_32_n_to_2(dest, src_channels, src,
					       src_end);
	else
		return NULL;

	return dest;
}

static void
pcm_convert_channels_float_2_to_1(float *restrict dest,
				  const float *restrict src,
				  const float *restrict src_end)
{
	while (src < src_end) {
		double a = *src++, b = *src++;

		*dest++ = (a + b) / 2;
	}
}

static void
pcm_convert_channels_float_n_to_2(float *dest,
				  unsigned src_channels, const float *src,
				  const float *src_end)
{
	unsigned c;

	assert(src_channels > 0);

	while (src < src_end) {
		double sum = 0;
		float value;

		for (c = 0; c < src_channels; ++c)
			sum += *src++;
		value = sum / (double)src_channels;

		/* XXX this is actually only mono ... */
		*dest++ = value;
		*dest++ = value;
	}
}

const float *
pcm_convert_channels_float(PcmBuffer &buffer,
			   unsigned dest_channels,
			   unsigned src_channels, const float *src,
			   size_t src_size, size_t *dest_size_r)
{
	assert(src_size % (sizeof(*src) * src_channels) == 0);

	size_t dest_size = src_size / src_channels * dest_channels;
	*dest_size_r = dest_size;

	float *dest = (float *)buffer.Get(dest_size);
	const float *src_end = (const float *)pcm_end_pointer(src, src_size);

	if (src_channels == 1 && dest_channels == 2)
		MonoToStereo(dest, src, src_end);
	else if (src_channels == 2 && dest_channels == 1)
		pcm_convert_channels_float_2_to_1(dest, src, src_end);
	else if (dest_channels == 2)
		pcm_convert_channels_float_n_to_2(dest, src_channels, src,
						  src_end);
	else
		return NULL;

	return dest;
}
