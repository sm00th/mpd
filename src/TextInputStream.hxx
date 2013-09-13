/*
 * Copyright (C) 2003-2011 The Music Player Daemon Project
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

#ifndef MPD_TEXT_INPUT_STREAM_HXX
#define MPD_TEXT_INPUT_STREAM_HXX

#include <string>

struct input_stream;
struct fifo_buffer;

class TextInputStream {
	struct input_stream *is;
	struct fifo_buffer *buffer;
public:
	/**
	 * Wraps an existing #input_stream object into a #TextInputStream,
	 * to read its contents as text lines.
	 *
	 * @param _is an open #input_stream object
	 */
	explicit TextInputStream(struct input_stream *_is);

	/**
	 * Frees the #TextInputStream object.  Does not close or free the
	 * underlying #input_stream.
	 */
	~TextInputStream();

	TextInputStream(const TextInputStream &) = delete;
	TextInputStream& operator=(const TextInputStream &) = delete;

	/**
	 * Reads the next line from the stream with newline character stripped.
	 *
	 * @param line a string to put result to
	 * @return true if line is read successfully, false on end of file
	 * or error
	 */
	bool ReadLine(std::string &line);
};

#endif
