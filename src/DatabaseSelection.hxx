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

#ifndef MPD_DATABASE_SELECTION_HXX
#define MPD_DATABASE_SELECTION_HXX

#include "gcc.h"

#include <assert.h>
#include <stddef.h>

class SongFilter;
struct Song;

struct DatabaseSelection {
	/**
	 * The base URI of the search (UTF-8).  Must not begin or end
	 * with a slash.  NULL or an empty string searches the whole
	 * database.
	 */
	const char *uri;

	/**
	 * Recursively search all sub directories?
	 */
	bool recursive;

	const SongFilter *filter;

	DatabaseSelection(const char *_uri, bool _recursive,
			  const SongFilter *_filter=nullptr)
		:uri(_uri), recursive(_recursive), filter(_filter) {
		assert(uri != NULL);
	}

	gcc_pure
	bool Match(const Song &song) const;
};

#endif
