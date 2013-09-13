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
#include "PlaylistMapper.hxx"
#include "PlaylistFile.hxx"
#include "PlaylistRegistry.hxx"
#include "Mapper.hxx"
#include "fs/Path.hxx"
#include "util/UriUtil.hxx"

#include <assert.h>

static SongEnumerator *
playlist_open_path(const char *path_fs, Mutex &mutex, Cond &cond,
		   struct input_stream **is_r)
{
	auto playlist = playlist_list_open_uri(path_fs, mutex, cond);
	if (playlist != NULL)
		*is_r = NULL;
	else
		playlist = playlist_list_open_path(path_fs, mutex, cond, is_r);

	return playlist;
}

/**
 * Load a playlist from the configured playlist directory.
 */
static SongEnumerator *
playlist_open_in_playlist_dir(const char *uri, Mutex &mutex, Cond &cond,
			      struct input_stream **is_r)
{
	char *path_fs;

	assert(spl_valid_name(uri));

	const Path &playlist_directory_fs = map_spl_path();
	if (playlist_directory_fs.IsNull())
		return NULL;

	path_fs = g_build_filename(playlist_directory_fs.c_str(), uri, NULL);

	auto playlist = playlist_open_path(path_fs, mutex, cond, is_r);
	g_free(path_fs);

	return playlist;
}

/**
 * Load a playlist from the configured music directory.
 */
static SongEnumerator *
playlist_open_in_music_dir(const char *uri, Mutex &mutex, Cond &cond,
			   struct input_stream **is_r)
{
	assert(uri_safe_local(uri));

	Path path = map_uri_fs(uri);
	if (path.IsNull())
		return NULL;

	return playlist_open_path(path.c_str(), mutex, cond, is_r);
}

SongEnumerator *
playlist_mapper_open(const char *uri, Mutex &mutex, Cond &cond,
		     struct input_stream **is_r)
{
	if (spl_valid_name(uri)) {
		auto playlist = playlist_open_in_playlist_dir(uri, mutex, cond,
							      is_r);
		if (playlist != NULL)
			return playlist;
	}

	if (uri_safe_local(uri)) {
		auto playlist = playlist_open_in_music_dir(uri, mutex, cond,
							   is_r);
		if (playlist != NULL)
			return playlist;
	}

	return NULL;
}
