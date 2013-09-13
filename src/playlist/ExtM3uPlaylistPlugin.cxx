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
#include "ExtM3uPlaylistPlugin.hxx"
#include "PlaylistPlugin.hxx"
#include "SongEnumerator.hxx"
#include "Song.hxx"
#include "tag/Tag.hxx"
#include "util/StringUtil.hxx"
#include "TextInputStream.hxx"

#include <glib.h>

#include <string.h>
#include <stdlib.h>

class ExtM3uPlaylist final : public SongEnumerator {
	TextInputStream tis;

public:
	ExtM3uPlaylist(input_stream *is)
		:tis(is) {
	}

	bool CheckFirstLine() {
		std::string line;
		return tis.ReadLine(line) &&
			strcmp(line.c_str(), "#EXTM3U") == 0;
	}

	virtual Song *NextSong() override;
};

static SongEnumerator *
extm3u_open_stream(struct input_stream *is)
{
	ExtM3uPlaylist *playlist = new ExtM3uPlaylist(is);

	if (!playlist->CheckFirstLine()) {
		/* no EXTM3U header: fall back to the plain m3u
		   plugin */
		delete playlist;
		return NULL;
	}

	return playlist;
}

/**
 * Parse a EXTINF line.
 *
 * @param line the rest of the input line after the colon
 */
static Tag *
extm3u_parse_tag(const char *line)
{
	long duration;
	char *endptr;
	const char *name;
	Tag *tag;

	duration = strtol(line, &endptr, 10);
	if (endptr[0] != ',')
		/* malformed line */
		return NULL;

	if (duration < 0)
		/* 0 means unknown duration */
		duration = 0;

	name = strchug_fast_c(endptr + 1);
	if (*name == 0 && duration == 0)
		/* no information available; don't allocate a tag
		   object */
		return NULL;

	tag = new Tag();
	tag->time = duration;

	/* unfortunately, there is no real specification for the
	   EXTM3U format, so we must assume that the string after the
	   comma is opaque, and is just the song name*/
	if (*name != 0)
		tag->AddItem(TAG_NAME, name);

	return tag;
}

Song *
ExtM3uPlaylist::NextSong()
{
	Tag *tag = NULL;
	std::string line;
	const char *line_s;
	Song *song;

	do {
		if (!tis.ReadLine(line)) {
			delete tag;
			return NULL;
		}
		
		line_s = line.c_str();

		if (g_str_has_prefix(line_s, "#EXTINF:")) {
			delete tag;
			tag = extm3u_parse_tag(line_s + 8);
			continue;
		}

		while (*line_s != 0 && g_ascii_isspace(*line_s))
			++line_s;
	} while (line_s[0] == '#' || *line_s == 0);

	song = Song::NewRemote(line_s);
	song->tag = tag;
	return song;
}

static const char *const extm3u_suffixes[] = {
	"m3u",
	NULL
};

static const char *const extm3u_mime_types[] = {
	"audio/x-mpegurl",
	NULL
};

const struct playlist_plugin extm3u_playlist_plugin = {
	"extm3u",

	nullptr,
	nullptr,
	nullptr,
	extm3u_open_stream,

	nullptr,
	extm3u_suffixes,
	extm3u_mime_types,
};
