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
#include "PlaylistPrint.hxx"
#include "PlaylistFile.hxx"
#include "PlaylistAny.hxx"
#include "PlaylistSong.hxx"
#include "QueuePrint.hxx"
#include "SongPrint.hxx"
#include "DatabaseGlue.hxx"
#include "DatabasePlugin.hxx"
#include "Client.hxx"

extern "C" {
#include "playlist_list.h"
#include "playlist_plugin.h"
#include "playlist.h"
#include "song.h"
#include "input_stream.h"
}

void
playlist_print_uris(struct client *client, const struct playlist *playlist)
{
	const struct queue *queue = &playlist->queue;

	queue_print_uris(client, queue, 0, queue_length(queue));
}

bool
playlist_print_info(struct client *client, const struct playlist *playlist,
		    unsigned start, unsigned end)
{
	const struct queue *queue = &playlist->queue;

	if (end > queue_length(queue))
		/* correct the "end" offset */
		end = queue_length(queue);

	if (start > end)
		/* an invalid "start" offset is fatal */
		return false;

	queue_print_info(client, queue, start, end);
	return true;
}

bool
playlist_print_id(struct client *client, const struct playlist *playlist,
		  unsigned id)
{
	const struct queue *queue = &playlist->queue;
	int position;

	position = queue_id_to_position(queue, id);
	if (position < 0)
		/* no such song */
		return false;

	return playlist_print_info(client, playlist, position, position + 1);
}

bool
playlist_print_current(struct client *client, const struct playlist *playlist)
{
	int current_position = playlist_get_current_song(playlist);

	if (current_position < 0)
		return false;

	queue_print_info(client, &playlist->queue,
			 current_position, current_position + 1);
	return true;
}

void
playlist_print_find(struct client *client, const struct playlist *playlist,
		    const SongFilter &filter)
{
	queue_find(client, &playlist->queue, filter);
}

void
playlist_print_changes_info(struct client *client,
			    const struct playlist *playlist,
			    uint32_t version)
{
	queue_print_changes_info(client, &playlist->queue, version);
}

void
playlist_print_changes_position(struct client *client,
				const struct playlist *playlist,
				uint32_t version)
{
	queue_print_changes_position(client, &playlist->queue, version);
}

static bool
PrintSongDetails(struct client *client, const char *uri_utf8)
{
	const Database *db = GetDatabase(nullptr);
	if (db == nullptr)
		return false;

	song *song = db->GetSong(uri_utf8, nullptr);
	if (song == nullptr)
		return false;

	song_print_info(client, song);
	db->ReturnSong(song);
	return true;
}

bool
spl_print(struct client *client, const char *name_utf8, bool detail,
	  GError **error_r)
{
	GError *error = NULL;
	PlaylistFileContents contents = LoadPlaylistFile(name_utf8, &error);
	if (contents.empty() && error != nullptr) {
		g_propagate_error(error_r, error);
		return false;
	}

	for (const auto &uri_utf8 : contents) {
		if (!detail || !PrintSongDetails(client, uri_utf8.c_str()))
			client_printf(client, SONG_FILE "%s\n",
				      uri_utf8.c_str());
	}

	return true;
}

static void
playlist_provider_print(struct client *client, const char *uri,
			struct playlist_provider *playlist, bool detail)
{
	struct song *song;
	char *base_uri = uri != NULL ? g_path_get_dirname(uri) : NULL;

	while ((song = playlist_plugin_read(playlist)) != NULL) {
		song = playlist_check_translate_song(song, base_uri, false);
		if (song == NULL)
			continue;

		if (detail)
			song_print_info(client, song);
		else
			song_print_uri(client, song);

		song_free(song);
	}

	g_free(base_uri);
}

bool
playlist_file_print(struct client *client, const char *uri, bool detail)
{
	GMutex *mutex = g_mutex_new();
	GCond *cond = g_cond_new();

	struct input_stream *is;
	struct playlist_provider *playlist =
		playlist_open_any(uri, mutex, cond, &is);
	if (playlist == NULL) {
		g_cond_free(cond);
		g_mutex_free(mutex);
		return false;
	}

	playlist_provider_print(client, uri, playlist, detail);
	playlist_plugin_close(playlist);

	if (is != NULL)
		input_stream_close(is);

	g_cond_free(cond);
	g_mutex_free(mutex);

	return true;
}
