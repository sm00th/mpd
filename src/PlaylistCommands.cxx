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
#include "PlaylistCommands.hxx"
#include "DatabasePlaylist.hxx"
#include "CommandError.hxx"
#include "PlaylistPrint.hxx"
#include "PlaylistSave.hxx"
#include "PlaylistFile.hxx"
#include "PlaylistVector.hxx"
#include "PlaylistQueue.hxx"
#include "TimePrint.hxx"
#include "ClientInternal.hxx"
#include "protocol/ArgParser.hxx"
#include "protocol/Result.hxx"
#include "ls.hxx"
#include "Playlist.hxx"
#include "util/UriUtil.hxx"
#include "util/Error.hxx"

#include <assert.h>
#include <stdlib.h>

static void
print_spl_list(Client *client, const PlaylistVector &list)
{
	for (const auto &i : list) {
		client_printf(client, "playlist: %s\n", i.name.c_str());

		if (i.mtime > 0)
			time_print(client, "Last-Modified", i.mtime);
	}
}

enum command_return
handle_save(Client *client, gcc_unused int argc, char *argv[])
{
	enum playlist_result result;

	result = spl_save_playlist(argv[1], &client->playlist);
	return print_playlist_result(client, result);
}

enum command_return
handle_load(Client *client, int argc, char *argv[])
{
	unsigned start_index, end_index;

	if (argc < 3) {
		start_index = 0;
		end_index = unsigned(-1);
	} else if (!check_range(client, &start_index, &end_index, argv[2]))
		return COMMAND_RETURN_ERROR;

	enum playlist_result result;

	result = playlist_open_into_queue(argv[1],
					  start_index, end_index,
					  &client->playlist,
					  client->player_control, true);
	if (result != PLAYLIST_RESULT_NO_SUCH_LIST)
		return print_playlist_result(client, result);

	Error error;
	if (playlist_load_spl(&client->playlist, client->player_control,
			      argv[1], start_index, end_index,
			      error))
		return COMMAND_RETURN_OK;

	if (error.IsDomain(playlist_domain) &&
	    error.GetCode() == PLAYLIST_RESULT_BAD_NAME) {
		/* the message for BAD_NAME is confusing when the
		   client wants to load a playlist file from the music
		   directory; patch the Error object to show "no such
		   playlist" instead */
		Error error2(playlist_domain, PLAYLIST_RESULT_NO_SUCH_LIST,
			     error.GetMessage());
		error = std::move(error2);
	}

	return print_error(client, error);
}

enum command_return
handle_listplaylist(Client *client, gcc_unused int argc, char *argv[])
{
	if (playlist_file_print(client, argv[1], false))
		return COMMAND_RETURN_OK;

	Error error;
	return spl_print(client, argv[1], false, error)
		? COMMAND_RETURN_OK
		: print_error(client, error);
}

enum command_return
handle_listplaylistinfo(Client *client,
			gcc_unused int argc, char *argv[])
{
	if (playlist_file_print(client, argv[1], true))
		return COMMAND_RETURN_OK;

	Error error;
	return spl_print(client, argv[1], true, error)
		? COMMAND_RETURN_OK
		: print_error(client, error);
}

enum command_return
handle_rm(Client *client, gcc_unused int argc, char *argv[])
{
	Error error;
	return spl_delete(argv[1], error)
		? COMMAND_RETURN_OK
		: print_error(client, error);
}

enum command_return
handle_rename(Client *client, gcc_unused int argc, char *argv[])
{
	Error error;
	return spl_rename(argv[1], argv[2], error)
		? COMMAND_RETURN_OK
		: print_error(client, error);
}

enum command_return
handle_playlistdelete(Client *client,
		      gcc_unused int argc, char *argv[]) {
	char *playlist = argv[1];
	unsigned from;

	if (!check_unsigned(client, &from, argv[2]))
		return COMMAND_RETURN_ERROR;

	Error error;
	return spl_remove_index(playlist, from, error)
		? COMMAND_RETURN_OK
		: print_error(client, error);
}

enum command_return
handle_playlistmove(Client *client, gcc_unused int argc, char *argv[])
{
	char *playlist = argv[1];
	unsigned from, to;

	if (!check_unsigned(client, &from, argv[2]))
		return COMMAND_RETURN_ERROR;
	if (!check_unsigned(client, &to, argv[3]))
		return COMMAND_RETURN_ERROR;

	Error error;
	return spl_move_index(playlist, from, to, error)
		? COMMAND_RETURN_OK
		: print_error(client, error);
}

enum command_return
handle_playlistclear(Client *client, gcc_unused int argc, char *argv[])
{
	Error error;
	return spl_clear(argv[1], error)
		? COMMAND_RETURN_OK
		: print_error(client, error);
}

enum command_return
handle_playlistadd(Client *client, gcc_unused int argc, char *argv[])
{
	char *playlist = argv[1];
	char *uri = argv[2];

	bool success;
	Error error;
	if (uri_has_scheme(uri)) {
		if (!uri_supported_scheme(uri)) {
			command_error(client, ACK_ERROR_NO_EXIST,
				      "unsupported URI scheme");
			return COMMAND_RETURN_ERROR;
		}

		success = spl_append_uri(uri, playlist, error);
	} else
		success = search_add_to_playlist(uri, playlist, nullptr,
						 error);

	if (!success && !error.IsDefined()) {
		command_error(client, ACK_ERROR_NO_EXIST,
			      "directory or file not found");
		return COMMAND_RETURN_ERROR;
	}

	return success ? COMMAND_RETURN_OK : print_error(client, error);
}

enum command_return
handle_listplaylists(Client *client,
		     gcc_unused int argc, gcc_unused char *argv[])
{
	Error error;
	const auto list = ListPlaylistFiles(error);
	if (list.empty() && error.IsDefined())
		return print_error(client, error);

	print_spl_list(client, list);
	return COMMAND_RETURN_OK;
}
