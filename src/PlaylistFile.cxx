/*
 * Copyright (C) 2003-2012 The Music Player Daemon Project
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
#include "PlaylistFile.hxx"
#include "PlaylistSave.hxx"
#include "PlaylistInfo.hxx"
#include "PlaylistVector.hxx"
#include "DatabasePlugin.hxx"
#include "DatabaseGlue.hxx"
#include "Song.hxx"
#include "Mapper.hxx"
#include "TextFile.hxx"
#include "ConfigGlobal.hxx"
#include "ConfigOption.hxx"
#include "ConfigDefaults.hxx"
#include "Idle.hxx"
#include "fs/Path.hxx"
#include "fs/FileSystem.hxx"
#include "fs/DirectoryReader.hxx"
#include "util/UriUtil.hxx"
#include "util/Error.hxx"

#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>

static const char PLAYLIST_COMMENT = '#';

static unsigned playlist_max_length;
bool playlist_saveAbsolutePaths = DEFAULT_PLAYLIST_SAVE_ABSOLUTE_PATHS;

void
spl_global_init(void)
{
	playlist_max_length = config_get_positive(CONF_MAX_PLAYLIST_LENGTH,
						  DEFAULT_PLAYLIST_MAX_LENGTH);

	playlist_saveAbsolutePaths =
		config_get_bool(CONF_SAVE_ABSOLUTE_PATHS,
				DEFAULT_PLAYLIST_SAVE_ABSOLUTE_PATHS);
}

bool
spl_valid_name(const char *name_utf8)
{
	/*
	 * Not supporting '/' was done out of laziness, and we should
	 * really strive to support it in the future.
	 *
	 * Not supporting '\r' and '\n' is done out of protocol
	 * limitations (and arguably laziness), but bending over head
	 * over heels to modify the protocol (and compatibility with
	 * all clients) to support idiots who put '\r' and '\n' in
	 * filenames isn't going to happen, either.
	 */

	return strchr(name_utf8, '/') == NULL &&
		strchr(name_utf8, '\n') == NULL &&
		strchr(name_utf8, '\r') == NULL;
}

static const Path &
spl_map(Error &error)
{
	const Path &path_fs = map_spl_path();
	if (path_fs.IsNull())
		error.Set(playlist_domain, PLAYLIST_RESULT_DISABLED,
			  "Stored playlists are disabled");
	return path_fs;
}

static bool
spl_check_name(const char *name_utf8, Error &error)
{
	if (!spl_valid_name(name_utf8)) {
		error.Set(playlist_domain, PLAYLIST_RESULT_BAD_NAME,
				    "Bad playlist name");
		return false;
	}

	return true;
}

static Path
spl_map_to_fs(const char *name_utf8, Error &error)
{
	if (spl_map(error).IsNull() || !spl_check_name(name_utf8, error))
		return Path::Null();

	Path path_fs = map_spl_utf8_to_fs(name_utf8);
	if (path_fs.IsNull())
		error.Set(playlist_domain, PLAYLIST_RESULT_BAD_NAME,
			  "Bad playlist name");

	return path_fs;
}

/**
 * Create an #Error for the current errno.
 */
static void
playlist_errno(Error &error)
{
	switch (errno) {
	case ENOENT:
		error.Set(playlist_domain, PLAYLIST_RESULT_NO_SUCH_LIST,
			  "No such playlist");
		break;

	default:
		error.SetErrno();
		break;
	}
}

static bool
LoadPlaylistFileInfo(PlaylistInfo &info,
		     const Path &parent_path_fs, const Path &name_fs)
{
	const char *name_fs_str = name_fs.c_str();
	size_t name_length = strlen(name_fs_str);

	if (name_length < sizeof(PLAYLIST_FILE_SUFFIX) ||
	    memchr(name_fs_str, '\n', name_length) != NULL)
		return false;

	if (!g_str_has_suffix(name_fs_str, PLAYLIST_FILE_SUFFIX))
		return false;

	Path path_fs = Path::Build(parent_path_fs, name_fs);
	struct stat st;
	if (!StatFile(path_fs, st) || !S_ISREG(st.st_mode))
		return false;

	char *name = g_strndup(name_fs_str,
			       name_length + 1 - sizeof(PLAYLIST_FILE_SUFFIX));
	std::string name_utf8 = Path::ToUTF8(name);
	g_free(name);
	if (name_utf8.empty())
		return false;

	info.name = std::move(name_utf8);
	info.mtime = st.st_mtime;
	return true;
}

PlaylistVector
ListPlaylistFiles(Error &error)
{
	PlaylistVector list;

	const Path &parent_path_fs = spl_map(error);
	if (parent_path_fs.IsNull())
		return list;

	DirectoryReader reader(parent_path_fs);
	if (reader.HasFailed()) {
		error.SetErrno();
		return list;
	}

	PlaylistInfo info;
	while (reader.ReadEntry()) {
		const Path entry = reader.GetEntry();
		if (LoadPlaylistFileInfo(info, parent_path_fs, entry))
			list.push_back(std::move(info));
	}

	return list;
}

static bool
SavePlaylistFile(const PlaylistFileContents &contents, const char *utf8path,
		 Error &error)
{
	assert(utf8path != NULL);

	if (spl_map(error).IsNull())
		return false;

	const Path path_fs = spl_map_to_fs(utf8path, error);
	if (path_fs.IsNull())
		return false;

	FILE *file = FOpen(path_fs, FOpenMode::WriteText);
	if (file == NULL) {
		playlist_errno(error);
		return false;
	}

	for (const auto &uri_utf8 : contents)
		playlist_print_uri(file, uri_utf8.c_str());

	fclose(file);
	return true;
}

PlaylistFileContents
LoadPlaylistFile(const char *utf8path, Error &error)
{
	PlaylistFileContents contents;

	if (spl_map(error).IsNull())
		return contents;

	const Path path_fs = spl_map_to_fs(utf8path, error);
	if (path_fs.IsNull())
		return contents;

	TextFile file(path_fs);
	if (file.HasFailed()) {
		playlist_errno(error);
		return contents;
	}

	char *s;
	while ((s = file.ReadLine()) != NULL) {
		if (*s == 0 || *s == PLAYLIST_COMMENT)
			continue;

		if (!uri_has_scheme(s)) {
			char *path_utf8;

			path_utf8 = map_fs_to_utf8(s);
			if (path_utf8 == NULL)
				continue;

			s = path_utf8;
		} else
			s = g_strdup(s);

		contents.emplace_back(s);
		if (contents.size() >= playlist_max_length)
			break;
	}

	return contents;
}

bool
spl_move_index(const char *utf8path, unsigned src, unsigned dest,
	       Error &error)
{
	if (src == dest)
		/* this doesn't check whether the playlist exists, but
		   what the hell.. */
		return true;

	auto contents = LoadPlaylistFile(utf8path, error);
	if (contents.empty() && error.IsDefined())
		return false;

	if (src >= contents.size() || dest >= contents.size()) {
		error.Set(playlist_domain, PLAYLIST_RESULT_BAD_RANGE,
			  "Bad range");
		return false;
	}

	const auto src_i = std::next(contents.begin(), src);
	auto value = std::move(*src_i);
	contents.erase(src_i);

	const auto dest_i = std::next(contents.begin(), dest);
	contents.insert(dest_i, std::move(value));

	bool result = SavePlaylistFile(contents, utf8path, error);

	idle_add(IDLE_STORED_PLAYLIST);
	return result;
}

bool
spl_clear(const char *utf8path, Error &error)
{
	if (spl_map(error).IsNull())
		return false;

	const Path path_fs = spl_map_to_fs(utf8path, error);
	if (path_fs.IsNull())
		return false;

	FILE *file = FOpen(path_fs, FOpenMode::WriteText);
	if (file == NULL) {
		playlist_errno(error);
		return false;
	}

	fclose(file);

	idle_add(IDLE_STORED_PLAYLIST);
	return true;
}

bool
spl_delete(const char *name_utf8, Error &error)
{
	const Path path_fs = spl_map_to_fs(name_utf8, error);
	if (path_fs.IsNull())
		return false;

	if (!RemoveFile(path_fs)) {
		playlist_errno(error);
		return false;
	}

	idle_add(IDLE_STORED_PLAYLIST);
	return true;
}

bool
spl_remove_index(const char *utf8path, unsigned pos, Error &error)
{
	auto contents = LoadPlaylistFile(utf8path, error);
	if (contents.empty() && error.IsDefined())
		return false;

	if (pos >= contents.size()) {
		error.Set(playlist_domain, PLAYLIST_RESULT_BAD_RANGE,
			  "Bad range");
		return false;
	}

	contents.erase(std::next(contents.begin(), pos));

	bool result = SavePlaylistFile(contents, utf8path, error);

	idle_add(IDLE_STORED_PLAYLIST);
	return result;
}

bool
spl_append_song(const char *utf8path, Song *song, Error &error)
{
	if (spl_map(error).IsNull())
		return false;

	const Path path_fs = spl_map_to_fs(utf8path, error);
	if (path_fs.IsNull())
		return false;

	FILE *file = FOpen(path_fs, FOpenMode::AppendText);
	if (file == NULL) {
		playlist_errno(error);
		return false;
	}

	struct stat st;
	if (fstat(fileno(file), &st) < 0) {
		playlist_errno(error);
		fclose(file);
		return false;
	}

	if (st.st_size / (MPD_PATH_MAX + 1) >= (off_t)playlist_max_length) {
		fclose(file);
		error.Set(playlist_domain, PLAYLIST_RESULT_TOO_LARGE,
			  "Stored playlist is too large");
		return false;
	}

	playlist_print_song(file, song);

	fclose(file);

	idle_add(IDLE_STORED_PLAYLIST);
	return true;
}

bool
spl_append_uri(const char *url, const char *utf8file, Error &error)
{
	if (uri_has_scheme(url)) {
		Song *song = Song::NewRemote(url);
		bool success = spl_append_song(utf8file, song, error);
		song->Free();
		return success;
	} else {
		const Database *db = GetDatabase(error);
		if (db == nullptr)
			return false;

		Song *song = db->GetSong(url, error);
		if (song == nullptr)
			return false;

		bool success = spl_append_song(utf8file, song, error);
		db->ReturnSong(song);
		return success;
	}
}

static bool
spl_rename_internal(const Path &from_path_fs, const Path &to_path_fs,
		    Error &error)
{
	if (!FileExists(from_path_fs)) {
		error.Set(playlist_domain, PLAYLIST_RESULT_NO_SUCH_LIST,
			  "No such playlist");
		return false;
	}

	if (FileExists(to_path_fs)) {
		error.Set(playlist_domain, PLAYLIST_RESULT_LIST_EXISTS,
			  "Playlist exists already");
		return false;
	}

	if (!RenameFile(from_path_fs, to_path_fs)) {
		playlist_errno(error);
		return false;
	}

	idle_add(IDLE_STORED_PLAYLIST);
	return true;
}

bool
spl_rename(const char *utf8from, const char *utf8to, Error &error)
{
	if (spl_map(error).IsNull())
		return false;

	Path from_path_fs = spl_map_to_fs(utf8from, error);
	if (from_path_fs.IsNull())
		return false;

	Path to_path_fs = spl_map_to_fs(utf8to, error);
	if (to_path_fs.IsNull())
		return false;

	return spl_rename_internal(from_path_fs, to_path_fs, error);
}
