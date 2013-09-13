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

#include "config.h" /* must be first for large file support */
#include "UpdateSong.hxx"
#include "UpdateInternal.hxx"
#include "UpdateIO.hxx"
#include "UpdateDatabase.hxx"
#include "UpdateContainer.hxx"
#include "DatabaseLock.hxx"
#include "Directory.hxx"
#include "Song.hxx"
#include "DecoderPlugin.hxx"
#include "DecoderList.hxx"

#include <glib.h>

#include <unistd.h>

static void
update_song_file2(Directory *directory,
		  const char *name, const struct stat *st,
		  const struct decoder_plugin *plugin)
{
	db_lock();
	Song *song = directory->FindSong(name);
	db_unlock();

	if (!directory_child_access(directory, name, R_OK)) {
		g_warning("no read permissions on %s/%s",
			  directory->GetPath(), name);
		if (song != NULL) {
			db_lock();
			delete_song(directory, song);
			db_unlock();
		}

		return;
	}

	if (!(song != NULL && st->st_mtime == song->mtime &&
	      !walk_discard) &&
	    update_container_file(directory, name, st, plugin)) {
		if (song != NULL) {
			db_lock();
			delete_song(directory, song);
			db_unlock();
		}

		return;
	}

	if (song == NULL) {
		g_debug("reading %s/%s", directory->GetPath(), name);
		song = Song::LoadFile(name, directory);
		if (song == NULL) {
			g_debug("ignoring unrecognized file %s/%s",
				directory->GetPath(), name);
			return;
		}

		db_lock();
		directory->AddSong(song);
		db_unlock();

		modified = true;
		g_message("added %s/%s",
			  directory->GetPath(), name);
	} else if (st->st_mtime != song->mtime || walk_discard) {
		g_message("updating %s/%s",
			  directory->GetPath(), name);
		if (!song->UpdateFile()) {
			g_debug("deleting unrecognized file %s/%s",
				directory->GetPath(), name);
			db_lock();
			delete_song(directory, song);
			db_unlock();
		}

		modified = true;
	}
}

bool
update_song_file(Directory *directory,
		 const char *name, const char *suffix,
		 const struct stat *st)
{
	const struct decoder_plugin *plugin =
		decoder_plugin_from_suffix(suffix, nullptr);
	if (plugin == NULL)
		return false;

	update_song_file2(directory, name, st, plugin);
	return true;
}
