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

#include "config.h" /* must be first for large file support */
#include "UpdateRemove.hxx"
#include "Playlist.hxx"
#include "GlobalEvents.hxx"
#include "thread/Mutex.hxx"
#include "thread/Cond.hxx"

#include "Song.hxx"
#include "Main.hxx"
#include "Instance.hxx"

#ifdef ENABLE_SQLITE
#include "StickerDatabase.hxx"
#include "SongSticker.hxx"
#endif

#include <glib.h>

#include <assert.h>

static const Song *removed_song;

static Mutex remove_mutex;
static Cond remove_cond;

/**
 * Safely remove a song from the database.  This must be done in the
 * main task, to be sure that there is no pointer left to it.
 */
static void
song_remove_event(void)
{
	char *uri;

	assert(removed_song != NULL);

	uri = removed_song->GetURI();
	g_message("removing %s", uri);
	g_free(uri);

#ifdef ENABLE_SQLITE
	/* if the song has a sticker, remove it */
	if (sticker_enabled())
		sticker_song_delete(removed_song);
#endif

	instance->DeleteSong(*removed_song);

	/* clear "removed_song" and send signal to update thread */
	remove_mutex.lock();
	removed_song = NULL;
	remove_cond.signal();
	remove_mutex.unlock();
}

void
update_remove_global_init(void)
{
	GlobalEvents::Register(GlobalEvents::DELETE, song_remove_event);
}

void
update_remove_song(const Song *song)
{
	assert(removed_song == NULL);

	removed_song = song;

	GlobalEvents::Emit(GlobalEvents::DELETE);

	remove_mutex.lock();

	while (removed_song != NULL)
		remove_cond.wait(remove_mutex);

	remove_mutex.unlock();
}
