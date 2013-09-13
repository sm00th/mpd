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

/*
 * Saving and loading the playlist to/from the state file.
 *
 */

#include "config.h"
#include "PlaylistState.hxx"
#include "Playlist.hxx"
#include "QueueSave.hxx"
#include "TextFile.hxx"
#include "PlayerControl.hxx"
#include "ConfigGlobal.hxx"
#include "ConfigOption.hxx"

#include <string.h>
#include <stdlib.h>

#define PLAYLIST_STATE_FILE_STATE		"state: "
#define PLAYLIST_STATE_FILE_RANDOM		"random: "
#define PLAYLIST_STATE_FILE_REPEAT		"repeat: "
#define PLAYLIST_STATE_FILE_SINGLE		"single: "
#define PLAYLIST_STATE_FILE_CONSUME		"consume: "
#define PLAYLIST_STATE_FILE_CURRENT		"current: "
#define PLAYLIST_STATE_FILE_TIME		"time: "
#define PLAYLIST_STATE_FILE_CROSSFADE		"crossfade: "
#define PLAYLIST_STATE_FILE_MIXRAMPDB		"mixrampdb: "
#define PLAYLIST_STATE_FILE_MIXRAMPDELAY	"mixrampdelay: "
#define PLAYLIST_STATE_FILE_PLAYLIST_BEGIN	"playlist_begin"
#define PLAYLIST_STATE_FILE_PLAYLIST_END	"playlist_end"

#define PLAYLIST_STATE_FILE_STATE_PLAY		"play"
#define PLAYLIST_STATE_FILE_STATE_PAUSE		"pause"
#define PLAYLIST_STATE_FILE_STATE_STOP		"stop"

#define PLAYLIST_BUFFER_SIZE	2*MPD_PATH_MAX

void
playlist_state_save(FILE *fp, const struct playlist *playlist,
		    struct player_control *pc)
{
	const auto player_status = pc->GetStatus();

	fputs(PLAYLIST_STATE_FILE_STATE, fp);

	if (playlist->playing) {
		switch (player_status.state) {
		case PLAYER_STATE_PAUSE:
			fputs(PLAYLIST_STATE_FILE_STATE_PAUSE "\n", fp);
			break;
		default:
			fputs(PLAYLIST_STATE_FILE_STATE_PLAY "\n", fp);
		}
		fprintf(fp, PLAYLIST_STATE_FILE_CURRENT "%i\n",
			playlist->queue.OrderToPosition(playlist->current));
		fprintf(fp, PLAYLIST_STATE_FILE_TIME "%i\n",
			(int)player_status.elapsed_time);
	} else {
		fputs(PLAYLIST_STATE_FILE_STATE_STOP "\n", fp);

		if (playlist->current >= 0)
			fprintf(fp, PLAYLIST_STATE_FILE_CURRENT "%i\n",
				playlist->queue.OrderToPosition(playlist->current));
	}

	fprintf(fp, PLAYLIST_STATE_FILE_RANDOM "%i\n", playlist->queue.random);
	fprintf(fp, PLAYLIST_STATE_FILE_REPEAT "%i\n", playlist->queue.repeat);
	fprintf(fp, PLAYLIST_STATE_FILE_SINGLE "%i\n", playlist->queue.single);
	fprintf(fp, PLAYLIST_STATE_FILE_CONSUME "%i\n",
		playlist->queue.consume);
	fprintf(fp, PLAYLIST_STATE_FILE_CROSSFADE "%i\n",
		(int)pc->GetCrossFade());
	fprintf(fp, PLAYLIST_STATE_FILE_MIXRAMPDB "%f\n",
		pc->GetMixRampDb());
	fprintf(fp, PLAYLIST_STATE_FILE_MIXRAMPDELAY "%f\n",
		pc->GetMixRampDelay());
	fputs(PLAYLIST_STATE_FILE_PLAYLIST_BEGIN "\n", fp);
	queue_save(fp, &playlist->queue);
	fputs(PLAYLIST_STATE_FILE_PLAYLIST_END "\n", fp);
}

static void
playlist_state_load(TextFile &file, struct playlist *playlist)
{
	const char *line = file.ReadLine();
	if (line == NULL) {
		g_warning("No playlist in state file");
		return;
	}

	while (!g_str_has_prefix(line, PLAYLIST_STATE_FILE_PLAYLIST_END)) {
		queue_load_song(file, line, &playlist->queue);

		line = file.ReadLine();
		if (line == NULL) {
			g_warning("'" PLAYLIST_STATE_FILE_PLAYLIST_END
				  "' not found in state file");
			break;
		}
	}

	playlist->queue.IncrementVersion();
}

bool
playlist_state_restore(const char *line, TextFile &file,
		       struct playlist *playlist, struct player_control *pc)
{
	int current = -1;
	int seek_time = 0;
	enum player_state state = PLAYER_STATE_STOP;
	bool random_mode = false;

	if (!g_str_has_prefix(line, PLAYLIST_STATE_FILE_STATE))
		return false;

	line += sizeof(PLAYLIST_STATE_FILE_STATE) - 1;

	if (strcmp(line, PLAYLIST_STATE_FILE_STATE_PLAY) == 0)
		state = PLAYER_STATE_PLAY;
	else if (strcmp(line, PLAYLIST_STATE_FILE_STATE_PAUSE) == 0)
		state = PLAYER_STATE_PAUSE;

	while ((line = file.ReadLine()) != NULL) {
		if (g_str_has_prefix(line, PLAYLIST_STATE_FILE_TIME)) {
			seek_time =
			    atoi(&(line[strlen(PLAYLIST_STATE_FILE_TIME)]));
		} else if (g_str_has_prefix(line, PLAYLIST_STATE_FILE_REPEAT)) {
			playlist->SetRepeat(*pc,
					    strcmp(&(line[strlen(PLAYLIST_STATE_FILE_REPEAT)]),
						   "1") == 0);
		} else if (g_str_has_prefix(line, PLAYLIST_STATE_FILE_SINGLE)) {
			playlist->SetSingle(*pc,
					    strcmp(&(line[strlen(PLAYLIST_STATE_FILE_SINGLE)]),
						   "1") == 0);
		} else if (g_str_has_prefix(line, PLAYLIST_STATE_FILE_CONSUME)) {
			playlist->SetConsume(strcmp(&(line[strlen(PLAYLIST_STATE_FILE_CONSUME)]),
						    "1") == 0);
		} else if (g_str_has_prefix(line, PLAYLIST_STATE_FILE_CROSSFADE)) {
			pc->SetCrossFade(atoi(line + strlen(PLAYLIST_STATE_FILE_CROSSFADE)));
		} else if (g_str_has_prefix(line, PLAYLIST_STATE_FILE_MIXRAMPDB)) {
			pc->SetMixRampDb(atof(line + strlen(PLAYLIST_STATE_FILE_MIXRAMPDB)));
		} else if (g_str_has_prefix(line, PLAYLIST_STATE_FILE_MIXRAMPDELAY)) {
			pc->SetMixRampDelay(atof(line + strlen(PLAYLIST_STATE_FILE_MIXRAMPDELAY)));
		} else if (g_str_has_prefix(line, PLAYLIST_STATE_FILE_RANDOM)) {
			random_mode =
				strcmp(line + strlen(PLAYLIST_STATE_FILE_RANDOM),
				       "1") == 0;
		} else if (g_str_has_prefix(line, PLAYLIST_STATE_FILE_CURRENT)) {
			current = atoi(&(line
					 [strlen
					  (PLAYLIST_STATE_FILE_CURRENT)]));
		} else if (g_str_has_prefix(line,
					    PLAYLIST_STATE_FILE_PLAYLIST_BEGIN)) {
			playlist_state_load(file, playlist);
		}
	}

	playlist->SetRandom(*pc, random_mode);

	if (!playlist->queue.IsEmpty()) {
		if (!playlist->queue.IsValidPosition(current))
			current = 0;

		if (state == PLAYER_STATE_PLAY &&
		    config_get_bool(CONF_RESTORE_PAUSED, false))
			/* the user doesn't want MPD to auto-start
			   playback after startup; fall back to
			   "pause" */
			state = PLAYER_STATE_PAUSE;

		/* enable all devices for the first time; this must be
		   called here, after the audio output states were
		   restored, before playback begins */
		if (state != PLAYER_STATE_STOP)
			pc->UpdateAudio();

		if (state == PLAYER_STATE_STOP /* && config_option */)
			playlist->current = current;
		else if (seek_time == 0)
			playlist->PlayPosition(*pc, current);
		else
			playlist->SeekSongPosition(*pc, current, seek_time);

		if (state == PLAYER_STATE_PAUSE)
			pc->Pause();
	}

	return true;
}

unsigned
playlist_state_get_hash(const struct playlist *playlist,
			struct player_control *pc)
{
	const auto player_status = pc->GetStatus();

	return playlist->queue.version ^
		(player_status.state != PLAYER_STATE_STOP
		 ? ((int)player_status.elapsed_time << 8)
		 : 0) ^
		(playlist->current >= 0
		 ? (playlist->queue.OrderToPosition(playlist->current) << 16)
		 : 0) ^
		((int)pc->GetCrossFade() << 20) ^
		(player_status.state << 24) ^
		(playlist->queue.random << 27) ^
		(playlist->queue.repeat << 28) ^
		(playlist->queue.single << 29) ^
		(playlist->queue.consume << 30) ^
		(playlist->queue.random << 31);
}
