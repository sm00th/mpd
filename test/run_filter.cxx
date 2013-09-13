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
#include "ConfigData.hxx"
#include "ConfigGlobal.hxx"
#include "fs/Path.hxx"
#include "AudioParser.hxx"
#include "AudioFormat.hxx"
#include "FilterPlugin.hxx"
#include "FilterInternal.hxx"
#include "pcm/PcmVolume.hxx"
#include "MixerControl.hxx"
#include "stdbin.h"
#include "util/Error.hxx"
#include "system/FatalError.hxx"

#include <glib.h>

#include <assert.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

bool
mixer_set_volume(gcc_unused Mixer *mixer,
		 gcc_unused unsigned volume, gcc_unused Error &error)
{
	return true;
}

static void
my_log_func(const gchar *log_domain, gcc_unused GLogLevelFlags log_level,
	    const gchar *message, gcc_unused gpointer user_data)
{
	if (log_domain != NULL)
		g_printerr("%s: %s\n", log_domain, message);
	else
		g_printerr("%s\n", message);
}

static const struct config_param *
find_named_config_block(ConfigOption option, const char *name)
{
	const struct config_param *param = NULL;

	while ((param = config_get_next_param(option, param)) != NULL) {
		const char *current_name = param->GetBlockValue("name");
		if (current_name != NULL && strcmp(current_name, name) == 0)
			return param;
	}

	return NULL;
}

static Filter *
load_filter(const char *name)
{
	const struct config_param *param;

	param = find_named_config_block(CONF_AUDIO_FILTER, name);
	if (param == NULL) {
		g_printerr("No such configured filter: %s\n", name);
		return nullptr;
	}

	Error error;
	Filter *filter = filter_configured_new(*param, error);
	if (filter == NULL) {
		g_printerr("Failed to load filter: %s\n", error.GetMessage());
		return NULL;
	}

	return filter;
}

int main(int argc, char **argv)
{
	struct audio_format_string af_string;
	Error error2;
	char buffer[4096];

	if (argc < 3 || argc > 4) {
		g_printerr("Usage: run_filter CONFIG NAME [FORMAT] <IN\n");
		return 1;
	}

	const Path config_path = Path::FromFS(argv[1]);

	AudioFormat audio_format(44100, SampleFormat::S16, 2);

	/* initialize GLib */

#if !GLIB_CHECK_VERSION(2,32,0)
	g_thread_init(NULL);
#endif

	g_log_set_default_handler(my_log_func, NULL);

	/* read configuration file (mpd.conf) */

	config_global_init();
	if (!ReadConfigFile(config_path, error2))
		FatalError(error2);

	/* parse the audio format */

	if (argc > 3) {
		Error error;
		if (!audio_format_parse(audio_format, argv[3], false, error)) {
			g_printerr("Failed to parse audio format: %s\n",
				   error.GetMessage());
			return 1;
		}
	}

	/* initialize the filter */

	Filter *filter = load_filter(argv[2]);
	if (filter == NULL)
		return 1;

	/* open the filter */

	Error error;
	const AudioFormat out_audio_format = filter->Open(audio_format, error);
	if (!out_audio_format.IsDefined()) {
		g_printerr("Failed to open filter: %s\n", error.GetMessage());
		delete filter;
		return 1;
	}

	g_printerr("audio_format=%s\n",
		   audio_format_to_string(out_audio_format, &af_string));

	/* play */

	while (true) {
		ssize_t nbytes;
		size_t length;
		const void *dest;

		nbytes = read(0, buffer, sizeof(buffer));
		if (nbytes <= 0)
			break;

		dest = filter->FilterPCM(buffer, (size_t)nbytes,
					 &length, error);
		if (dest == NULL) {
			g_printerr("Filter failed: %s\n", error.GetMessage());
			filter->Close();
			delete filter;
			return 1;
		}

		nbytes = write(1, dest, length);
		if (nbytes < 0) {
			g_printerr("Failed to write: %s\n", g_strerror(errno));
			filter->Close();
			delete filter;
			return 1;
		}
	}

	/* cleanup and exit */

	filter->Close();
	delete filter;

	config_global_finish();

	return 0;
}
