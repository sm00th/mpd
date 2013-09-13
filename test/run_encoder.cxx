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
#include "EncoderList.hxx"
#include "EncoderPlugin.hxx"
#include "AudioFormat.hxx"
#include "AudioParser.hxx"
#include "ConfigData.hxx"
#include "util/Error.hxx"
#include "stdbin.h"

#include <glib.h>

#include <stddef.h>
#include <unistd.h>

static void
encoder_to_stdout(Encoder &encoder)
{
	size_t length;
	static char buffer[32768];

	while ((length = encoder_read(&encoder, buffer, sizeof(buffer))) > 0) {
		gcc_unused ssize_t ignored = write(1, buffer, length);
	}
}

int main(int argc, char **argv)
{
	const char *encoder_name;
	static char buffer[32768];

	/* parse command line */

	if (argc > 3) {
		g_printerr("Usage: run_encoder [ENCODER] [FORMAT] <IN >OUT\n");
		return 1;
	}

	if (argc > 1)
		encoder_name = argv[1];
	else
		encoder_name = "vorbis";

	/* create the encoder */

	const auto plugin = encoder_plugin_get(encoder_name);
	if (plugin == NULL) {
		g_printerr("No such encoder: %s\n", encoder_name);
		return 1;
	}

	config_param param;
	param.AddBlockParam("quality", "5.0", -1);

	Error error;
	const auto encoder = encoder_init(*plugin, param, error);
	if (encoder == NULL) {
		g_printerr("Failed to initialize encoder: %s\n",
			   error.GetMessage());
		return 1;
	}

	/* open the encoder */

	AudioFormat audio_format(44100, SampleFormat::S16, 2);
	if (argc > 2) {
		if (!audio_format_parse(audio_format, argv[2], false, error)) {
			g_printerr("Failed to parse audio format: %s\n",
				   error.GetMessage());
			return 1;
		}
	}

	if (!encoder_open(encoder, audio_format, error)) {
		g_printerr("Failed to open encoder: %s\n",
			   error.GetMessage());
		return 1;
	}

	encoder_to_stdout(*encoder);

	/* do it */

	ssize_t nbytes;
	while ((nbytes = read(0, buffer, sizeof(buffer))) > 0) {
		if (!encoder_write(encoder, buffer, nbytes, error)) {
			g_printerr("encoder_write() failed: %s\n",
				   error.GetMessage());
			return 1;
		}

		encoder_to_stdout(*encoder);
	}

	if (!encoder_end(encoder, error)) {
		g_printerr("encoder_flush() failed: %s\n",
			   error.GetMessage());
		return 1;
	}

	encoder_to_stdout(*encoder);
}
