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
#include "TagFile.hxx"
#include "util/UriUtil.hxx"
#include "util/Error.hxx"
#include "DecoderList.hxx"
#include "DecoderPlugin.hxx"
#include "InputStream.hxx"

#include <assert.h>
#include <unistd.h> /* for SEEK_SET */

bool
tag_file_scan(const char *path_fs,
	      const struct tag_handler *handler, void *handler_ctx)
{
	assert(path_fs != NULL);
	assert(handler != NULL);

	/* check if there's a suffix and a plugin */

	const char *suffix = uri_get_suffix(path_fs);
	if (suffix == NULL)
		return false;

	const struct decoder_plugin *plugin =
		decoder_plugin_from_suffix(suffix, NULL);
	if (plugin == NULL)
		return false;

	struct input_stream *is = NULL;
	Mutex mutex;
	Cond cond;

	do {
		/* load file tag */
		if (decoder_plugin_scan_file(plugin, path_fs,
					     handler, handler_ctx))
			break;

		/* fall back to stream tag */
		if (plugin->scan_stream != NULL) {
			/* open the input_stream (if not already
			   open) */
			if (is == nullptr) {
				Error error;
				is = input_stream::Open(path_fs, mutex, cond,
							error);
			}

			/* now try the stream_tag() method */
			if (is != NULL) {
				if (decoder_plugin_scan_stream(plugin, is,
							       handler,
							       handler_ctx))
					break;

				is->LockSeek(0, SEEK_SET, IgnoreError());
			}
		}

		plugin = decoder_plugin_from_suffix(suffix, plugin);
	} while (plugin != NULL);

	if (is != NULL)
		is->Close();

	return plugin != NULL;
}
