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
#include "DatabaseRegistry.hxx"
#include "DatabasePlugin.hxx"
#include "DatabaseSelection.hxx"
#include "Directory.hxx"
#include "Song.hxx"
#include "PlaylistVector.hxx"
#include "ConfigGlobal.hxx"
#include "ConfigData.hxx"
#include "tag/TagConfig.hxx"
#include "fs/Path.hxx"
#include "util/Error.hxx"

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <stdlib.h>

static void
my_log_func(const gchar *log_domain, gcc_unused GLogLevelFlags log_level,
	    const gchar *message, gcc_unused gpointer user_data)
{
	if (log_domain != NULL)
		g_printerr("%s: %s\n", log_domain, message);
	else
		g_printerr("%s\n", message);
}

static bool
DumpDirectory(const Directory &directory, Error &)
{
	cout << "D " << directory.path << endl;
	return true;
}

static bool
DumpSong(Song &song, Error &)
{
	cout << "S " << song.parent->path << "/" << song.uri << endl;
	return true;
}

static bool
DumpPlaylist(const PlaylistInfo &playlist,
	     const Directory &directory, Error &)
{
	cout << "P " << directory.path << "/" << playlist.name.c_str() << endl;
	return true;
}

int
main(int argc, char **argv)
{
	if (argc != 3) {
		cerr << "Usage: DumpDatabase CONFIG PLUGIN" << endl;
		return 1;
	}

	const Path config_path = Path::FromFS(argv[1]);
	const char *const plugin_name = argv[2];

	const DatabasePlugin *plugin = GetDatabasePluginByName(plugin_name);
	if (plugin == NULL) {
		cerr << "No such database plugin: " << plugin_name << endl;
		return EXIT_FAILURE;
	}

	/* initialize GLib */

#if !GLIB_CHECK_VERSION(2,32,0)
	g_thread_init(nullptr);
#endif

	g_log_set_default_handler(my_log_func, nullptr);

	/* initialize MPD */

	config_global_init();

	Error error;
	if (!ReadConfigFile(config_path, error)) {
		cerr << error.GetMessage() << endl;
		return EXIT_FAILURE;
	}

	TagLoadConfig();

	/* do it */

	const struct config_param *path = config_get_param(CONF_DB_FILE);
	config_param param("database", path->line);
	if (path != nullptr)
		param.AddBlockParam("path", path->value, path->line);

	Database *db = plugin->create(param, error);

	if (db == nullptr) {
		cerr << error.GetMessage() << endl;
		return EXIT_FAILURE;
	}

	if (!db->Open(error)) {
		delete db;
		cerr << error.GetMessage() << endl;
		return EXIT_FAILURE;
	}

	const DatabaseSelection selection("", true);

	if (!db->Visit(selection, DumpDirectory, DumpSong, DumpPlaylist,
		       error)) {
		db->Close();
		delete db;
		cerr << error.GetMessage() << endl;
		return EXIT_FAILURE;
	}

	db->Close();
	delete db;

	/* deinitialize everything */

	config_global_finish();

	return EXIT_SUCCESS;
}
