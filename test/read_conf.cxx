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
#include "ConfigGlobal.hxx"
#include "fs/Path.hxx"
#include "util/Error.hxx"

#include <glib.h>

#include <assert.h>

static void
my_log_func(gcc_unused const gchar *log_domain,
	    GLogLevelFlags log_level,
	    const gchar *message, gcc_unused gpointer user_data)
{
	if (log_level > G_LOG_LEVEL_WARNING)
		return;

	g_printerr("%s\n", message);
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		g_printerr("Usage: read_conf FILE SETTING\n");
		return 1;
	}

	const Path config_path = Path::FromFS(argv[1]);
	const char *name = argv[2];

	g_log_set_default_handler(my_log_func, NULL);

	config_global_init();

	Error error;
	if (!ReadConfigFile(config_path, error)) {
		g_printerr("%s:", error.GetMessage());
		return 1;
	}

	ConfigOption option = ParseConfigOptionName(name);
	const char *value = option != CONF_MAX
		? config_get_string(option, nullptr)
		: nullptr;
	int ret;
	if (value != NULL) {
		g_print("%s\n", value);
		ret = 0;
	} else {
		g_printerr("No such setting: %s\n", name);
		ret = 2;
	}

	config_global_finish();
	return ret;
}
