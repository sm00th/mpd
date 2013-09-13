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

#include "config.h"
#include "DatabaseGlue.hxx"
#include "DatabaseSimple.hxx"
#include "DatabaseRegistry.hxx"
#include "DatabaseSave.hxx"
#include "DatabaseError.hxx"
#include "Directory.hxx"
#include "util/Error.hxx"
#include "ConfigData.hxx"

extern "C" {
#include "stats.h"
}

#include "DatabasePlugin.hxx"
#include "db/SimpleDatabasePlugin.hxx"

#include <glib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "database"

static Database *db;
static bool db_is_open;
static bool is_simple;

bool
DatabaseGlobalInit(const config_param &param, Error &error)
{
	assert(db == NULL);
	assert(!db_is_open);

	const char *plugin_name =
		param.GetBlockValue("plugin", "simple");
	is_simple = strcmp(plugin_name, "simple") == 0;

	const DatabasePlugin *plugin = GetDatabasePluginByName(plugin_name);
	if (plugin == NULL) {
		error.Format(db_domain,
			     "No such database plugin: %s", plugin_name);
		return false;
	}

	db = plugin->create(param, error);
	return db != NULL;
}

void
DatabaseGlobalDeinit(void)
{
	if (db_is_open)
		db->Close();

	if (db != NULL)
		delete db;
}

const Database *
GetDatabase()
{
	assert(db == NULL || db_is_open);

	return db;
}

const Database *
GetDatabase(Error &error)
{
	assert(db == nullptr || db_is_open);

	if (db == nullptr)
		error.Set(db_domain, DB_DISABLED, "No database");

	return db;
}

bool
db_is_simple(void)
{
	assert(db == NULL || db_is_open);

	return is_simple;
}

Directory *
db_get_root(void)
{
	assert(db != NULL);
	assert(db_is_simple());

	return ((SimpleDatabase *)db)->GetRoot();
}

Directory *
db_get_directory(const char *name)
{
	if (db == NULL)
		return NULL;

	Directory *music_root = db_get_root();
	if (name == NULL)
		return music_root;

	return music_root->LookupDirectory(name);
}

bool
db_save(Error &error)
{
	assert(db != NULL);
	assert(db_is_open);
	assert(db_is_simple());

	return ((SimpleDatabase *)db)->Save(error);
}

bool
DatabaseGlobalOpen(Error &error)
{
	assert(db != NULL);
	assert(!db_is_open);

	if (!db->Open(error))
		return false;

	db_is_open = true;

	stats_update();

	return true;
}

time_t
db_get_mtime(void)
{
	assert(db != NULL);
	assert(db_is_open);
	assert(db_is_simple());

	return ((SimpleDatabase *)db)->GetLastModified();
}
