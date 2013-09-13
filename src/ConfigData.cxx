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
#include "ConfigParser.hxx"
#include "ConfigPath.hxx"
#include "util/Error.hxx"
#include "fs/Path.hxx"
#include "system/FatalError.hxx"

#include <glib.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>

unsigned
block_param::GetUnsignedValue() const
{
	char *endptr;
	long value2 = strtol(value.c_str(), &endptr, 0);
	if (*endptr != 0)
		FormatFatalError("Not a valid number in line %i", line);

	if (value2 < 0)
		FormatFatalError("Not a positive number in line %i", line);

	return (unsigned)value2;
}

bool
block_param::GetBoolValue() const
{
	bool value2;
	if (!get_bool(value.c_str(), &value2))
		FormatFatalError("%s is not a boolean value (yes, true, 1) or "
				 "(no, false, 0) on line %i\n",
				 name.c_str(), line);

	return value2;
}

config_param::config_param(const char *_value, int _line)
	:next(nullptr), value(g_strdup(_value)), line(_line) {}

config_param::~config_param()
{
	delete next;
	g_free(value);
}

const block_param *
config_param::GetBlockParam(const char *name) const
{
	for (const auto &i : block_params) {
		if (i.name == name) {
			i.used = true;
			return &i;
		}
	}

	return NULL;
}

const char *
config_param::GetBlockValue(const char *name, const char *default_value) const
{
	const block_param *bp = GetBlockParam(name);
	if (bp == nullptr)
		return default_value;

	return bp->value.c_str();
}

char *
config_param::DupBlockString(const char *name, const char *default_value) const
{
	return g_strdup(GetBlockValue(name, default_value));
}

Path
config_param::GetBlockPath(const char *name, const char *default_value,
			   Error &error) const
{
	assert(!error.IsDefined());

	int line2 = line;
	const char *s;

	const block_param *bp = GetBlockParam(name);
	if (bp != nullptr) {
		line2 = bp->line;
		s = bp->value.c_str();
	} else
		s = default_value;

	Path path = ParsePath(s, error);
	if (gcc_unlikely(path.IsNull()))
		error.FormatPrefix("Invalid path in \"%s\" at line %i: ",
				   name, line2);

	return path;
}

Path
config_param::GetBlockPath(const char *name, Error &error) const
{
	return GetBlockPath(name, nullptr, error);
}

unsigned
config_param::GetBlockValue(const char *name, unsigned default_value) const
{
	const block_param *bp = GetBlockParam(name);
	if (bp == nullptr)
		return default_value;

	return bp->GetUnsignedValue();
}

gcc_pure
bool
config_param::GetBlockValue(const char *name, bool default_value) const
{
	const block_param *bp = GetBlockParam(name);
	if (bp == NULL)
		return default_value;

	return bp->GetBoolValue();
}
