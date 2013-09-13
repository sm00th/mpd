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

#include "UriUtil.hxx"

#include <glib.h>

#include <assert.h>
#include <string.h>

bool uri_has_scheme(const char *uri)
{
	return strstr(uri, "://") != nullptr;
}

/* suffixes should be ascii only characters */
const char *
uri_get_suffix(const char *uri)
{
	const char *suffix = strrchr(uri, '.');
	if (suffix == nullptr)
		return nullptr;

	++suffix;

	if (strpbrk(suffix, "/\\") != nullptr)
		return nullptr;

	return suffix;
}

static const char *
verify_uri_segment(const char *p)
{
	const char *q;

	unsigned dots = 0;
	while (*p == '.') {
		++p;
		++dots;
	}

	if (dots <= 2 && (*p == 0 || *p == '/'))
		return nullptr;

	q = strchr(p + 1, '/');
	return q != nullptr ? q : "";
}

bool
uri_safe_local(const char *uri)
{
	while (true) {
		uri = verify_uri_segment(uri);
		if (uri == nullptr)
			return false;

		if (*uri == 0)
			return true;

		assert(*uri == '/');

		++uri;
	}
}

char *
uri_remove_auth(const char *uri)
{
	const char *auth, *slash, *at;
	char *p;

	if (strncmp(uri, "http://", 7) == 0)
		auth = uri + 7;
	else if (strncmp(uri, "https://", 8) == 0)
		auth = uri + 8;
	else
		/* unrecognized URI */
		return nullptr;

	slash = strchr(auth, '/');
	if (slash == nullptr)
		slash = auth + strlen(auth);

	at = (const char *)memchr(auth, '@', slash - auth);
	if (at == nullptr)
		/* no auth info present, do nothing */
		return nullptr;

	/* duplicate the full URI and then delete the auth
	   information */
	p = g_strdup(uri);
	memmove(p + (auth - uri), p + (at + 1 - uri),
		strlen(at));

	return p;
}
