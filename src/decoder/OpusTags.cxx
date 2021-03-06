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
#include "OpusTags.hxx"
#include "OpusReader.hxx"
#include "XiphTags.hxx"
#include "tag/TagHandler.hxx"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

static void
ScanOneOpusTag(const char *name, const char *value,
	       const struct tag_handler *handler, void *ctx)
{
	tag_handler_invoke_pair(handler, ctx, name, value);

	if (handler->tag != nullptr) {
		enum tag_type t = tag_table_lookup_i(xiph_tags, name);
		if (t != TAG_NUM_OF_ITEM_TYPES)
			tag_handler_invoke_tag(handler, ctx, t, value);
	}
}

bool
ScanOpusTags(const void *data, size_t size,
	     const struct tag_handler *handler, void *ctx)
{
	OpusReader r(data, size);
	if (!r.Expect("OpusTags", 8))
		return false;

	if (handler->pair == nullptr && handler->tag == nullptr)
		return true;

	if (!r.SkipString())
		return false;

	uint32_t n;
	if (!r.ReadWord(n))
		return false;

	while (n-- > 0) {
		char *p = r.ReadString();
		if (p == nullptr)
			return false;

		char *eq = strchr(p, '=');
		if (eq != nullptr && eq > p) {
			*eq = 0;

			ScanOneOpusTag(p, eq + 1, handler, ctx);
		}

		free(p);
	}

	return true;
}
