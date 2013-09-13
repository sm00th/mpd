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
#include "EightTracksPlaylistPlugin.hxx"
#include "PlaylistPlugin.hxx"
#include "ConfigData.hxx"
#include "InputStream.hxx"
#include "util/Error.hxx"
#include "Song.hxx"
#include "tag/Tag.hxx"
#include "MemorySongEnumerator.hxx"

#include <glib.h>
#include <yajl/yajl_parse.h>

#include <string.h>

static struct {
  char *apikey;
  char *token;
} et_config;

enum et_key {
  KEY_PLAYTOKEN,
  KEY_NAME,
  KEY_PERFORMER,
  KEY_URL,
  KEY_DURATION,
  KEY_MIXEND,
  KEY_ID,
  KEY_MIX,
  KEY_OTHER,
};

enum et_lvls {
  LVL_ROOT,
  LVL_MIX,
};

static const char* et_keystr[] = {
  "play_token",
  "name",
  "performer",
  "url",
  "play_duration",
  "at_end",
  "id",
  "mix",
  NULL,
};

struct parse_data {
  int key;
  int lvl;
  int sublvl;
  char *title;
  char *artist;
  char *url;
  char *mixid;
  int duration;
  bool mixend;
};

static int handle_string(void *ctx, const unsigned char* stringval,
#ifdef HAVE_YAJL1
       unsigned int
#else
       size_t
#endif
       stringlen)
{
  struct parse_data *data = (struct parse_data *) ctx;

  switch (data->key) {
  case KEY_PLAYTOKEN:
    if (et_config.token != NULL)
      g_free(et_config.token);
    et_config.token = g_strndup((const gchar*)stringval, stringlen);
    break;
  case KEY_NAME:
    if (data->title != NULL)
      g_free(data->title);
    data->title = g_strndup((const gchar*)stringval, stringlen);
    break;
  case KEY_PERFORMER:
    if (data->artist != NULL)
      g_free(data->artist);
    data->artist = g_strndup((const gchar*)stringval, stringlen);
    break;
  case KEY_URL:
    if (data->url != NULL)
      g_free(data->url);
    data->url = g_strndup((const gchar*)stringval, stringlen);
    break;
  default:
    break;
  }

  return 1;
}

static int handle_boolean(void *ctx, int boolval)
{
  struct parse_data *data = (struct parse_data *) ctx;
  switch (data->key) {
  case KEY_MIXEND:
    data->mixend = boolval;
    break;
  default:
    break;
  }

  return 1;
}

static int handle_integer(void *ctx,
        long
#ifndef HAVE_YAJL1
        long
#endif
        intval)
{
  struct parse_data *data = (struct parse_data *) ctx;
  switch (data->key) {
  case KEY_DURATION:
    data->duration = intval;
    break;
  case KEY_ID:
    if (data->lvl == LVL_MIX && data->sublvl == 1) {
      if (data->mixid != NULL)
        g_free(data->mixid);
      data->mixid = g_strdup_printf("%lld", intval);
    }
    break;
  default:
    break;
  }

  return 1;
}

static int handle_mapkey(void *ctx, const unsigned char* stringval,
#ifdef HAVE_YAJL1
       unsigned int
#else
       size_t
#endif
       stringlen)
{
  struct parse_data *data = (struct parse_data *) ctx;

  int i;
  data->key = KEY_OTHER;

  for (i = 0; i < KEY_OTHER; ++i) {
    if (strncmp((const char *)stringval, et_keystr[i], stringlen) == 0) {
      data->key = i;
      break;
    }
  }

  return 1;
}

static int handle_start_map(void *ctx)
{
  struct parse_data *data = (struct parse_data *) ctx;

  switch (data->key) {
  case KEY_MIX:
    data->lvl = LVL_MIX;
    data->sublvl = 1;
    break;
  default:
    data->sublvl++;
    break;
  }

  return 1;
}

static int handle_end_map(void *ctx)
{
  struct parse_data *data = (struct parse_data *) ctx;

  // Assuming that lvls we are interested in will never overlap
  if (data->sublvl > 0) {
    if (--data->sublvl == 0) {
      data->lvl = LVL_ROOT;
    }
  }

  return 1;
}

static yajl_callbacks parse_callbacks = {
  NULL,
  handle_boolean,
  handle_integer,
  NULL,
  NULL,
  handle_string,
  handle_start_map,
  handle_mapkey,
  handle_end_map,
  NULL,
  NULL,
};

static int etracks_parse_url(const char* uri, Mutex &mutex, Cond &cond,
    struct parse_data &data)
{
  yajl_handle hand;

#ifdef HAVE_YAJL1
  hand = yajl_alloc(&parse_callbacks, NULL, NULL, (void *) &data);
#else
  hand = yajl_alloc(&parse_callbacks, NULL, (void *) &data);
#endif

  Error error;
  input_stream *input_stream = input_stream::Open(uri, mutex, cond,
    error);
  if (input_stream == NULL) {
    if (error.IsDefined())
      g_warning("%s", error.GetMessage());
    return -1;
  }
  mutex.lock();
  input_stream->WaitReady();

  yajl_status stat;
  int done = 0;

  char buffer[4096];
  unsigned char *ubuffer = (unsigned char *)buffer;
  while (!done) {
    const size_t nbytes =
      input_stream->Read(buffer, sizeof(buffer), error);
    if (nbytes == 0) {
      if (error.IsDefined())
        g_warning("%s", error.GetMessage());

      if (input_stream->IsEOF()) {
        done = true;
      } else {
        mutex.unlock();
        input_stream->Close();
        return -1;
      }
    }
    if (done) {
#ifdef HAVE_YAJL1
      stat = yajl_parse_complete(hand);
#else
      stat = yajl_complete_parse(hand);
#endif
    } else
      stat = yajl_parse(hand, ubuffer, nbytes);

    if (stat != yajl_status_ok
#ifdef HAVE_YAJL1
        && stat != yajl_status_insufficient_data
#endif
        )
    {
      unsigned char *str = yajl_get_error(hand, 1, ubuffer, nbytes);
      yajl_free_error(hand, str);
      break;
    }
  }

  mutex.unlock();
  input_stream->Close();

  return 0;
}

static void etracks_parse_data(struct parse_data &data,
    std::forward_list<SongPointer> &songs)
{
  if (data.url != NULL) {
    Song *song = Song::NewRemote(data.url);
    Tag *t = new Tag();
    t->time = data.duration / 1000;
    if (data.title != NULL) {
      t->AddItem(TAG_TITLE, data.title);
      g_free(data.title);
      data.title = NULL;
    }
    if (data.artist != NULL) {
      t->AddItem(TAG_ARTIST, data.artist);
      g_free(data.artist);
      data.artist = NULL;
    }
    song->tag = t;
    songs.emplace_front(song);
    g_free(data.url);
    data.url = NULL;
  }
}

static SongEnumerator *
etracks_open_uri(const char *uri, Mutex &mutex, Cond &cond)
{
  struct parse_data data;
  data.artist = NULL;
  data.title = NULL;
  data.url = NULL;
  data.mixid = NULL;
  data.mixend = false;
  data.lvl = LVL_ROOT;
  data.sublvl = 0;

  if (et_config.token == NULL) {
    char *tokenurl = g_strconcat("http://8tracks.com/sets/new.json?api_key=",
        et_config.apikey, NULL);
    etracks_parse_url(tokenurl, mutex, cond, data);
    if (et_config.token == NULL) {
      g_warning("Failed to get playtoken");
      return NULL;
    }
  }

  char *s, *p;
  char *arg, *rest;
  char *mixid = NULL;
  s = g_strdup(uri);
  for (p = s; *p; p++) {
    if (*p == ':' && *(p+1) == '/' && *(p+2) == '/') {
      *p = 0;
      p += 3;
      break;
    }
  }
  arg = p;
  for (; *p; p++) {
    if (*p == '/') {
      *p = 0;
      p++;
      break;
    }
  }
  rest = p;

  if (strcmp(arg, "mix") == 0) {
    mixid = rest;
  } else {
    char *mixinfourl = g_strconcat("http://8tracks.com/", arg, "/", rest,
        ".json?api_key=", et_config.apikey, NULL);
    etracks_parse_url(mixinfourl, mutex, cond, data);
    mixid = data.mixid;
  }

  std::forward_list<SongPointer> songs;

  if (mixid != NULL) {
    char *mixurl = g_strconcat("http://8tracks.com/sets/", et_config.token,
        "/play.json?mix_id=", mixid, "&api_key=", et_config.apikey, NULL);

    int result = etracks_parse_url(mixurl, mutex, cond, data);
    g_free(mixurl);
    etracks_parse_data(data, songs);
    while (data.mixend == false && result == 0) {
      mixurl = g_strconcat("http://8tracks.com/sets/", et_config.token,
          "/next.json?mix_id=", mixid, "&api_key=", et_config.apikey, NULL);
      result = etracks_parse_url(mixurl, mutex, cond, data);
      etracks_parse_data(data, songs);
      g_free(mixurl);
    }
    if (data.mixid != NULL) {
      g_free(data.mixid);
    }
  } else {
    g_warning("Failed to parse uri: %s", uri);
  }
  g_free(s);

  songs.reverse();
  return new MemorySongEnumerator(std::move(songs));
}

static bool
etracks_init(const config_param &param)
{
  et_config.apikey = param.DupBlockString("apikey");
  if (et_config.apikey == NULL) {
    g_debug("disabling the 8tracks playlist plugin "
      "because API key is not set");
    return false;
  }
  et_config.token = NULL;
  return true;
}

static void
etracks_finish(void)
{
  g_free(et_config.apikey);
  if (et_config.token != NULL) {
    g_free(et_config.token);
  }
}

static const char *const etracks_schemes[] = {
  "etracks",
  NULL
};

const struct playlist_plugin eighttracks_playlist_plugin = {
  "etracks",

  etracks_init,
  etracks_finish,
  etracks_open_uri,
  nullptr,

  etracks_schemes,
  nullptr,
  nullptr,
};
