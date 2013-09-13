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

/**
  * single bz2 archive handling (requires libbz2)
  */

#include "config.h"
#include "Bzip2ArchivePlugin.hxx"
#include "ArchivePlugin.hxx"
#include "ArchiveFile.hxx"
#include "ArchiveVisitor.hxx"
#include "InputInternal.hxx"
#include "InputStream.hxx"
#include "InputPlugin.hxx"
#include "util/RefCount.hxx"
#include "util/Error.hxx"
#include "util/Domain.hxx"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <glib.h>
#include <bzlib.h>

#ifdef HAVE_OLDER_BZIP2
#define BZ2_bzDecompressInit bzDecompressInit
#define BZ2_bzDecompress bzDecompress
#endif

class Bzip2ArchiveFile final : public ArchiveFile {
public:
	RefCount ref;

	char *const name;
	struct input_stream *const istream;

	Bzip2ArchiveFile(const char *path, input_stream *_is)
		:ArchiveFile(bz2_archive_plugin),
		 name(g_path_get_basename(path)),
		 istream(_is) {
		// remove .bz2 suffix
		size_t len = strlen(name);
		if (len > 4)
			name[len - 4] = 0;
	}

	~Bzip2ArchiveFile() {
		istream->Close();
	}

	void Ref() {
		ref.Increment();
	}

	void Unref() {
		if (!ref.Decrement())
			return;

		g_free(name);
		delete this;
	}

	virtual void Close() override {
		Unref();
	}

	virtual void Visit(ArchiveVisitor &visitor) override {
		visitor.VisitArchiveEntry(name);
	}

	virtual input_stream *OpenStream(const char *path,
					 Mutex &mutex, Cond &cond,
					 Error &error) override;
};

struct Bzip2InputStream {
	struct input_stream base;

	Bzip2ArchiveFile *archive;

	bool eof;

	bz_stream bzstream;

	char buffer[5000];

	Bzip2InputStream(Bzip2ArchiveFile &context, const char *uri,
			 Mutex &mutex, Cond &cond);
	~Bzip2InputStream();

	bool Open(Error &error);
	void Close();
};

extern const struct input_plugin bz2_inputplugin;

static constexpr Domain bz2_domain("bz2");

static inline GQuark
bz2_quark(void)
{
	return g_quark_from_static_string("bz2");
}

/* single archive handling allocation helpers */

inline bool
Bzip2InputStream::Open(Error &error)
{
	bzstream.bzalloc = nullptr;
	bzstream.bzfree = nullptr;
	bzstream.opaque = nullptr;

	bzstream.next_in = (char *)buffer;
	bzstream.avail_in = 0;

	int ret = BZ2_bzDecompressInit(&bzstream, 0, 0);
	if (ret != BZ_OK) {
		error.Set(bz2_domain, ret,
			  "BZ2_bzDecompressInit() has failed");
		return false;
	}

	base.ready = true;
	return true;
}

inline void
Bzip2InputStream::Close()
{
	BZ2_bzDecompressEnd(&bzstream);
}

/* archive open && listing routine */

static ArchiveFile *
bz2_open(const char *pathname, Error &error)
{
	static Mutex mutex;
	static Cond cond;
	input_stream *is = input_stream::Open(pathname, mutex, cond, error);
	if (is == nullptr)
		return nullptr;

	return new Bzip2ArchiveFile(pathname, is);
}

/* single archive handling */

Bzip2InputStream::Bzip2InputStream(Bzip2ArchiveFile &_context, const char *uri,
				   Mutex &mutex, Cond &cond)
	:base(bz2_inputplugin, uri, mutex, cond),
	 archive(&_context), eof(false)
{
	archive->Ref();
}

Bzip2InputStream::~Bzip2InputStream()
{
	archive->Unref();
}

input_stream *
Bzip2ArchiveFile::OpenStream(const char *path,
			     Mutex &mutex, Cond &cond,
			     Error &error)
{
	Bzip2InputStream *bis = new Bzip2InputStream(*this, path, mutex, cond);
	if (!bis->Open(error)) {
		delete bis;
		return NULL;
	}

	return &bis->base;
}

static void
bz2_is_close(struct input_stream *is)
{
	Bzip2InputStream *bis = (Bzip2InputStream *)is;

	bis->Close();
	delete bis;
}

static bool
bz2_fillbuffer(Bzip2InputStream *bis, Error &error)
{
	size_t count;
	bz_stream *bzstream;

	bzstream = &bis->bzstream;

	if (bzstream->avail_in > 0)
		return true;

	count = bis->archive->istream->Read(bis->buffer, sizeof(bis->buffer),
					    error);
	if (count == 0)
		return false;

	bzstream->next_in = bis->buffer;
	bzstream->avail_in = count;
	return true;
}

static size_t
bz2_is_read(struct input_stream *is, void *ptr, size_t length,
	    Error &error)
{
	Bzip2InputStream *bis = (Bzip2InputStream *)is;
	bz_stream *bzstream;
	int bz_result;
	size_t nbytes = 0;

	if (bis->eof)
		return 0;

	bzstream = &bis->bzstream;
	bzstream->next_out = (char *)ptr;
	bzstream->avail_out = length;

	do {
		if (!bz2_fillbuffer(bis, error))
			return 0;

		bz_result = BZ2_bzDecompress(bzstream);

		if (bz_result == BZ_STREAM_END) {
			bis->eof = true;
			break;
		}

		if (bz_result != BZ_OK) {
			error.Set(bz2_domain, bz_result,
				  "BZ2_bzDecompress() has failed");
			return 0;
		}
	} while (bzstream->avail_out == length);

	nbytes = length - bzstream->avail_out;
	is->offset += nbytes;

	return nbytes;
}

static bool
bz2_is_eof(struct input_stream *is)
{
	Bzip2InputStream *bis = (Bzip2InputStream *)is;

	return bis->eof;
}

/* exported structures */

static const char *const bz2_extensions[] = {
	"bz2",
	NULL
};

const struct input_plugin bz2_inputplugin = {
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	bz2_is_close,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	bz2_is_read,
	bz2_is_eof,
	nullptr,
};

const struct archive_plugin bz2_archive_plugin = {
	"bz2",
	nullptr,
	nullptr,
	bz2_open,
	bz2_extensions,
};

