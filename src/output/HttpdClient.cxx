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
#include "HttpdClient.hxx"
#include "HttpdInternal.hxx"
#include "util/fifo_buffer.h"
#include "Page.hxx"
#include "IcyMetaDataServer.hxx"
#include "system/SocketError.hxx"

#include <assert.h>
#include <string.h>

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "httpd_output"

HttpdClient::~HttpdClient()
{
	if (state == RESPONSE) {
		if (current_page != nullptr)
			current_page->Unref();

		for (auto page : pages)
			page->Unref();
	}

	if (metadata)
		metadata->Unref();
}

void
HttpdClient::Close()
{
	httpd->RemoveClient(*this);
}

void
HttpdClient::LockClose()
{
	const ScopeLock protect(httpd->mutex);
	Close();
}

void
HttpdClient::BeginResponse()
{
	assert(state != RESPONSE);

	state = RESPONSE;
	current_page = nullptr;

	httpd->SendHeader(*this);
}

/**
 * Handle a line of the HTTP request.
 */
bool
HttpdClient::HandleLine(const char *line)
{
	assert(state != RESPONSE);

	if (state == REQUEST) {
		if (strncmp(line, "GET /", 5) != 0) {
			/* only GET is supported */
			g_warning("malformed request line from client");
			return false;
		}

		line = strchr(line + 5, ' ');
		if (line == nullptr || strncmp(line + 1, "HTTP/", 5) != 0) {
			/* HTTP/0.9 without request headers */
			BeginResponse();
			return true;
		}

		/* after the request line, request headers follow */
		state = HEADERS;
		return true;
	} else {
		if (*line == 0) {
			/* empty line: request is finished */
			BeginResponse();
			return true;
		}

		if (g_ascii_strncasecmp(line, "Icy-MetaData: 1", 15) == 0) {
			/* Send icy metadata */
			metadata_requested = metadata_supported;
			return true;
		}

		if (g_ascii_strncasecmp(line, "transferMode.dlna.org: Streaming", 32) == 0) {
			/* Send as dlna */
			dlna_streaming_requested = true;
			/* metadata is not supported by dlna streaming, so disable it */
			metadata_supported = false;
			metadata_requested = false;
			return true;
		}

		/* expect more request headers */
		return true;
	}
}

/**
 * Sends the status line and response headers to the client.
 */
bool
HttpdClient::SendResponse()
{
	char buffer[1024];
	assert(state == RESPONSE);

	if (dlna_streaming_requested) {
		snprintf(buffer, sizeof(buffer),
			 "HTTP/1.1 206 OK\r\n"
			 "Content-Type: %s\r\n"
			 "Content-Length: 10000\r\n"
			 "Content-RangeX: 0-1000000/1000000\r\n"
			 "transferMode.dlna.org: Streaming\r\n"
			 "Accept-Ranges: bytes\r\n"
			 "Connection: close\r\n"
			 "realTimeInfo.dlna.org: DLNA.ORG_TLAG=*\r\n"
			 "contentFeatures.dlna.org: DLNA.ORG_OP=01;DLNA.ORG_CI=0\r\n"
			 "\r\n",
			 httpd->content_type);

	} else if (metadata_requested) {
		gchar *metadata_header;

		metadata_header =
			icy_server_metadata_header(httpd->name, httpd->genre,
						   httpd->website,
						   httpd->content_type,
						   metaint);

		g_strlcpy(buffer, metadata_header, sizeof(buffer));

		g_free(metadata_header);

       } else { /* revert to a normal HTTP request */
		snprintf(buffer, sizeof(buffer),
			 "HTTP/1.1 200 OK\r\n"
			 "Content-Type: %s\r\n"
			 "Connection: close\r\n"
			 "Pragma: no-cache\r\n"
			 "Cache-Control: no-cache, no-store\r\n"
			 "\r\n",
			 httpd->content_type);
	}

	ssize_t nbytes = SocketMonitor::Write(buffer, strlen(buffer));
	if (gcc_unlikely(nbytes < 0)) {
		const SocketErrorMessage msg;
		g_warning("failed to write to client: %s", (const char *)msg);
		Close();
		return false;
	}

	return true;
}

HttpdClient::HttpdClient(HttpdOutput *_httpd, int _fd, EventLoop &_loop,
			 bool _metadata_supported)
	:BufferedSocket(_fd, _loop),
	 httpd(_httpd),
	 state(REQUEST),
	 dlna_streaming_requested(false),
	 metadata_supported(_metadata_supported),
	 metadata_requested(false), metadata_sent(true),
	 metaint(8192), /*TODO: just a std value */
	 metadata(nullptr),
	 metadata_current_position(0), metadata_fill(0)
{
}

size_t
HttpdClient::GetQueueSize() const
{
	if (state != RESPONSE)
		return 0;

	size_t size = 0;
	for (auto page : pages)
		size += page->size;
	return size;
}

void
HttpdClient::CancelQueue()
{
	if (state != RESPONSE)
		return;

	for (auto page : pages)
		page->Unref();
	pages.clear();

	if (current_page == nullptr)
		CancelWrite();
}

ssize_t
HttpdClient::TryWritePage(const Page &page, size_t position)
{
	assert(position < page.size);

	return Write(page.data + position, page.size - position);
}

ssize_t
HttpdClient::TryWritePageN(const Page &page, size_t position, ssize_t n)
{
	return n >= 0
		? Write(page.data + position, n)
		: TryWritePage(page, position);
}

ssize_t
HttpdClient::GetBytesTillMetaData() const
{
	if (metadata_requested &&
	    current_page->size - current_position > metaint - metadata_fill)
		return metaint - metadata_fill;

	return -1;
}

inline bool
HttpdClient::TryWrite()
{
	const ScopeLock protect(httpd->mutex);

	assert(state == RESPONSE);

	if (current_page == nullptr) {
		if (pages.empty()) {
			/* another thread has removed the event source
			   while this thread was waiting for
			   httpd->mutex */
			CancelWrite();
			return true;
		}

		current_page = pages.front();
		pages.pop_front();
		current_position = 0;
	}

	const ssize_t bytes_to_write = GetBytesTillMetaData();
	if (bytes_to_write == 0) {
		if (!metadata_sent) {
			ssize_t nbytes = TryWritePage(*metadata,
						      metadata_current_position);
			if (nbytes < 0) {
				auto e = GetSocketError();
				if (IsSocketErrorAgain(e))
					return true;

				if (!IsSocketErrorClosed(e)) {
					SocketErrorMessage msg(e);
					g_warning("failed to write to client: %s",
						  (const char *)msg);
				}

				Close();
				return false;
			}

			metadata_current_position += nbytes;

			if (metadata->size - metadata_current_position == 0) {
				metadata_fill = 0;
				metadata_current_position = 0;
				metadata_sent = true;
			}
		} else {
			guchar empty_data = 0;

			ssize_t nbytes = Write(&empty_data, 1);
			if (nbytes < 0) {
				auto e = GetSocketError();
				if (IsSocketErrorAgain(e))
					return true;

				if (!IsSocketErrorClosed(e)) {
					SocketErrorMessage msg(e);
					g_warning("failed to write to client: %s",
						  (const char *)msg);
				}

				Close();
				return false;
			}

			metadata_fill = 0;
			metadata_current_position = 0;
		}
	} else {
		ssize_t nbytes =
			TryWritePageN(*current_page, current_position,
				      bytes_to_write);
		if (nbytes < 0) {
			auto e = GetSocketError();
			if (IsSocketErrorAgain(e))
				return true;

			if (!IsSocketErrorClosed(e)) {
				SocketErrorMessage msg(e);
				g_warning("failed to write to client: %s",
					  (const char *)msg);
			}

			Close();
			return false;
		}

		current_position += nbytes;
		assert(current_position <= current_page->size);

		if (metadata_requested)
			metadata_fill += nbytes;

		if (current_position >= current_page->size) {
			current_page->Unref();
			current_page = nullptr;

			if (pages.empty())
				/* all pages are sent: remove the
				   event source */
				CancelWrite();
		}
	}

	return true;
}

void
HttpdClient::PushPage(Page *page)
{
	if (state != RESPONSE)
		/* the client is still writing the HTTP request */
		return;

	page->Ref();
	pages.push_back(page);

	ScheduleWrite();
}

void
HttpdClient::PushMetaData(Page *page)
{
	if (metadata) {
		metadata->Unref();
		metadata = nullptr;
	}

	g_return_if_fail (page);

	page->Ref();
	metadata = page;
	metadata_sent = false;
}

bool
HttpdClient::OnSocketReady(unsigned flags)
{
	if (!BufferedSocket::OnSocketReady(flags))
		return false;

	if (flags & WRITE)
		if (!TryWrite())
			return false;

	return true;
}

BufferedSocket::InputResult
HttpdClient::OnSocketInput(const void *data, size_t length)
{
	if (state == RESPONSE) {
		g_warning("unexpected input from client");
		LockClose();
		return InputResult::CLOSED;
	}

	const char *line = (const char *)data;
	const char *newline = (const char *)memchr(line, '\n', length);
	if (newline == nullptr)
		return InputResult::MORE;

	ConsumeInput(newline + 1 - line);

	if (newline > line && newline[-1] == '\r')
		--newline;

	/* terminate the string at the end of the line; the const_cast
	   is a dirty hack */
	*const_cast<char *>(newline) = 0;

	if (!HandleLine(line)) {
		assert(state == RESPONSE);
		LockClose();
		return InputResult::CLOSED;
	}

	if (state == RESPONSE && !SendResponse())
		return InputResult::CLOSED;

	return InputResult::AGAIN;
}

void
HttpdClient::OnSocketError(Error &&error)
{
	g_warning("error on HTTP client: %s", error.GetMessage());
}

void
HttpdClient::OnSocketClosed()
{
	LockClose();
}
