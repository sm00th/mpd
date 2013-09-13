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
#include "CurlInputPlugin.hxx"
#include "InputInternal.hxx"
#include "InputStream.hxx"
#include "InputPlugin.hxx"
#include "ConfigGlobal.hxx"
#include "ConfigData.hxx"
#include "tag/Tag.hxx"
#include "IcyMetaDataParser.hxx"
#include "event/MultiSocketMonitor.hxx"
#include "event/Call.hxx"
#include "IOThread.hxx"
#include "util/Error.hxx"
#include "util/Domain.hxx"

#include <assert.h>

#if defined(WIN32)
	#include <winsock2.h>
#else
	#include <sys/select.h>
#endif

#include <string.h>
#include <errno.h>

#include <list>
#include <forward_list>

#include <curl/curl.h>
#include <glib.h>

#if LIBCURL_VERSION_NUM < 0x071200
#error libcurl is too old
#endif

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "input_curl"

/**
 * Do not buffer more than this number of bytes.  It should be a
 * reasonable limit that doesn't make low-end machines suffer too
 * much, but doesn't cause stuttering on high-latency lines.
 */
static const size_t CURL_MAX_BUFFERED = 512 * 1024;

/**
 * Resume the stream at this number of bytes after it has been paused.
 */
static const size_t CURL_RESUME_AT = 384 * 1024;

/**
 * Buffers created by input_curl_writefunction().
 */
class CurlInputBuffer {
	/** size of the payload */
	size_t size;

	/** how much has been consumed yet? */
	size_t consumed;

	/** the payload */
	uint8_t *data;

public:
	CurlInputBuffer(const void *_data, size_t _size)
		:size(_size), consumed(0), data(new uint8_t[size]) {
		memcpy(data, _data, size);
	}

	~CurlInputBuffer() {
		delete[] data;
	}

	CurlInputBuffer(const CurlInputBuffer &) = delete;
	CurlInputBuffer &operator=(const CurlInputBuffer &) = delete;

	const void *Begin() const {
		return data + consumed;
	}

	size_t TotalSize() const {
		return size;
	}

	size_t Available() const {
		return size - consumed;
	}

	/**
	 * Mark a part of the buffer as consumed.
	 *
	 * @return false if the buffer is now empty
	 */
	bool Consume(size_t length) {
		assert(consumed < size);

		consumed += length;
		if (consumed < size)
			return true;

		assert(consumed == size);
		return false;
	}

	bool Read(void *dest, size_t length) {
		assert(consumed + length <= size);

		memcpy(dest, data + consumed, length);
		return Consume(length);
	}
};

struct input_curl {
	struct input_stream base;

	/* some buffers which were passed to libcurl, which we have
	   too free */
	char *range;
	struct curl_slist *request_headers;

	/** the curl handles */
	CURL *easy;

	/** list of buffers, where input_curl_writefunction() appends
	    to, and input_curl_read() reads from them */
	std::list<CurlInputBuffer> buffers;

	/**
	 * Is the connection currently paused?  That happens when the
	 * buffer was getting too large.  It will be unpaused when the
	 * buffer is below the threshold again.
	 */
	bool paused;

	/** error message provided by libcurl */
	char error[CURL_ERROR_SIZE];

	/** parser for icy-metadata */
	IcyMetaDataParser icy;

	/** the stream name from the icy-name response header */
	char *meta_name;

	/** the tag object ready to be requested via
	    input_stream::ReadTag() */
	Tag *tag;

	Error postponed_error;

	input_curl(const char *url, Mutex &mutex, Cond &cond)
		:base(input_plugin_curl, url, mutex, cond),
		 range(nullptr), request_headers(nullptr),
		 paused(false),
		 meta_name(nullptr),
		 tag(nullptr) {}

	~input_curl();

	input_curl(const input_curl &) = delete;
	input_curl &operator=(const input_curl &) = delete;
};

/**
 * This class monitors all CURL file descriptors.
 */
class CurlSockets final : private MultiSocketMonitor {
public:
	CurlSockets(EventLoop &_loop)
		:MultiSocketMonitor(_loop) {}

	using MultiSocketMonitor::InvalidateSockets;

private:
	void UpdateSockets();

	virtual int PrepareSockets() override;
	virtual void DispatchSockets() override;
};

/** libcurl should accept "ICY 200 OK" */
static struct curl_slist *http_200_aliases;

/** HTTP proxy settings */
static const char *proxy, *proxy_user, *proxy_password;
static unsigned proxy_port;

static struct {
	CURLM *multi;

	/**
	 * A linked list of all active HTTP requests.  An active
	 * request is one that doesn't have the "eof" flag set.
	 */
	std::forward_list<input_curl *> requests;

	CurlSockets *sockets;
} curl;

static constexpr Domain http_domain("http");
static constexpr Domain curl_domain("curl");
static constexpr Domain curlm_domain("curlm");

/**
 * Find a request by its CURL "easy" handle.
 *
 * Runs in the I/O thread.  No lock needed.
 */
static struct input_curl *
input_curl_find_request(CURL *easy)
{
	assert(io_thread_inside());

	for (auto c : curl.requests)
		if (c->easy == easy)
			return c;

	return NULL;
}

static void
input_curl_resume(struct input_curl *c)
{
	assert(io_thread_inside());

	if (c->paused) {
		c->paused = false;
		curl_easy_pause(c->easy, CURLPAUSE_CONT);
	}
}

/**
 * Calculates the GLib event bit mask for one file descriptor,
 * obtained from three #fd_set objects filled by curl_multi_fdset().
 */
static unsigned
input_curl_fd_events(int fd, fd_set *rfds, fd_set *wfds, fd_set *efds)
{
	gushort events = 0;

	if (FD_ISSET(fd, rfds)) {
		events |= G_IO_IN | G_IO_HUP | G_IO_ERR;
		FD_CLR(fd, rfds);
	}

	if (FD_ISSET(fd, wfds)) {
		events |= G_IO_OUT | G_IO_ERR;
		FD_CLR(fd, wfds);
	}

	if (FD_ISSET(fd, efds)) {
		events |= G_IO_HUP | G_IO_ERR;
		FD_CLR(fd, efds);
	}

	return events;
}

/**
 * Updates all registered GPollFD objects, unregisters old ones,
 * registers new ones.
 *
 * Runs in the I/O thread.  No lock needed.
 */
void
CurlSockets::UpdateSockets()
{
	assert(io_thread_inside());

	fd_set rfds, wfds, efds;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&efds);

	int max_fd;
	CURLMcode mcode = curl_multi_fdset(curl.multi, &rfds, &wfds,
					   &efds, &max_fd);
	if (mcode != CURLM_OK) {
		g_warning("curl_multi_fdset() failed: %s\n",
			  curl_multi_strerror(mcode));
		return;
	}

	UpdateSocketList([&rfds, &wfds, &efds](int fd){
			return input_curl_fd_events(fd, &rfds,
						    &wfds, &efds);
		});

	for (int fd = 0; fd <= max_fd; ++fd) {
		unsigned events = input_curl_fd_events(fd, &rfds, &wfds, &efds);
		if (events != 0)
			AddSocket(fd, events);
	}
}

/**
 * Runs in the I/O thread.  No lock needed.
 */
static bool
input_curl_easy_add(struct input_curl *c, Error &error)
{
	assert(io_thread_inside());
	assert(c != NULL);
	assert(c->easy != NULL);
	assert(input_curl_find_request(c->easy) == NULL);

	curl.requests.push_front(c);

	CURLMcode mcode = curl_multi_add_handle(curl.multi, c->easy);
	if (mcode != CURLM_OK) {
		error.Format(curlm_domain, mcode,
			     "curl_multi_add_handle() failed: %s",
			     curl_multi_strerror(mcode));
		return false;
	}

	curl.sockets->InvalidateSockets();

	return true;
}

/**
 * Call input_curl_easy_add() in the I/O thread.  May be called from
 * any thread.  Caller must not hold a mutex.
 */
static bool
input_curl_easy_add_indirect(struct input_curl *c, Error &error)
{
	assert(c != NULL);
	assert(c->easy != NULL);

	bool result;
	BlockingCall(io_thread_get(), [c, &error, &result](){
			result = input_curl_easy_add(c, error);
		});
	return result;
}

/**
 * Frees the current "libcurl easy" handle, and everything associated
 * with it.
 *
 * Runs in the I/O thread.
 */
static void
input_curl_easy_free(struct input_curl *c)
{
	assert(io_thread_inside());
	assert(c != NULL);

	if (c->easy == NULL)
		return;

	curl.requests.remove(c);

	curl_multi_remove_handle(curl.multi, c->easy);
	curl_easy_cleanup(c->easy);
	c->easy = NULL;

	curl_slist_free_all(c->request_headers);
	c->request_headers = NULL;

	g_free(c->range);
	c->range = NULL;
}

/**
 * Frees the current "libcurl easy" handle, and everything associated
 * with it.
 *
 * The mutex must not be locked.
 */
static void
input_curl_easy_free_indirect(struct input_curl *c)
{
	BlockingCall(io_thread_get(), [c](){
			input_curl_easy_free(c);
			curl.sockets->InvalidateSockets();
		});

	assert(c->easy == NULL);
}

/**
 * Abort and free all HTTP requests.
 *
 * Runs in the I/O thread.  The caller must not hold locks.
 */
static void
input_curl_abort_all_requests(const Error &error)
{
	assert(io_thread_inside());
	assert(error.IsDefined());

	while (!curl.requests.empty()) {
		struct input_curl *c = curl.requests.front();
		assert(!c->postponed_error.IsDefined());

		input_curl_easy_free(c);

		const ScopeLock protect(c->base.mutex);

		c->postponed_error.Set(error);
		c->base.ready = true;

		c->base.cond.broadcast();
	}

}

/**
 * A HTTP request is finished.
 *
 * Runs in the I/O thread.  The caller must not hold locks.
 */
static void
input_curl_request_done(struct input_curl *c, CURLcode result, long status)
{
	assert(io_thread_inside());
	assert(c != NULL);
	assert(c->easy == NULL);
	assert(!c->postponed_error.IsDefined());

	const ScopeLock protect(c->base.mutex);

	if (result != CURLE_OK) {
		c->postponed_error.Format(curl_domain, result,
					  "curl failed: %s", c->error);
	} else if (status < 200 || status >= 300) {
		c->postponed_error.Format(http_domain, status,
					  "got HTTP status %ld",
					  status);
	}

	c->base.ready = true;

	c->base.cond.broadcast();
}

static void
input_curl_handle_done(CURL *easy_handle, CURLcode result)
{
	struct input_curl *c = input_curl_find_request(easy_handle);
	assert(c != NULL);

	long status = 0;
	curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE, &status);

	input_curl_easy_free(c);
	input_curl_request_done(c, result, status);
}

/**
 * Check for finished HTTP responses.
 *
 * Runs in the I/O thread.  The caller must not hold locks.
 */
static void
input_curl_info_read(void)
{
	assert(io_thread_inside());

	CURLMsg *msg;
	int msgs_in_queue;

	while ((msg = curl_multi_info_read(curl.multi,
					   &msgs_in_queue)) != NULL) {
		if (msg->msg == CURLMSG_DONE)
			input_curl_handle_done(msg->easy_handle, msg->data.result);
	}
}

/**
 * Give control to CURL.
 *
 * Runs in the I/O thread.  The caller must not hold locks.
 */
static bool
input_curl_perform(void)
{
	assert(io_thread_inside());

	CURLMcode mcode;

	do {
		int running_handles;
		mcode = curl_multi_perform(curl.multi, &running_handles);
	} while (mcode == CURLM_CALL_MULTI_PERFORM);

	if (mcode != CURLM_OK && mcode != CURLM_CALL_MULTI_PERFORM) {
		Error error;
		error.Format(curlm_domain, mcode,
			     "curl_multi_perform() failed: %s",
			     curl_multi_strerror(mcode));
		input_curl_abort_all_requests(error);
		return false;
	}

	return true;
}

int
CurlSockets::PrepareSockets()
{
	UpdateSockets();

	long timeout2;
	CURLMcode mcode = curl_multi_timeout(curl.multi, &timeout2);
	if (mcode == CURLM_OK) {
		if (timeout2 >= 0 && timeout2 < 10)
			/* CURL 7.21.1 likes to report "timeout=0",
			   which means we're running in a busy loop.
			   Quite a bad idea to waste so much CPU.
			   Let's use a lower limit of 10ms. */
			timeout2 = 10;

		return timeout2;
	} else {
		g_warning("curl_multi_timeout() failed: %s\n",
			  curl_multi_strerror(mcode));
		return -1;
	}
}

void
CurlSockets::DispatchSockets()
{
	if (input_curl_perform())
		input_curl_info_read();
}

/*
 * input_plugin methods
 *
 */

static bool
input_curl_init(const config_param &param, Error &error)
{
	CURLcode code = curl_global_init(CURL_GLOBAL_ALL);
	if (code != CURLE_OK) {
		error.Format(curl_domain, code,
			     "curl_global_init() failed: %s",
			     curl_easy_strerror(code));
		return false;
	}

	http_200_aliases = curl_slist_append(http_200_aliases, "ICY 200 OK");

	proxy = param.GetBlockValue("proxy");
	proxy_port = param.GetBlockValue("proxy_port", 0u);
	proxy_user = param.GetBlockValue("proxy_user");
	proxy_password = param.GetBlockValue("proxy_password");

	if (proxy == NULL) {
		/* deprecated proxy configuration */
		proxy = config_get_string(CONF_HTTP_PROXY_HOST, NULL);
		proxy_port = config_get_positive(CONF_HTTP_PROXY_PORT, 0);
		proxy_user = config_get_string(CONF_HTTP_PROXY_USER, NULL);
		proxy_password = config_get_string(CONF_HTTP_PROXY_PASSWORD,
						   "");
	}

	curl.multi = curl_multi_init();
	if (curl.multi == NULL) {
		error.Set(curl_domain, 0, "curl_multi_init() failed");
		return false;
	}

	curl.sockets = new CurlSockets(io_thread_get());

	return true;
}

static void
input_curl_finish(void)
{
	assert(curl.requests.empty());

	BlockingCall(io_thread_get(), [](){
			delete curl.sockets;
		});

	curl_multi_cleanup(curl.multi);

	curl_slist_free_all(http_200_aliases);

	curl_global_cleanup();
}

/**
 * Determine the total sizes of all buffers, including portions that
 * have already been consumed.
 *
 * The caller must lock the mutex.
 */
gcc_pure
static size_t
curl_total_buffer_size(const struct input_curl *c)
{
	size_t total = 0;

	for (const auto &i : c->buffers)
		total += i.TotalSize();

	return total;
}

input_curl::~input_curl()
{
	delete tag;

	g_free(meta_name);

	input_curl_easy_free_indirect(this);
}

static bool
input_curl_check(struct input_stream *is, Error &error)
{
	struct input_curl *c = (struct input_curl *)is;

	bool success = !c->postponed_error.IsDefined();
	if (!success) {
		error = std::move(c->postponed_error);
		c->postponed_error.Clear();
	}

	return success;
}

static Tag *
input_curl_tag(struct input_stream *is)
{
	struct input_curl *c = (struct input_curl *)is;
	Tag *tag = c->tag;

	c->tag = NULL;
	return tag;
}

static bool
fill_buffer(struct input_curl *c, Error &error)
{
	while (c->easy != NULL && c->buffers.empty())
		c->base.cond.wait(c->base.mutex);

	if (c->postponed_error.IsDefined()) {
		error = std::move(c->postponed_error);
		c->postponed_error.Clear();
		return false;
	}

	return !c->buffers.empty();
}

static size_t
read_from_buffer(IcyMetaDataParser &icy, std::list<CurlInputBuffer> &buffers,
		 void *dest0, size_t length)
{
	auto &buffer = buffers.front();
	uint8_t *dest = (uint8_t *)dest0;
	size_t nbytes = 0;

	if (length > buffer.Available())
		length = buffer.Available();

	while (true) {
		size_t chunk;

		chunk = icy.Data(length);
		if (chunk > 0) {
			const bool empty = !buffer.Read(dest, chunk);

			nbytes += chunk;
			dest += chunk;
			length -= chunk;

			if (empty) {
				buffers.pop_front();
				break;
			}

			if (length == 0)
				break;
		}

		chunk = icy.Meta(buffer.Begin(), length);
		if (chunk > 0) {
			const bool empty = !buffer.Consume(chunk);

			length -= chunk;

			if (empty) {
				buffers.pop_front();
				break;
			}

			if (length == 0)
				break;
		}
	}

	return nbytes;
}

static void
copy_icy_tag(struct input_curl *c)
{
	Tag *tag = c->icy.ReadTag();

	if (tag == NULL)
		return;

	delete c->tag;

	if (c->meta_name != NULL && !tag->HasType(TAG_NAME))
		tag->AddItem(TAG_NAME, c->meta_name);

	c->tag = tag;
}

static bool
input_curl_available(struct input_stream *is)
{
	struct input_curl *c = (struct input_curl *)is;

	return c->postponed_error.IsDefined() || c->easy == NULL ||
		!c->buffers.empty();
}

static size_t
input_curl_read(struct input_stream *is, void *ptr, size_t size,
		Error &error)
{
	struct input_curl *c = (struct input_curl *)is;
	bool success;
	size_t nbytes = 0;
	char *dest = (char *)ptr;

	do {
		/* fill the buffer */

		success = fill_buffer(c, error);
		if (!success)
			return 0;

		/* send buffer contents */

		while (size > 0 && !c->buffers.empty()) {
			size_t copy = read_from_buffer(c->icy, c->buffers,
						       dest + nbytes, size);

			nbytes += copy;
			size -= copy;
		}
	} while (nbytes == 0);

	if (c->icy.IsDefined())
		copy_icy_tag(c);

	is->offset += (goffset)nbytes;

	if (c->paused && curl_total_buffer_size(c) < CURL_RESUME_AT) {
		c->base.mutex.unlock();

		BlockingCall(io_thread_get(), [c](){
				input_curl_resume(c);
			});

		c->base.mutex.lock();
	}

	return nbytes;
}

static void
input_curl_close(struct input_stream *is)
{
	struct input_curl *c = (struct input_curl *)is;

	delete c;
}

static bool
input_curl_eof(gcc_unused struct input_stream *is)
{
	struct input_curl *c = (struct input_curl *)is;

	return c->easy == NULL && c->buffers.empty();
}

/** called by curl when new data is available */
static size_t
input_curl_headerfunction(void *ptr, size_t size, size_t nmemb, void *stream)
{
	struct input_curl *c = (struct input_curl *)stream;
	char name[64];

	size *= nmemb;

	const char *header = (const char *)ptr;
	const char *end = header + size;

	const char *value = (const char *)memchr(header, ':', size);
	if (value == NULL || (size_t)(value - header) >= sizeof(name))
		return size;

	memcpy(name, header, value - header);
	name[value - header] = 0;

	/* skip the colon */

	++value;

	/* strip the value */

	while (value < end && g_ascii_isspace(*value))
		++value;

	while (end > value && g_ascii_isspace(end[-1]))
		--end;

	if (g_ascii_strcasecmp(name, "accept-ranges") == 0) {
		/* a stream with icy-metadata is not seekable */
		if (!c->icy.IsDefined())
			c->base.seekable = true;
	} else if (g_ascii_strcasecmp(name, "content-length") == 0) {
		char buffer[64];

		if ((size_t)(end - header) >= sizeof(buffer))
			return size;

		memcpy(buffer, value, end - value);
		buffer[end - value] = 0;

		c->base.size = c->base.offset + g_ascii_strtoull(buffer, NULL, 10);
	} else if (g_ascii_strcasecmp(name, "content-type") == 0) {
		c->base.mime.assign(value, end);
	} else if (g_ascii_strcasecmp(name, "icy-name") == 0 ||
		   g_ascii_strcasecmp(name, "ice-name") == 0 ||
		   g_ascii_strcasecmp(name, "x-audiocast-name") == 0) {
		g_free(c->meta_name);
		c->meta_name = g_strndup(value, end - value);

		delete c->tag;

		c->tag = new Tag();
		c->tag->AddItem(TAG_NAME, c->meta_name);
	} else if (g_ascii_strcasecmp(name, "icy-metaint") == 0) {
		char buffer[64];
		size_t icy_metaint;

		if ((size_t)(end - header) >= sizeof(buffer) ||
		    c->icy.IsDefined())
			return size;

		memcpy(buffer, value, end - value);
		buffer[end - value] = 0;

		icy_metaint = g_ascii_strtoull(buffer, NULL, 10);
		g_debug("icy-metaint=%zu", icy_metaint);

		if (icy_metaint > 0) {
			c->icy.Start(icy_metaint);

			/* a stream with icy-metadata is not
			   seekable */
			c->base.seekable = false;
		}
	}

	return size;
}

/** called by curl when new data is available */
static size_t
input_curl_writefunction(void *ptr, size_t size, size_t nmemb, void *stream)
{
	struct input_curl *c = (struct input_curl *)stream;

	size *= nmemb;
	if (size == 0)
		return 0;

	const ScopeLock protect(c->base.mutex);

	if (curl_total_buffer_size(c) + size >= CURL_MAX_BUFFERED) {
		c->paused = true;
		return CURL_WRITEFUNC_PAUSE;
	}

	c->buffers.emplace_back(ptr, size);
	c->base.ready = true;

	c->base.cond.broadcast();
	return size;
}

static bool
input_curl_easy_init(struct input_curl *c, Error &error)
{
	CURLcode code;

	c->easy = curl_easy_init();
	if (c->easy == NULL) {
		error.Set(curl_domain, "curl_easy_init() failed");
		return false;
	}

	curl_easy_setopt(c->easy, CURLOPT_USERAGENT,
			 "Music Player Daemon " VERSION);
	curl_easy_setopt(c->easy, CURLOPT_HEADERFUNCTION,
			 input_curl_headerfunction);
	curl_easy_setopt(c->easy, CURLOPT_WRITEHEADER, c);
	curl_easy_setopt(c->easy, CURLOPT_WRITEFUNCTION,
			 input_curl_writefunction);
	curl_easy_setopt(c->easy, CURLOPT_WRITEDATA, c);
	curl_easy_setopt(c->easy, CURLOPT_HTTP200ALIASES, http_200_aliases);
	curl_easy_setopt(c->easy, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(c->easy, CURLOPT_NETRC, 1);
	curl_easy_setopt(c->easy, CURLOPT_MAXREDIRS, 5);
	curl_easy_setopt(c->easy, CURLOPT_FAILONERROR, true);
	curl_easy_setopt(c->easy, CURLOPT_ERRORBUFFER, c->error);
	curl_easy_setopt(c->easy, CURLOPT_NOPROGRESS, 1l);
	curl_easy_setopt(c->easy, CURLOPT_NOSIGNAL, 1l);
	curl_easy_setopt(c->easy, CURLOPT_CONNECTTIMEOUT, 10l);

	if (proxy != NULL)
		curl_easy_setopt(c->easy, CURLOPT_PROXY, proxy);

	if (proxy_port > 0)
		curl_easy_setopt(c->easy, CURLOPT_PROXYPORT, (long)proxy_port);

	if (proxy_user != NULL && proxy_password != NULL) {
		char *proxy_auth_str =
			g_strconcat(proxy_user, ":", proxy_password, NULL);
		curl_easy_setopt(c->easy, CURLOPT_PROXYUSERPWD, proxy_auth_str);
		g_free(proxy_auth_str);
	}

	code = curl_easy_setopt(c->easy, CURLOPT_URL, c->base.uri.c_str());
	if (code != CURLE_OK) {
		error.Format(curl_domain, code,
			     "curl_easy_setopt() failed: %s",
			     curl_easy_strerror(code));
		return false;
	}

	c->request_headers = NULL;
	c->request_headers = curl_slist_append(c->request_headers,
					       "Icy-Metadata: 1");
	curl_easy_setopt(c->easy, CURLOPT_HTTPHEADER, c->request_headers);

	return true;
}

static bool
input_curl_seek(struct input_stream *is, goffset offset, int whence,
		Error &error)
{
	struct input_curl *c = (struct input_curl *)is;
	bool ret;

	assert(is->ready);

	if (whence == SEEK_SET && offset == is->offset)
		/* no-op */
		return true;

	if (!is->seekable)
		return false;

	/* calculate the absolute offset */

	switch (whence) {
	case SEEK_SET:
		break;

	case SEEK_CUR:
		offset += is->offset;
		break;

	case SEEK_END:
		if (is->size < 0)
			/* stream size is not known */
			return false;

		offset += is->size;
		break;

	default:
		return false;
	}

	if (offset < 0)
		return false;

	/* check if we can fast-forward the buffer */

	while (offset > is->offset && !c->buffers.empty()) {
		auto &buffer = c->buffers.front();
		size_t length = buffer.Available();
		if (offset - is->offset < (goffset)length)
			length = offset - is->offset;

		const bool empty = !buffer.Consume(length);
		if (empty)
			c->buffers.pop_front();

		is->offset += length;
	}

	if (offset == is->offset)
		return true;

	/* close the old connection and open a new one */

	c->base.mutex.unlock();

	input_curl_easy_free_indirect(c);
	c->buffers.clear();

	is->offset = offset;
	if (is->offset == is->size) {
		/* seek to EOF: simulate empty result; avoid
		   triggering a "416 Requested Range Not Satisfiable"
		   response */
		return true;
	}

	ret = input_curl_easy_init(c, error);
	if (!ret)
		return false;

	/* send the "Range" header */

	if (is->offset > 0) {
		c->range = g_strdup_printf("%lld-", (long long)is->offset);
		curl_easy_setopt(c->easy, CURLOPT_RANGE, c->range);
	}

	c->base.ready = false;

	if (!input_curl_easy_add_indirect(c, error))
		return false;

	c->base.mutex.lock();

	while (!c->base.ready)
		c->base.cond.wait(c->base.mutex);

	if (c->postponed_error.IsDefined()) {
		error = std::move(c->postponed_error);
		c->postponed_error.Clear();
		return false;
	}

	return true;
}

static struct input_stream *
input_curl_open(const char *url, Mutex &mutex, Cond &cond,
		Error &error)
{
	if ((strncmp(url, "http://",  7) != 0) &&
	    (strncmp(url, "https://", 8) != 0))
		return NULL;

	struct input_curl *c = new input_curl(url, mutex, cond);

	if (!input_curl_easy_init(c, error)) {
		delete c;
		return NULL;
	}

	if (!input_curl_easy_add_indirect(c, error)) {
		delete c;
		return NULL;
	}

	return &c->base;
}

const struct input_plugin input_plugin_curl = {
	"curl",
	input_curl_init,
	input_curl_finish,
	input_curl_open,
	input_curl_close,
	input_curl_check,
	nullptr,
	input_curl_tag,
	input_curl_available,
	input_curl_read,
	input_curl_eof,
	input_curl_seek,
};
