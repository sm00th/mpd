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

#ifndef MPD_SOCKET_MONITOR_HXX
#define MPD_SOCKET_MONITOR_HXX

#include "check.h"

#ifdef USE_EPOLL
#include <sys/epoll.h>
#else
#include <glib.h>
#endif

#include <type_traits>

#include <assert.h>
#include <stddef.h>

#ifdef WIN32
/* ERRORis a WIN32 macro that poisons our namespace; this is a
   kludge to allow us to use it anyway */
#ifdef ERROR
#undef ERROR
#endif
#endif

class EventLoop;

class SocketMonitor {
#ifdef USE_EPOLL
#else
	struct Source {
		GSource base;

		SocketMonitor *monitor;
	};
#endif

	int fd;
	EventLoop &loop;

#ifdef USE_EPOLL
	/**
	 * A bit mask of events that is currently registered in the EventLoop.
	 */
	unsigned scheduled_flags;
#else
	Source *source;
	GPollFD poll;
#endif

public:
#ifdef USE_EPOLL
	static constexpr unsigned READ = EPOLLIN;
	static constexpr unsigned WRITE = EPOLLOUT;
	static constexpr unsigned ERROR = EPOLLERR;
	static constexpr unsigned HANGUP = EPOLLHUP;
#else
	static constexpr unsigned READ = G_IO_IN;
	static constexpr unsigned WRITE = G_IO_OUT;
	static constexpr unsigned ERROR = G_IO_ERR;
	static constexpr unsigned HANGUP = G_IO_HUP;
#endif

	typedef std::make_signed<size_t>::type ssize_t;

#ifdef USE_EPOLL
	SocketMonitor(EventLoop &_loop)
		:fd(-1), loop(_loop), scheduled_flags(0) {}

	SocketMonitor(int _fd, EventLoop &_loop)
		:fd(_fd), loop(_loop), scheduled_flags(0) {}
#else
	SocketMonitor(EventLoop &_loop)
		:fd(-1), loop(_loop), source(nullptr) {}

	SocketMonitor(int _fd, EventLoop &_loop);
#endif

	~SocketMonitor();

	EventLoop &GetEventLoop() {
		return loop;
	}

	bool IsDefined() const {
		return fd >= 0;
	}

	int Get() const {
		assert(IsDefined());

		return fd;
	}

	void Open(int _fd);

	/**
	 * "Steal" the socket descriptor.  This abandons the socket
	 * and puts the responsibility for closing it to the caller.
	 */
	int Steal();

	void Close();

	unsigned GetScheduledFlags() const {
		assert(IsDefined());

#ifdef USE_EPOLL
		return scheduled_flags;
#else
		return poll.events;
#endif
	}

	void Schedule(unsigned flags);

	void Cancel() {
		Schedule(0);
	}

	void ScheduleRead() {
		Schedule(GetScheduledFlags() | READ | HANGUP | ERROR);
	}

	void ScheduleWrite() {
		Schedule(GetScheduledFlags() | WRITE);
	}

	void CancelRead() {
		Schedule(GetScheduledFlags() & ~(READ|HANGUP|ERROR));
	}

	void CancelWrite() {
		Schedule(GetScheduledFlags() & ~WRITE);
	}

	ssize_t Read(void *data, size_t length);
	ssize_t Write(const void *data, size_t length);

protected:
	/**
	 * @return false if the socket has been closed
	 */
	virtual bool OnSocketReady(unsigned flags) = 0;

public:
#ifdef USE_EPOLL
	void Dispatch(unsigned flags);
#else
	/* GSource callbacks */
	static gboolean Prepare(GSource *source, gint *timeout_r);
	static gboolean Check(GSource *source);
	static gboolean Dispatch(GSource *source, GSourceFunc callback,
				 gpointer user_data);

private:
	bool Check() const {
		assert(IsDefined());

		return (poll.revents & poll.events) != 0;
	}

	void Dispatch() {
		assert(IsDefined());

		OnSocketReady(poll.revents & poll.events);
	}
#endif
};

#endif
