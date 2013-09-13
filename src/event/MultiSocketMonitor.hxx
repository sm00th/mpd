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

#ifndef MPD_MULTI_SOCKET_MONITOR_HXX
#define MPD_MULTI_SOCKET_MONITOR_HXX

#include "check.h"
#include "gcc.h"

#ifdef USE_EPOLL
#include "IdleMonitor.hxx"
#include "TimeoutMonitor.hxx"
#include "SocketMonitor.hxx"
#else
#include "glib_compat.h"
#include <glib.h>

#endif

#include <forward_list>

#include <assert.h>
#include <stdint.h>

#ifdef WIN32
/* ERRORis a WIN32 macro that poisons our namespace; this is a
   kludge to allow us to use it anyway */
#ifdef ERROR
#undef ERROR
#endif
#endif

class EventLoop;

/**
 * Monitor multiple sockets.
 */
class MultiSocketMonitor
#ifdef USE_EPOLL
	: private IdleMonitor, private TimeoutMonitor
#endif
{
#ifdef USE_EPOLL
	class SingleFD final : public SocketMonitor {
		MultiSocketMonitor &multi;

		unsigned revents;

	public:
		SingleFD(MultiSocketMonitor &_multi, int _fd, unsigned events)
			:SocketMonitor(_fd, _multi.GetEventLoop()),
			multi(_multi), revents(0) {
			Schedule(events);
		}

		int GetFD() const {
			return SocketMonitor::Get();
		}

		unsigned GetEvents() const {
			return SocketMonitor::GetScheduledFlags();
		}

		void SetEvents(unsigned _events) {
			revents &= _events;
			SocketMonitor::Schedule(_events);
		}

		unsigned GetReturnedEvents() const {
			return revents;
		}

		void ClearReturnedEvents() {
			revents = 0;
		}

	protected:
		virtual bool OnSocketReady(unsigned flags) override {
			revents = flags;
			multi.SetReady();
			return true;
		}
	};

	friend class SingleFD;

	bool ready, refresh;
#else
	struct Source {
		GSource base;

		MultiSocketMonitor *monitor;
	};

	struct SingleFD {
		GPollFD pfd;

		constexpr SingleFD(gcc_unused MultiSocketMonitor &m,
				   int fd, unsigned events)
			:pfd{fd, gushort(events), 0} {}

		constexpr int GetFD() const {
			return pfd.fd;
		}

		constexpr unsigned GetEvents() const {
			return pfd.events;
		}

		constexpr unsigned GetReturnedEvents() const {
			return pfd.revents;
		}

		void SetEvents(unsigned _events) {
			pfd.events = _events;
		}
	};

	EventLoop &loop;
	Source *source;
	uint64_t absolute_timeout_us;
#endif

	std::forward_list<SingleFD> fds;

public:
#ifdef USE_EPOLL
	static constexpr unsigned READ = SocketMonitor::READ;
	static constexpr unsigned WRITE = SocketMonitor::WRITE;
	static constexpr unsigned ERROR = SocketMonitor::ERROR;
	static constexpr unsigned HANGUP = SocketMonitor::HANGUP;
#else
	static constexpr unsigned READ = G_IO_IN;
	static constexpr unsigned WRITE = G_IO_OUT;
	static constexpr unsigned ERROR = G_IO_ERR;
	static constexpr unsigned HANGUP = G_IO_HUP;
#endif

	MultiSocketMonitor(EventLoop &_loop);
	~MultiSocketMonitor();

#ifdef USE_EPOLL
	using IdleMonitor::GetEventLoop;
#else
	EventLoop &GetEventLoop() {
		return loop;
	}
#endif

public:
#ifndef USE_EPOLL
	gcc_pure
	uint64_t GetTime() const {
		return g_source_get_time(&source->base);
	}
#endif

	void InvalidateSockets() {
#ifdef USE_EPOLL
		refresh = true;
		IdleMonitor::Schedule();
#else
		/* no-op because GLib always calls the GSource's
		   "prepare" method before each poll() anyway */
#endif
	}

	void AddSocket(int fd, unsigned events) {
		fds.emplace_front(*this, fd, events);
#ifndef USE_EPOLL
		g_source_add_poll(&source->base, &fds.front().pfd);
#endif
	}

	template<typename E>
	void UpdateSocketList(E &&e) {
		for (auto prev = fds.before_begin(), end = fds.end(),
			     i = std::next(prev);
		     i != end; i = std::next(prev)) {
			assert(i->GetEvents() != 0);

			unsigned events = e(i->GetFD());
			if (events != 0) {
				i->SetEvents(events);
				prev = i;
			} else {
#ifdef USE_EPOLL
				i->Steal();
#else
				g_source_remove_poll(&source->base, &i->pfd);
#endif
				fds.erase_after(prev);
			}
		}
	}

protected:
	/**
	 * @return timeout [ms] or -1 for no timeout
	 */
	virtual int PrepareSockets() = 0;
	virtual void DispatchSockets() = 0;

#ifdef USE_EPOLL
private:
	void SetReady() {
		ready = true;
		IdleMonitor::Schedule();
	}

	void Prepare();

	virtual void OnTimeout() final {
		SetReady();
		IdleMonitor::Schedule();
	}

	virtual void OnIdle() final;

#else
public:
	/* GSource callbacks */
	static gboolean Prepare(GSource *source, gint *timeout_r);
	static gboolean Check(GSource *source);
	static gboolean Dispatch(GSource *source, GSourceFunc callback,
				 gpointer user_data);

private:
	bool Prepare(gint *timeout_r);
	bool Check() const;

	void Dispatch() {
		DispatchSockets();
	}
#endif
};

#endif
