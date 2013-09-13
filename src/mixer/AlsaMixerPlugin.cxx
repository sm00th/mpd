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
#include "MixerInternal.hxx"
#include "OutputAPI.hxx"
#include "GlobalEvents.hxx"
#include "Main.hxx"
#include "event/MultiSocketMonitor.hxx"
#include "event/Loop.hxx"
#include "util/ReusableArray.hxx"
#include "util/Error.hxx"
#include "util/Domain.hxx"

#include <algorithm>

#include <glib.h>
#include <alsa/asoundlib.h>

#define VOLUME_MIXER_ALSA_DEFAULT		"default"
#define VOLUME_MIXER_ALSA_CONTROL_DEFAULT	"PCM"
static constexpr unsigned VOLUME_MIXER_ALSA_INDEX_DEFAULT = 0;

class AlsaMixerMonitor final : private MultiSocketMonitor {
	snd_mixer_t *const mixer;

	ReusableArray<pollfd> pfd_buffer;

public:
	AlsaMixerMonitor(EventLoop &_loop, snd_mixer_t *_mixer)
		:MultiSocketMonitor(_loop), mixer(_mixer) {
		_loop.AddCall([this](){ InvalidateSockets(); });
	}

private:
	virtual int PrepareSockets() override;
	virtual void DispatchSockets() override;
};

class AlsaMixer final : public Mixer {
	const char *device;
	const char *control;
	unsigned int index;

	snd_mixer_t *handle;
	snd_mixer_elem_t *elem;
	long volume_min;
	long volume_max;
	int volume_set;

	AlsaMixerMonitor *monitor;

public:
	AlsaMixer():Mixer(alsa_mixer_plugin) {}

	void Configure(const config_param &param);
	bool Setup(Error &error);
	bool Open(Error &error);
	void Close();

	int GetVolume(Error &error);
	bool SetVolume(unsigned volume, Error &error);
};

static constexpr Domain alsa_mixer_domain("alsa_mixer");

int
AlsaMixerMonitor::PrepareSockets()
{
	int count = snd_mixer_poll_descriptors_count(mixer);
	if (count < 0)
		count = 0;

	struct pollfd *pfds = pfd_buffer.Get(count);

	count = snd_mixer_poll_descriptors(mixer, pfds, count);
	if (count < 0)
		count = 0;

	struct pollfd *end = pfds + count;

	UpdateSocketList([pfds, end](int fd) -> unsigned {
			auto i = std::find_if(pfds, end, [fd](const struct pollfd &pfd){
					return pfd.fd == fd;
				});
			if (i == end)
				return 0;

			auto events = i->events;
			i->events = 0;
			return events;
		});

	for (auto i = pfds; i != end; ++i)
		if (i->events != 0)
			AddSocket(i->fd, i->events);

	return -1;
}

void
AlsaMixerMonitor::DispatchSockets()
{
	snd_mixer_handle_events(mixer);
}

/*
 * libasound callbacks
 *
 */

static int
alsa_mixer_elem_callback(gcc_unused snd_mixer_elem_t *elem, unsigned mask)
{
	if (mask & SND_CTL_EVENT_MASK_VALUE)
		GlobalEvents::Emit(GlobalEvents::MIXER);

	return 0;
}

/*
 * mixer_plugin methods
 *
 */

inline void
AlsaMixer::Configure(const config_param &param)
{
	device = param.GetBlockValue("mixer_device",
				     VOLUME_MIXER_ALSA_DEFAULT);
	control = param.GetBlockValue("mixer_control",
				      VOLUME_MIXER_ALSA_CONTROL_DEFAULT);
	index = param.GetBlockValue("mixer_index",
				    VOLUME_MIXER_ALSA_INDEX_DEFAULT);
}

static Mixer *
alsa_mixer_init(gcc_unused void *ao, const config_param &param,
		gcc_unused Error &error)
{
	AlsaMixer *am = new AlsaMixer();
	am->Configure(param);

	return am;
}

static void
alsa_mixer_finish(Mixer *data)
{
	AlsaMixer *am = (AlsaMixer *)data;

	delete am;

	/* free libasound's config cache */
	snd_config_update_free_global();
}

gcc_pure
static snd_mixer_elem_t *
alsa_mixer_lookup_elem(snd_mixer_t *handle, const char *name, unsigned idx)
{
	for (snd_mixer_elem_t *elem = snd_mixer_first_elem(handle);
	     elem != NULL; elem = snd_mixer_elem_next(elem)) {
		if (snd_mixer_elem_get_type(elem) == SND_MIXER_ELEM_SIMPLE &&
		    g_ascii_strcasecmp(snd_mixer_selem_get_name(elem),
				       name) == 0 &&
		    snd_mixer_selem_get_index(elem) == idx)
			return elem;
	}

	return NULL;
}

inline bool
AlsaMixer::Setup(Error &error)
{
	int err;

	if ((err = snd_mixer_attach(handle, device)) < 0) {
		error.Format(alsa_mixer_domain, err,
			     "failed to attach to %s: %s",
			     device, snd_strerror(err));
		return false;
	}

	if ((err = snd_mixer_selem_register(handle, NULL,
		    NULL)) < 0) {
		error.Format(alsa_mixer_domain, err,
			     "snd_mixer_selem_register() failed: %s",
			     snd_strerror(err));
		return false;
	}

	if ((err = snd_mixer_load(handle)) < 0) {
		error.Format(alsa_mixer_domain, err,
			     "snd_mixer_load() failed: %s\n",
			     snd_strerror(err));
		return false;
	}

	elem = alsa_mixer_lookup_elem(handle, control, index);
	if (elem == NULL) {
		error.Format(alsa_mixer_domain, 0,
			    "no such mixer control: %s", control);
		return false;
	}

	snd_mixer_selem_get_playback_volume_range(elem, &volume_min,
						  &volume_max);

	snd_mixer_elem_set_callback(elem, alsa_mixer_elem_callback);

	monitor = new AlsaMixerMonitor(*main_loop, handle);

	return true;
}

inline bool
AlsaMixer::Open(Error &error)
{
	int err;

	volume_set = -1;

	err = snd_mixer_open(&handle, 0);
	if (err < 0) {
		error.Format(alsa_mixer_domain, err,
			     "snd_mixer_open() failed: %s", snd_strerror(err));
		return false;
	}

	if (!Setup(error)) {
		snd_mixer_close(handle);
		return false;
	}

	return true;
}

static bool
alsa_mixer_open(Mixer *data, Error &error)
{
	AlsaMixer *am = (AlsaMixer *)data;

	return am->Open(error);
}

inline void
AlsaMixer::Close()
{
	assert(handle != NULL);

	delete monitor;

	snd_mixer_elem_set_callback(elem, NULL);
	snd_mixer_close(handle);
}

static void
alsa_mixer_close(Mixer *data)
{
	AlsaMixer *am = (AlsaMixer *)data;
	am->Close();
}

inline int
AlsaMixer::GetVolume(Error &error)
{
	int err;
	int ret;
	long level;

	assert(handle != NULL);

	err = snd_mixer_handle_events(handle);
	if (err < 0) {
		error.Format(alsa_mixer_domain, err,
			     "snd_mixer_handle_events() failed: %s",
			     snd_strerror(err));
		return false;
	}

	err = snd_mixer_selem_get_playback_volume(elem,
						  SND_MIXER_SCHN_FRONT_LEFT,
						  &level);
	if (err < 0) {
		error.Format(alsa_mixer_domain, err,
			     "failed to read ALSA volume: %s",
			     snd_strerror(err));
		return false;
	}

	ret = ((volume_set / 100.0) * (volume_max - volume_min)
	       + volume_min) + 0.5;
	if (volume_set > 0 && ret == level) {
		ret = volume_set;
	} else {
		ret = (int)(100 * (((float)(level - volume_min)) /
				   (volume_max - volume_min)) + 0.5);
	}

	return ret;
}

static int
alsa_mixer_get_volume(Mixer *mixer, Error &error)
{
	AlsaMixer *am = (AlsaMixer *)mixer;
	return am->GetVolume(error);
}

inline bool
AlsaMixer::SetVolume(unsigned volume, Error &error)
{
	float vol;
	long level;
	int err;

	assert(handle != NULL);

	vol = volume;

	volume_set = vol + 0.5;

	level = (long)(((vol / 100.0) * (volume_max - volume_min) +
			volume_min) + 0.5);
	level = level > volume_max ? volume_max : level;
	level = level < volume_min ? volume_min : level;

	err = snd_mixer_selem_set_playback_volume_all(elem, level);
	if (err < 0) {
		error.Format(alsa_mixer_domain, err,
			     "failed to set ALSA volume: %s",
			     snd_strerror(err));
		return false;
	}

	return true;
}

static bool
alsa_mixer_set_volume(Mixer *mixer, unsigned volume, Error &error)
{
	AlsaMixer *am = (AlsaMixer *)mixer;
	return am->SetVolume(volume, error);
}

const struct mixer_plugin alsa_mixer_plugin = {
	alsa_mixer_init,
	alsa_mixer_finish,
	alsa_mixer_open,
	alsa_mixer_close,
	alsa_mixer_get_volume,
	alsa_mixer_set_volume,
	true,
};
