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
#include "MikmodDecoderPlugin.hxx"
#include "DecoderAPI.hxx"
#include "tag/TagHandler.hxx"
#include "system/FatalError.hxx"

#include <glib.h>
#include <mikmod.h>
#include <assert.h>

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "mikmod"

/* this is largely copied from alsaplayer */

static constexpr size_t MIKMOD_FRAME_SIZE = 4096;

static BOOL
mikmod_mpd_init(void)
{
	return VC_Init();
}

static void
mikmod_mpd_exit(void)
{
	VC_Exit();
}

static void
mikmod_mpd_update(void)
{
}

static BOOL
mikmod_mpd_is_present(void)
{
	return true;
}

static char drv_name[] = PACKAGE_NAME;
static char drv_version[] = VERSION;

#if (LIBMIKMOD_VERSION > 0x030106)
static char drv_alias[] = PACKAGE;
#endif

static MDRIVER drv_mpd = {
	nullptr,
	drv_name,
	drv_version,
	0,
	255,
#if (LIBMIKMOD_VERSION > 0x030106)
	drv_alias,
#if (LIBMIKMOD_VERSION >= 0x030200)
	nullptr,  /* CmdLineHelp */
#endif
	nullptr,  /* CommandLine */
#endif
	mikmod_mpd_is_present,
	VC_SampleLoad,
	VC_SampleUnload,
	VC_SampleSpace,
	VC_SampleLength,
	mikmod_mpd_init,
	mikmod_mpd_exit,
	nullptr,
	VC_SetNumVoices,
	VC_PlayStart,
	VC_PlayStop,
	mikmod_mpd_update,
	nullptr,
	VC_VoiceSetVolume,
	VC_VoiceGetVolume,
	VC_VoiceSetFrequency,
	VC_VoiceGetFrequency,
	VC_VoiceSetPanning,
	VC_VoiceGetPanning,
	VC_VoicePlay,
	VC_VoiceStop,
	VC_VoiceStopped,
	VC_VoiceGetPosition,
	VC_VoiceRealVolume
};

static unsigned mikmod_sample_rate;

static bool
mikmod_decoder_init(const config_param &param)
{
	static char params[] = "";

	mikmod_sample_rate = param.GetBlockValue("sample_rate", 44100u);
	if (!audio_valid_sample_rate(mikmod_sample_rate))
		FormatFatalError("Invalid sample rate in line %d: %u",
				 param.line, mikmod_sample_rate);

	md_device = 0;
	md_reverb = 0;

	MikMod_RegisterDriver(&drv_mpd);
	MikMod_RegisterAllLoaders();

	md_pansep = 64;
	md_mixfreq = mikmod_sample_rate;
	md_mode = (DMODE_SOFT_MUSIC | DMODE_INTERP | DMODE_STEREO |
		   DMODE_16BITS);

	if (MikMod_Init(params)) {
		g_warning("Could not init MikMod: %s\n",
			  MikMod_strerror(MikMod_errno));
		return false;
	}

	return true;
}

static void
mikmod_decoder_finish(void)
{
	MikMod_Exit();
}

static void
mikmod_decoder_file_decode(struct decoder *decoder, const char *path_fs)
{
	char *path2;
	MODULE *handle;
	int ret;
	SBYTE buffer[MIKMOD_FRAME_SIZE];
	enum decoder_command cmd = DECODE_COMMAND_NONE;

	path2 = g_strdup(path_fs);
	handle = Player_Load(path2, 128, 0);
	g_free(path2);

	if (handle == nullptr) {
		g_warning("failed to open mod: %s", path_fs);
		return;
	}

	/* Prevent module from looping forever */
	handle->loop = 0;

	const AudioFormat audio_format(mikmod_sample_rate, SampleFormat::S16, 2);
	assert(audio_format.IsValid());

	decoder_initialized(decoder, audio_format, false, 0);

	Player_Start(handle);
	while (cmd == DECODE_COMMAND_NONE && Player_Active()) {
		ret = VC_WriteBytes(buffer, sizeof(buffer));
		cmd = decoder_data(decoder, nullptr, buffer, ret, 0);
	}

	Player_Stop();
	Player_Free(handle);
}

static bool
mikmod_decoder_scan_file(const char *path_fs,
			 const struct tag_handler *handler, void *handler_ctx)
{
	char *path2 = g_strdup(path_fs);
	MODULE *handle = Player_Load(path2, 128, 0);

	if (handle == nullptr) {
		g_free(path2);
		g_debug("Failed to open file: %s", path_fs);
		return false;

	}

	Player_Free(handle);

	char *title = Player_LoadTitle(path2);
	g_free(path2);

	if (title != nullptr) {
		tag_handler_invoke_tag(handler, handler_ctx,
				       TAG_TITLE, title);
#if (LIBMIKMOD_VERSION >= 0x030200)
		MikMod_free(title);
#else
		free(title);
#endif
	}

	return true;
}

static const char *const mikmod_decoder_suffixes[] = {
	"amf",
	"dsm",
	"far",
	"gdm",
	"imf",
	"it",
	"med",
	"mod",
	"mtm",
	"s3m",
	"stm",
	"stx",
	"ult",
	"uni",
	"xm",
	nullptr
};

const struct decoder_plugin mikmod_decoder_plugin = {
	"mikmod",
	mikmod_decoder_init,
	mikmod_decoder_finish,
	nullptr,
	mikmod_decoder_file_decode,
	mikmod_decoder_scan_file,
	nullptr,
	nullptr,
	mikmod_decoder_suffixes,
	nullptr,
};
