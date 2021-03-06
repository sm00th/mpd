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
#include "RpiOutputPlugin.hxx"
#include "OutputAPI.hxx"

#include <glib.h>

#include "bcm_host.h"
#include "IL/OMX_Types.h"
#include "IL/OMX_Core.h"
#include "IL/OMX_Component.h"
#include "IL/OMX_Broadcom.h"

#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "rpi"

#define BUFFER_SIZE_SAMPLES 1024

#define OMX_INIT_STRUCTURE(a) \
  memset(&(a), 0, sizeof(a)); \
  (a).nSize = sizeof(a); \
  (a).nVersion.s.nVersionMajor = OMX_VERSION_MAJOR; \
  (a).nVersion.s.nVersionMinor = OMX_VERSION_MINOR; \
  (a).nVersion.s.nRevision = OMX_VERSION_REVISION; \
  (a).nVersion.s.nStep = OMX_VERSION_STEP

struct RpiOutput {
	struct audio_output base;

	const char *device_name;
	OMX_HANDLETYPE m_render;
	unsigned int   m_input_port;
	GMutex         buffer_lock;
	GList*         input_buffer_list;
	GList*         input_buffers_avail;
	uint8_t        num_buffers_avail;

	bool Initialize(const config_param &param, Error &error_r) {
		return ao_base_init(&base, &rpi_output_plugin, param,
				    error_r);
	}

	void Deinitialize() {
		ao_base_finish(&base);
	}
};

static OMX_ERRORTYPE rpi_event_handler_callback(
		G_GNUC_UNUSED OMX_HANDLETYPE hComponent, G_GNUC_UNUSED OMX_PTR pAppData,
		G_GNUC_UNUSED OMX_EVENTTYPE eEvent, G_GNUC_UNUSED OMX_U32 nData1,
		G_GNUC_UNUSED OMX_U32 nData2, G_GNUC_UNUSED OMX_PTR pEventData)
{
	return OMX_ErrorNone;
}

static OMX_ERRORTYPE rpi_empty_buffer_done_callback(
		G_GNUC_UNUSED OMX_HANDLETYPE hComponent,
		OMX_PTR pAppData, OMX_BUFFERHEADERTYPE* pBuffer)
{
	RpiOutput *od = (RpiOutput *)pAppData;
	g_mutex_lock(&od->buffer_lock);
	od->input_buffers_avail = g_list_append(od->input_buffers_avail, pBuffer);
	od->num_buffers_avail++;
	g_mutex_unlock(&od->buffer_lock);
	return OMX_ErrorNone;
}

static OMX_ERRORTYPE rpi_fill_buffer_done_callback(
		G_GNUC_UNUSED OMX_HANDLETYPE hComponent, G_GNUC_UNUSED OMX_PTR pAppData,
		G_GNUC_UNUSED OMX_BUFFERHEADERTYPE* pBuffer)
{
	return OMX_ErrorNone;
}

static bool m_get_handle(OMX_HANDLETYPE *handle, OMX_STRING name,
		OMX_PTR prData, OMX_CALLBACKTYPE *callbacks)
{
	OMX_ERRORTYPE omx_err;

	omx_err = OMX_GetHandle(handle, name, prData, callbacks);
	if (!handle || omx_err != OMX_ErrorNone) {
		g_error("could not get handle for %s omx_err(0x%08x)\n", name, omx_err);
		return false;
	}
	return true;
}

static bool m_get_param(OMX_HANDLETYPE handle, OMX_INDEXTYPE idx,
		OMX_PTR param)
{
	OMX_ERRORTYPE omx_err;

	omx_err = OMX_GetParameter(handle, idx, param);
	if (omx_err != OMX_ErrorNone) {
		g_warning("could not get parameter 0x%08x omx_err(0x%08x)\n", idx,
				omx_err);
		return false;
	}
	return true;
}

static bool m_set_param(OMX_HANDLETYPE handle, OMX_INDEXTYPE idx,
		OMX_PTR param)
{
	OMX_ERRORTYPE omx_err;

	omx_err = OMX_SetParameter(handle, idx, param);
	if (omx_err != OMX_ErrorNone) {
		g_warning("could not set parameter 0x%08x omx_err(0x%08x)\n", idx,
				omx_err);
		return false;
	}
	return true;
}

/* Unused for now
static bool m_get_config(OMX_HANDLETYPE handle, OMX_INDEXTYPE idx,
		OMX_PTR cfg)
{
	OMX_ERRORTYPE omx_err;

	omx_err = OMX_GetConfig(handle, idx, cfg);
	if (omx_err != OMX_ErrorNone) {
		g_warning("could not set config 0x%08x omx_err(0x%08x)\n", idx, omx_err);
		return false;
	}
	return true;
}
*/

static bool m_set_config(OMX_HANDLETYPE handle, OMX_INDEXTYPE idx,
		OMX_PTR cfg)
{
	OMX_ERRORTYPE omx_err;

	omx_err = OMX_SetConfig(handle, idx, cfg);
	if (omx_err != OMX_ErrorNone) {
		g_warning("could not set config 0x%08x omx_err(0x%08x)\n", idx, omx_err);
		return false;
	}
	return true;
}

static bool m_send_cmd(OMX_HANDLETYPE handle, OMX_COMMANDTYPE cmd,
		OMX_U32 param)
{
	OMX_ERRORTYPE omx_err;

	omx_err = OMX_SendCommand(handle, cmd, param, NULL);
	if (omx_err != OMX_ErrorNone) {
		g_warning("failed to send command %d(%d) omx_err(0x%08x)\n", cmd, param,
				omx_err);
		return false;
	}
	return true;
}

static struct audio_output *
rpi_init(const config_param &param, Error &error)
{
	RpiOutput *od = new RpiOutput();
	od->device_name = param.GetBlockValue("device");
	od->input_buffer_list = g_list_alloc();
	od->input_buffers_avail = g_list_alloc();
	od->num_buffers_avail = 0;
	g_mutex_init(&od->buffer_lock);

	if (!od->Initialize(param, error)) {
		delete od;
		return nullptr;
	}

	return &od->base;
}

static void
rpi_finish(struct audio_output *ao)
{
	RpiOutput *od = (RpiOutput *)ao;

	od->Deinitialize();

	g_list_free(od->input_buffer_list);
	g_list_free(od->input_buffers_avail);
	g_mutex_clear(&od->buffer_lock);
	delete od;
}

static bool
rpi_open(struct audio_output *ao, AudioFormat &audio_format,
	    G_GNUC_UNUSED Error &error)
{
	RpiOutput *od = (RpiOutput *)ao;
	uint8_t i, j;
	char render[] = "OMX.broadcom.audio_render";
	int buffers = 10;
	int buffer_size;
	uint8_t bitrate = 16;

	if (audio_format.format == SampleFormat::S8) /* only 8/16 are supported */
		bitrate = 8;

	buffer_size = (BUFFER_SIZE_SAMPLES * bitrate * audio_format.channels) >> 3;

	OMX_INDEXTYPE types[] = {OMX_IndexParamAudioInit, OMX_IndexParamVideoInit,
		OMX_IndexParamImageInit, OMX_IndexParamOtherInit};

	OMX_ERRORTYPE omx_err;

	OMX_CALLBACKTYPE m_callbacks;
	OMX_PORT_PARAM_TYPE port_param;
	OMX_PARAM_PORTDEFINITIONTYPE port_def;
	OMX_AUDIO_PARAM_PCMMODETYPE pcm;
	OMX_CONFIG_BRCMAUDIODESTINATIONTYPE audio_dest;

	m_callbacks.EventHandler = rpi_event_handler_callback;
	m_callbacks.EmptyBufferDone = rpi_empty_buffer_done_callback;
	m_callbacks.FillBufferDone = rpi_fill_buffer_done_callback;

	bcm_host_init();
	OMX_Init();

	if (!m_get_handle(&od->m_render, render, od, &m_callbacks)) {
		return false;
	}

	OMX_INIT_STRUCTURE(port_param);
	m_get_param(od->m_render, OMX_IndexParamAudioInit, &port_param);
	od->m_input_port = port_param.nStartPortNumber;

	OMX_INIT_STRUCTURE(port_param);
	for(i = 0; i < 4; i++) {
		if(m_get_param(od->m_render, types[i], &port_param)) {
			for(j = 0; j < port_param.nPorts; j++) {
				OMX_INIT_STRUCTURE(port_def);
				port_def.nPortIndex = port_param.nStartPortNumber + j;
				m_get_param(od->m_render, OMX_IndexParamPortDefinition, &port_def);
				if (port_def.bEnabled == OMX_FALSE) {
					continue;
				}
				m_send_cmd(od->m_render, OMX_CommandPortDisable,
						port_param.nStartPortNumber + j);
			}
		}
	}

	OMX_INIT_STRUCTURE(port_def);
	port_def.nPortIndex = od->m_input_port;
	m_get_param(od->m_render, OMX_IndexParamPortDefinition, &port_def);
	port_def.nBufferSize = buffer_size;
	port_def.nBufferCountActual = buffers;
	port_def.format.audio.eEncoding = OMX_AUDIO_CodingPCM;
	m_set_param(od->m_render, OMX_IndexParamPortDefinition, &port_def);

	OMX_INIT_STRUCTURE(pcm);
	pcm.nPortIndex         = od->m_input_port;
	pcm.eNumData           = OMX_NumericalDataSigned;
	pcm.eEndian            = OMX_EndianLittle;
	pcm.bInterleaved       = OMX_TRUE;
	pcm.ePCMMode           = OMX_AUDIO_PCMModeLinear;
	pcm.nChannels          = audio_format.channels;
	pcm.nSamplingRate      = audio_format.sample_rate;
	pcm.nBitPerSample      = bitrate;
	pcm.eChannelMapping[0] = OMX_AUDIO_ChannelLF;
	pcm.eChannelMapping[1] = OMX_AUDIO_ChannelRF;

	m_set_param(od->m_render, OMX_IndexParamAudioPcm, &pcm);

	m_send_cmd(od->m_render, OMX_CommandStateSet, OMX_StateIdle);

	OMX_INIT_STRUCTURE(port_def);
	port_def.nPortIndex = od->m_input_port;
	m_get_param(od->m_render, OMX_IndexParamPortDefinition, &port_def);
	if(port_def.bEnabled != OMX_FALSE || port_def.nBufferCountActual == 0
			|| port_def.nBufferSize == 0)
		g_warning("Failed to set buffers\n");

	m_send_cmd(od->m_render, OMX_CommandPortEnable, od->m_input_port);

	for (i = 0; i != port_def.nBufferCountActual; i++) {
		OMX_BUFFERHEADERTYPE *buffer = NULL;

		omx_err = OMX_AllocateBuffer(od->m_render, &buffer, od->m_input_port,
				NULL, port_def.nBufferSize);
		if (omx_err != OMX_ErrorNone)
			g_warning("Failed to allocate buffer %d of %d (0x%08x)\n", i,
					port_def.nBufferSize, omx_err);

		buffer->nInputPortIndex = od->m_input_port;
		buffer->nFilledLen      = 0;
		buffer->nOffset         = 0;
		g_mutex_lock(&od->buffer_lock);
		od->num_buffers_avail++;
		od->input_buffer_list   = g_list_append(od->input_buffer_list, buffer);
		od->input_buffers_avail = g_list_append(od->input_buffers_avail, buffer);
		g_mutex_unlock(&od->buffer_lock);
	}

	m_send_cmd(od->m_render, OMX_CommandStateSet, OMX_StateExecuting);

	OMX_INIT_STRUCTURE(audio_dest);
	strncpy((char *)audio_dest.sName, od->device_name, sizeof(od->device_name));
	m_set_config(od->m_render, OMX_IndexConfigBrcmAudioDestination, &audio_dest);

	return true;
}

static void
rpi_close(struct audio_output *ao)
{
	RpiOutput *od = (RpiOutput *)ao;
	GList *list_ptr = NULL;
	OMX_PARAM_PORTDEFINITIONTYPE port_def;

	m_send_cmd(od->m_render, OMX_CommandFlush, od->m_input_port);

	m_send_cmd(od->m_render, OMX_CommandStateSet, OMX_StateIdle);

	OMX_INIT_STRUCTURE(port_def);
	port_def.nPortIndex = od->m_input_port;
	m_get_param(od->m_render, OMX_IndexParamPortDefinition, &port_def);
	if(port_def.bEnabled != OMX_TRUE || port_def.nBufferCountActual == 0
			|| port_def.nBufferSize == 0) {
		g_warning("port buffer state error: enabled: %d; count: %d; size: %u\n",
				port_def.bEnabled, port_def.nBufferCountActual, port_def.nBufferSize);
		return;
	}

	m_send_cmd(od->m_render, OMX_CommandPortDisable, od->m_input_port);
	g_mutex_lock(&od->buffer_lock);
	while (od->num_buffers_avail > 0) {
		OMX_BUFFERHEADERTYPE *omx_buffer = NULL;

		list_ptr = g_list_last(od->input_buffer_list);
		omx_buffer = static_cast<OMX_BUFFERHEADERTYPE *>(list_ptr->data);
		od->input_buffer_list = g_list_remove(od->input_buffer_list, omx_buffer);
		od->input_buffers_avail = g_list_remove(od->input_buffers_avail,
				omx_buffer);
		od->num_buffers_avail--;
		OMX_FreeBuffer(od->m_render, od->m_input_port, omx_buffer);
	}
	g_mutex_unlock(&od->buffer_lock);

	m_send_cmd(od->m_render, OMX_CommandStateSet, OMX_StateLoaded);
	OMX_FreeHandle(od->m_render);

	OMX_Deinit();
	bcm_host_deinit();
}

static unsigned
rpi_delay(struct audio_output *ao)
{
	RpiOutput *od = (RpiOutput *)ao;

	return od->num_buffers_avail < 1 ? 50 : 0;
}

static size_t
rpi_play(struct audio_output *ao, const void *chunk, size_t size,
	    G_GNUC_UNUSED Error &error)
{
	RpiOutput *od = (RpiOutput *)ao;
	OMX_ERRORTYPE omx_err;
	OMX_BUFFERHEADERTYPE *omx_buffer = NULL;

	unsigned int demuxer_bytes = (unsigned int)size;
	const uint8_t *demuxer_content = static_cast<const uint8_t *>(chunk);

	while(demuxer_bytes) {
		omx_buffer =
			(OMX_BUFFERHEADERTYPE*)(g_list_last(od->input_buffers_avail)->data);
		if (omx_buffer == NULL) {
			g_warning("can't get a buffer\n");
			continue;
		}
		omx_buffer->nOffset = 0;
		omx_buffer->nFlags  = 0;
		omx_buffer->nFilledLen = (demuxer_bytes > omx_buffer->nAllocLen) ? \
			omx_buffer->nAllocLen : demuxer_bytes;
		memcpy(omx_buffer->pBuffer, demuxer_content, omx_buffer->nFilledLen);

		omx_buffer->nFlags = OMX_BUFFERFLAG_TIME_UNKNOWN;

		demuxer_bytes   -= omx_buffer->nFilledLen;
		demuxer_content += omx_buffer->nFilledLen;
		if(demuxer_bytes == 0)
			omx_buffer->nFlags |= OMX_BUFFERFLAG_ENDOFFRAME;

		omx_err = OMX_EmptyThisBuffer(od->m_render, omx_buffer);
		g_mutex_lock(&od->buffer_lock);
		od->num_buffers_avail--;
		od->input_buffers_avail = g_list_remove(od->input_buffers_avail,
				omx_buffer);
		if (omx_err != OMX_ErrorNone)
			g_warning("%s: failed to empty buffer 0x%08x\n", __func__, omx_err);
		g_mutex_unlock(&od->buffer_lock);
	}

	return size;
}

static void
rpi_cancel(G_GNUC_UNUSED struct audio_output *ao)
{
	// FIXME: logically we should flush on cancel but flushing here leads to
	// carcking sound between tracks on rpi.
	//RpiOutput *od = (RpiOutput *)ao;
	//m_send_cmd(od->m_render, OMX_CommandFlush, od->m_input_port);
}

const struct audio_output_plugin rpi_output_plugin = {
	"rpi",
	nullptr,
	rpi_init,
	rpi_finish,
	nullptr,
	nullptr,
	rpi_open,
	rpi_close,
	rpi_delay,
	nullptr,
	rpi_play,
	nullptr,
	rpi_cancel,
	nullptr,
	nullptr,
};
