/*
 * Copyright 2014 Fraunhofer FOKUS
 * Copyright 2015 Linaro LtD
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <sys/signal.h>
#include <sys/time.h>

#include <fstream>
#include <iostream>
#include <map>
#include <thread>
#include <string>
#include <vector>

#include "cdmi.h"
#include "cdmi-log.h"
#include "shmemsem/shmemsem_helper.h"

#ifdef CFG_SECURE_DATA_PATH
#include "socket_server_helper.h"
#endif

extern "C" {
#include "opencdm_xdr.h"
#include "opencdm_callback.h"
}



USE_NAMESPACE_OCDM()

using namespace std;

/* Compare operator for std::map */
struct cmp_char
{
  bool operator()(char const *a, char const *b)
    {
      return strcmp(a, b) < 0;
    }
};

IMediaKeys *g_pMediaKeys = NULL;

map<const char*, IMediaKeySession*, cmp_char> g_mediaKeySessions;

// TODO(fhg): get rid of more globals
vector<IMediaEngineSession *> g_mediaEngineSessions;
char g_hostname[256];
u_long g_pnum;  // program number for callback routine

void doCallback(int, string, int, const char*, const char*);


class CCallback : public IMediaKeySessionCallback {
 public:
  CCallback(const IMediaKeySession *fp_mediaKeySession) {
    m_mediaKeySession = const_cast<IMediaKeySession *>(fp_mediaKeySession);
  }

  virtual ~CCallback(void) {}

  virtual void OnKeyMessage(
      const uint8_t *pbKeyMessage,
      uint32_t cbKeyMessage,
      char *f_pszUrl) {

    string message;

    CDMI_DLOG() << "Key Message received:"
        << std::string((char*) pbKeyMessage, cbKeyMessage);

    message =  std::string((const char*) pbKeyMessage, cbKeyMessage);

    doCallback(ON_MESSAGE, message.c_str(), CDMi_SUCCESS, m_mediaKeySession->GetSessionId(), f_pszUrl);
  }

  virtual void OnKeyReady(void) {
    CDMI_DLOG() << "OnKeyReady: Key is ready.";
    doCallback(ON_READY, "", 0, m_mediaKeySession->GetSessionId(), NULL);
  }

  virtual void OnKeyError(int16_t f_nError, CDMi_RESULT error) {
    CDMI_DLOG() << "Key error is detected: " << error;
    doCallback(ON_ERROR, "", error, m_mediaKeySession->GetSessionId(), NULL);
  }

  virtual void OnKeyStatusUpdate(const char* keyMessage) {
    doCallback(ON_KEY_STATUS_UPDATE, keyMessage, 0, m_mediaKeySession->GetSessionId(), NULL);
 }

 private:
  IMediaKeySession *m_mediaKeySession;
};


rpc_response_generic* rpc_open_cdm_is_type_supported_1_svc(
    rpc_request_is_type_supported *type, struct svc_req *) {
  static CDMi_RESULT cr = CDMi_SUCCESS;
  rpc_response_generic *response =
      reinterpret_cast<rpc_response_generic*>(
      malloc(sizeof(rpc_response_generic)));

  CDMI_DLOG() << "#rpc_open_cdm_is_type_supported_1_svc: "
       << type->key_system.key_system_val ;
  if (g_pMediaKeys) {
    cr = g_pMediaKeys->IsTypeSupported(
      reinterpret_cast<char *>(type->mime_type.mime_type_val),
       reinterpret_cast<char *>(type->key_system.key_system_val));
  } else {
    cr = CDMi_S_FALSE;
  }

  response->platform_val = cr;
  return response;
}

rpc_response_generic* rpc_open_cdm_mediakeys_1_svc(
  rpc_request_mediakeys *keysystem, struct svc_req *) {
  static CDMi_RESULT cr = CDMi_S_FALSE;
  rpc_response_generic *response =
      reinterpret_cast<rpc_response_generic*>(
      malloc(sizeof(rpc_response_generic)));

  CDMI_DLOG() << "#rpc_open_cdm_mediakeys_1_svc: "
       << keysystem->key_system.key_system_val;
  cr = CreateMediaKeys(&g_pMediaKeys);

  response->platform_val = cr;
  return response;
}

rpc_response_create_session* rpc_open_cdm_mediakeys_create_session_1_svc(
  rpc_request_create_session *sessionmessage, struct svc_req *) {
  static CDMi_RESULT cr = CDMi_S_FALSE;
  static rpc_response_create_session *response =
      reinterpret_cast<rpc_response_create_session*>(
      calloc(1, sizeof(rpc_response_create_session)));

  IMediaKeySessionCallback *callback = NULL;
  char *dst, *lic;

  // callback_info for info on how to rpc callback into browser
  CDMI_DLOG() << "#open_cdm_mediakeys_create_session_1_svc: prog num: "
       <<  sessionmessage->callback_info.prog_num ;

  g_pnum = sessionmessage->callback_info.prog_num;

  if (g_pMediaKeys) {
    IMediaKeySession *p_mediaKeySession;
    cr = g_pMediaKeys->CreateMediaKeySession(
        sessionmessage->init_data_type.init_data_type_val,
        sessionmessage->init_data.init_data_val,
        sessionmessage->init_data.init_data_len,
        NULL,
        0,
        &p_mediaKeySession);

    if (cr == CDMi_SUCCESS) {
      const char *sid = p_mediaKeySession->GetSessionId();
      uint32_t sid_size = strlen(sid);
      g_mediaKeySessions[sid] = p_mediaKeySession;
      dst = reinterpret_cast<char*>(malloc(sizeof(char) * sid_size));

      strncpy(dst, sid, sid_size);
      response->session_id.session_id_val = dst;
      response->session_id.session_id_len = sid_size;

      callback = new CCallback(p_mediaKeySession);
      // generates challenge
      lic = p_mediaKeySession->RunAndGetLicenceChallange(callback);
      if(lic) {
        CDMI_WLOG() << "License :" << lic ;
        /* Free old response */
        if(response->licence_req.licence_req_val)
          free(response->licence_req.licence_req_val);

        response->licence_req.licence_req_len = strlen(lic);
        response->licence_req.licence_req_val = lic;
      } else {
        CDMI_ELOG() << "Failed obtain license from CDMI";
        cr = CDMi_S_FALSE;
      }

    }  else {
      CDMI_ELOG() << "Failed to create session" ;
    }
  }
  response->platform_val = cr;
  return response;
}

rpc_response_generic* rpc_open_cdm_mediakeys_load_session_1_svc(
  rpc_request_load_session *params, struct svc_req *) {
  return NULL;  // TODO(fhg): NYI
}

rpc_response_generic* rpc_open_cdm_mediakeysession_update_1_svc(
  rpc_request_session_update *params, struct svc_req *) {
  static CDMi_RESULT cr = CDMi_SUCCESS;
  std::string sid;

  rpc_response_generic *response =
      reinterpret_cast<rpc_response_generic*>(
      malloc(sizeof(rpc_response_generic)));
  IMediaKeySession *p_mediaKeySession;

  sid = std::string((char*) params->session_id.session_id_val, params->session_id.session_id_len);
  p_mediaKeySession = g_mediaKeySessions[sid.c_str()];

  if (p_mediaKeySession) {
    p_mediaKeySession->Update(params->key.key_val,
        params->key.key_len);
    cr = CDMi_SUCCESS;
  } else {
    CDMI_ELOG() << "no session found for session id: " << sid ;
    cr = CDMi_S_FALSE;
  }

  response->platform_val = cr;
  return response;
}

rpc_response_generic* rpc_open_cdm_mediakeysession_release_1_svc(
  rpc_request_session_release *params, struct svc_req *) {

  CDMI_DLOG() << "#open_cdm_mediakeysession_release_1_svc ";

  static CDMi_RESULT cr = CDMi_SUCCESS;

  rpc_response_generic *response =
      reinterpret_cast<rpc_response_generic*>(
      malloc(sizeof(rpc_response_generic)));
  IMediaKeySession *p_mediaKeySession;

  std::string sid = std::string(params->session_id.session_id_val, params->session_id.session_id_len);
  p_mediaKeySession = g_mediaKeySessions[sid.c_str()];

  if (p_mediaKeySession) {
    p_mediaKeySession->Close();
    g_mediaKeySessions.erase(params->session_id.session_id_val);
    g_pMediaKeys->DestroyMediaKeySession(p_mediaKeySession);
    cr = CDMi_SUCCESS;
  } else {
    cr = CDMi_S_FALSE;
  }

  response->platform_val = cr;
  return response;
}


void decryptShmem(unsigned int idxMES, int idXchngSem, int idXchngShMem, int idSocketChannel) {
#ifdef CFG_SECURE_DATA_PATH
  SocketServer socketServer;
#endif
  int secureFd = -1;
  uint32_t secureMemSize = 0;
  
  shmem_info *mesShmem;
  IMediaEngineSession *pMediaEngineSession = NULL;
  mesShmem = (shmem_info *) MapSharedMemory(idXchngShMem);

#ifdef CFG_SECURE_DATA_PATH
  // Establish connection to transfer the secure file descriptor.
  if(socketServer.Connect(idSocketChannel) < 0) {
    return;
  }
#endif

  for (;;) {

    CDMi_RESULT cr;
    if (g_mediaEngineSessions.size() -1 < idxMES) {
      CDMI_ELOG() << "decryptShmem: invalid media engine session idx: "
           << idxMES;
      cr = CDMi_S_FALSE;
      break;
    }

    pMediaEngineSession = g_mediaEngineSessions.at(idxMES);

    if (pMediaEngineSession == NULL) {
      CDMI_ELOG() << "decryptShmem: no valid media engine session found";
      cr = CDMi_S_FALSE;
      break;
    } else {
      /*
       * TODO: (init, on create mes)
       *  1. transfer id of static info shmem (from client to cdmi)
       *  2. associate with mes
       *
       * TODO:
       *  1. get both shmems for corresponding media engine
       *  2. wait for access (lock)
       *  3. get size and shmem id from static shmem
       *  4. get dynamic shmem with sampledata
       *  5. decrypt inplace
       *  6. unlock both shmem
       *
       *  HOWTO: reach end of loop, signaling end of segment?
       */

      // lock own semaphore to get data
      LockSemaphore(idXchngSem, SEM_XCHNG_DECRYPT);

      if (mesShmem->idIvShMem == 0
          && mesShmem->idSampleShMem == 0
          && mesShmem->ivSize == 0
          && mesShmem->sampleSize == 0) {
        DetachExistingSharedMemory(mesShmem);

        UnlockSemaphore(idXchngSem, SEM_XCHNG_PULL);
        break;
      }

      uint8_t *mem_iv = (uint8_t *) MapSharedMemory(mesShmem->idIvShMem);
      uint8_t *mem_sample = (uint8_t *) MapSharedMemory(mesShmem->idSampleShMem);

      uint32_t *mem_subsample_data = NULL;
      uint32_t subsample_count = mesShmem->subsampleDataSize / sizeof(uint32_t);
      if(subsample_count > 0) {
        /* When available, map the sub-sample data. */
        mem_subsample_data = (uint32_t *) MapSharedMemory(mesShmem->idSubsampleDataShMem);
        if(mem_subsample_data == NULL) {
          CDMI_ELOG() << "decryptShmem: Cannot map subsample data";
          cr = CDMi_S_FALSE;
          goto handle_error;
        }
      }

      static uint32_t clear_content_size = 0;
      static uint8_t* clear_content = NULL;
      /* FIXME: Releasing needs to be implemented using a separate
       *  IPC call. Currently we assume that the previous decrypted clear
       *  data is consumed when the Decrypt() called again.
       */
      if(clear_content)
        pMediaEngineSession->ReleaseClearContent(clear_content_size, clear_content);

#ifdef CFG_SECURE_DATA_PATH
      /* Get secure file descriptor. */
      if(socketServer.ReceiveFileDescriptor(secureFd, secureMemSize) < 0) {
        cr = CDMi_S_FALSE;
        goto handle_error;
      }
#endif

      cr = pMediaEngineSession->Decrypt(
          subsample_count,          //number of subsamples
          mem_subsample_data,       //subsamples (optional)
          mesShmem->ivSize,
          mem_iv,
          mesShmem->sampleSize,
          mem_sample,
          &clear_content_size,
          &clear_content,
          secureMemSize,
          secureFd);
      if(cr!=CDMi_SUCCESS)
        CDMI_ELOG() << "Failed to decrypt sample. Error:" << cr;

#ifndef CFG_SECURE_DATA_PATH
      // FIXME: opencdm uses a single buffer for passing the
      //  encrypted and decrypted buffer. Due to this we need an
      //  additional memcpy
      if(clear_content_size != mesShmem->sampleSize)
         CDMI_WLOG() << "Warning: returned clear sample size " << clear_content_size <<
          "differs from encrypted " <<
          "buffer size"  << mesShmem->sampleSize;

      memcpy(mem_sample, clear_content, MIN(mesShmem->sampleSize, clear_content_size) );
#endif

handle_error:
#ifdef CFG_SECURE_DATA_PATH
      socketServer.CloseFileDescriptor(secureFd);
      secureFd = -1;
#endif

      // detach all shared memories!
      DetachExistingSharedMemory(mem_iv);
      DetachExistingSharedMemory(mem_sample);
      if(mem_subsample_data != NULL) DetachExistingSharedMemory(mem_subsample_data);

      // unlock that clnt knows about finished decryption
      UnlockSemaphore(idXchngSem, SEM_XCHNG_PULL);
    }
  }
#ifdef CFG_SECURE_DATA_PATH
  socketServer.Disconnect();
#endif
}

rpc_response_create_mediaengine_session* rpc_open_cdm_mediaengine_1_svc(
  rpc_request_mediaengine_data *params, struct svc_req *) {
  static CDMi_RESULT cr = CDMi_S_FALSE;
  rpc_response_create_mediaengine_session *response =
      reinterpret_cast<rpc_response_create_mediaengine_session*>(
      calloc(1, sizeof(rpc_response_create_mediaengine_session)));
  IMediaKeySession *p_mediaKeySession;
  IMediaEngineSession *pMediaEngineSession = NULL;

  CDMI_DLOG() << "#cdm_mediaenginesession_rpc_1_svc: "
      << params->id_exchange_shmem << " "
      << params->id_exchange_sem;

#ifdef CFG_SECURE_DATA_PATH
  response->socket_channel_id = SocketServer::GetUniqueId();
  CDMI_DLOG() << "Unique socket channel ID is " << response->socket_channel_id;
#else
  response->socket_channel_id = 0; // Only used by SDP implementation.
#endif

  std::string sid = std::string(params->session_id.session_id_val, params->session_id.session_id_len);

  p_mediaKeySession = g_mediaKeySessions[sid.c_str()];
  cr = CreateMediaEngineSession(p_mediaKeySession,
      &pMediaEngineSession);

  if (cr == CDMi_SUCCESS) {
    g_mediaEngineSessions.push_back(pMediaEngineSession);
    thread t(decryptShmem,
        g_mediaEngineSessions.size() - 1,
        params->id_exchange_sem,
        params->id_exchange_shmem,
        response->socket_channel_id);
    t.detach();
  } else {
    CDMI_ELOG() << "MediaEngineSession create failed!";
  }

  response->platform_val = cr;
  return response;
}

void doCallback(
    int eventType,
    string message = "",
    int error = 0,
    const char *sid = NULL, 
    const char *f_pszUrl = NULL) {
  CLIENT *clnt;

  gethostname(g_hostname, sizeof(g_hostname));

  CDMI_DLOG() << "#doCallback: eventType: " <<  eventType;
  CDMI_DLOG() << "#doCallback: hostname: " << g_hostname;
  CDMI_DLOG() << "#doCallback: prog num: " <<  g_pnum;
  if ((clnt = clnt_create(g_hostname, g_pnum, 1, "tcp")) == NULL) {
    CDMI_ELOG() << "service: doCallback: clnt_create";
    clnt_pcreateerror(g_hostname);
    exit(2);
  }

  const char *temp_message = message.c_str();

  int sid_size = strlen(sid);

  char *dst = new char[sid_size];
  memcpy(dst, sid, sid_size);

  switch (eventType) {
    case ON_MESSAGE:
      rpc_cb_message km;
      km.session_id.session_id_len = sid_size;
      km.session_id.session_id_val = dst;
      km.destination_url = const_cast<char*>(f_pszUrl);
      km.message = const_cast<char*>(temp_message);
      on_message_1(&km, clnt);
      break;

    case ON_READY:
      rpc_cb_ready kr;
      kr.session_id.session_id_len = sid_size;
      kr.session_id.session_id_val = dst;
      on_ready_1(&kr, clnt);
      break;

    case ON_ERROR:
      rpc_cb_error ke;
      ke.session_id.session_id_len = sid_size;
      ke.session_id.session_id_val = dst;
      on_error_1(&ke, clnt);
      break;

    case ON_KEY_STATUS_UPDATE:
      rpc_cb_key_status_update  msg;
      msg.session_id.session_id_len = sid_size;
      msg.session_id.session_id_val = dst;
      msg.message = const_cast<char*>(temp_message);
      on_key_status_update_1(&msg, clnt);
      break;
    default:
      CDMI_ELOG() << "doCallback: unknown eventType" ;
    }
    delete[] dst;
}
