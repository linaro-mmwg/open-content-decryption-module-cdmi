/*
 * Copyright 2014 Fraunhofer FOKUS
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

#include <pthread.h>
#include <assert.h>
#include <iostream>
#include <string>
#include <string.h>
#include <sstream>

#include "imp.h"
#include "json_web_key.h"
#include "keypairs.h"
#include "cdmi-log.h"

#define DESTINATION_URL_PLACEHOLDER ""

#define NYI_KEYSYSTEM "keysystem-placeholder"
#ifndef USE_AES_TA
#include <openssl/aes.h>
#include <openssl/evp.h>
#else
extern "C" {
#include <aes_crypto.h>
}
#endif

#define kDecryptionKeySize 16

#define kPersistentLicenceRequest "\
{\
    'kids':\
    [\
    'LwVHf8JLtPrv2GUXFW2v',\
    ],\
    'type':\"persistent-license\"}"

#ifdef USE_AES_TA
/* Map between OP TEE TA and OpenSSL */
#define AES_BLOCK_SIZE CTR_AES_BLOCK_SIZE
#endif
using namespace std;

BEGIN_NAMESPACE_OCDM()

static media::KeyIdAndKeyPairs g_keys;
static int tee_session_initialized = 0;

static void hex_print(const void* pv, size_t len)
{
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i<len;++i)
            printf("%02X ", *p++);
    }
    printf("\n");
}

static std::string keyIdAndKeyPairsToJSON(media::KeyIdAndKeyPairs *g_keys) {
    /* FIXME: This JSON consturctor is for proof of concept only.
     * We need to add a proper JSON library.
     */
    ostringstream result;
    result << "{ ";
    for(std::vector<media::KeyIdAndKeyPair>::iterator it = g_keys->begin();
            it!=g_keys->end(); ++it)
    {
      result <<  "\""  << it->first  << "\" : \"" << MEDIA_KEY_STATUS_USABLE << "\"\n";
    }
    result  << "}";
    return result.str();
}

CMediaKeySession::CMediaKeySession(const char *sessionId) : m_piCallback(NULL) {
  m_sessionId = sessionId;
  CDMI_DLOG() << "creating mediakeysession with id: " << m_sessionId << endl;
}

CMediaKeySession::~CMediaKeySession(void) {}

char* CMediaKeySession::RunAndGetLicenceChallange(
    const IMediaKeySessionCallback *f_piMediaKeySessionCallback) {
  int err;
  char* result;
  pthread_t thread;

  CDMI_DLOG() << "#mediakeysession.Run" << endl;

  if (f_piMediaKeySessionCallback != NULL) {
    m_piCallback = const_cast<IMediaKeySessionCallback *>(f_piMediaKeySessionCallback);

    err = pthread_create(&thread, NULL, CMediaKeySession::_CallRunThread, this);
    if (err == 0) {
      pthread_detach(thread);
    } else {
      CDMI_ELOG() << "#mediakeysession.Run: err: could not create thread" << endl;
      return NULL;
    }
  } else {
    CDMI_ELOG() << "#mediakeysession.Run: err: MediaKeySessionCallback NULL" << endl;
  }
  result = (char*) malloc(sizeof(char) * (strlen(kPersistentLicenceRequest) + 1));
  strncpy(result, kPersistentLicenceRequest, strlen(kPersistentLicenceRequest));
  return result;
}

void* CMediaKeySession::_CallRunThread(void *arg) {
  return ((CMediaKeySession*)arg)->RunThread(1);
}

void* CMediaKeySession::_CallRunThread2(void *arg) {
  return ((CMediaKeySession*)arg)->RunThread(2);
}

void* CMediaKeySession::RunThread(int i) {
  CDMI_DLOG() << "#mediakeysession._RunThread : " << i << endl;

  if(!m_piCallback) {
    CDMI_ELOG() << "Callback function not set" <<endl;
    return NULL;
  }

  if (i == 1) {
    m_piCallback->OnKeyMessage(NULL, 0, const_cast<char*>(DESTINATION_URL_PLACEHOLDER));
  } else {
//    m_piCallback->OnKeyReady();
  }
}

void CMediaKeySession::Update(
    const uint8_t *f_pbKeyMessageResponse,
    uint32_t f_cbKeyMessageResponse) {
  int ret;
  pthread_t thread;
  std::string keys_updated;

  CDMI_DLOG() << "#mediakeysession.Run" << endl;
  std::string key_string(reinterpret_cast<const char*>(f_pbKeyMessageResponse),
                                   f_cbKeyMessageResponse);
  //Session type is set to "0". We keep the function signature to
  //match Chromium's ExtractKeysFromJWKSet(...) function
  media::ExtractKeysFromJWKSet(key_string, &g_keys, 0);

  ret = pthread_create(&thread, NULL, CMediaKeySession::_CallRunThread2, this);
  if (ret == 0) {
    pthread_detach(thread);
  } else {
    CDMI_ELOG() << "#mediakeysession.Run: err: could not create thread" << endl;
    return;
  }
  keys_updated = keyIdAndKeyPairsToJSON(&g_keys);
  m_piCallback->OnKeyStatusUpdate(key_string.c_str());
}

void CMediaKeySession::Close(void) {
#ifdef USE_AES_TA
  tee_session_initialized--;
  if(tee_session_initialized == 0)
    TEE_crypto_close();
#endif
}

const char *CMediaKeySession::GetSessionId(void) const {
  return m_sessionId;
}

const char *CMediaKeySession::GetKeySystem(void) const {
  // TODO(fhg):
  return NYI_KEYSYSTEM;
}

CDMi_RESULT CMediaKeySession::Init(
    const uint8_t *f_pbInitData,
    uint32_t f_cbInitData,
    const uint8_t *f_pbCDMData,
    uint32_t f_cbCDMData) {
#ifdef USE_AES_TA
   if(!tee_session_initialized) {
     TEE_crypto_init();
   }
   tee_session_initialized++;
#endif
  return CDMi_SUCCESS;
}

// Decrypt is not an IMediaKeySession interface method therefore it can only be
// accessed from code that has internal knowledge of CMediaKeySession.
CDMi_RESULT CMediaKeySession::Decrypt(
      const uint8_t *f_pbSessionKey,
      uint32_t f_cbSessionKey,
      const uint32_t *f_pdwSubSampleMapping,
      uint32_t f_cdwSubSampleMapping,
      const uint8_t *f_pbIV,
      uint32_t f_cbIV,
      const uint8_t *f_pbData,
      uint32_t f_cbData,
      uint32_t *f_pcbOpaqueClearContent,
      uint8_t **f_ppbOpaqueClearContent) {


  uint8_t * out; /* Faked secure buffer */
  const char * key;

  uint8_t ivec[AES_BLOCK_SIZE] = { 0 };
  uint8_t ecount_buf[AES_BLOCK_SIZE] = { 0 };
  unsigned int block_offset = 0;


  assert(f_cbIV <  AES_BLOCK_SIZE);

  if(f_pcbOpaqueClearContent == NULL) {
    CDMI_ELOG() << "ERROR: f_pcbOpaqueClearContent is NULL" << endl;
    return -1;
  }

  out = (uint8_t*) malloc(f_cbData * sizeof(uint8_t));

  if(g_keys.size() != 1) {
        CDMI_DLOG() << "FIXME: We support only one key at the moment. Number keys: " << g_keys.size()<< endl;
    }

  if ( (g_keys[0].second).size() != kDecryptionKeySize) {
    CDMI_ELOG() << "ERROR: Wrong key size" << endl;
    goto fail;
  }

  key = (g_keys[0].second).data();

#ifndef USE_AES_TA
  AES_KEY aes_key;
  AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key),
                          strlen(key) * 8, &aes_key) ;
#endif

  memcpy(&(ivec[0]), f_pbIV, f_cbIV);

#ifndef USE_AES_TA
  AES_ctr128_encrypt(reinterpret_cast<const unsigned char*>(f_pbData), out,
                     f_cbData, &aes_key, ivec, ecount_buf, &block_offset);
#else
  if(TEE_AES_ctr128_encrypt(reinterpret_cast<const unsigned char*>(f_pbData),
                     out, f_cbData, key,
                     ivec, ecount_buf, &block_offset) !=0) {
      CDMI_ELOG() << "ERROR: AES CTR128 Decryption failed\n";
      goto fail;
  }
#endif

  /* Return clear content */
  *f_pcbOpaqueClearContent = f_cbData;
  *f_ppbOpaqueClearContent = out;

  return CDMi_SUCCESS;
fail:
   free(out);
   return -1;
}

CDMi_RESULT CMediaKeySession::ReleaseClearContent(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t  f_cbClearContentOpaque,
        uint8_t  *f_pbClearContentOpaque ){
    free(f_pbClearContentOpaque);
  }
END_NAMESPACE_OCDM()
