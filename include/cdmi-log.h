/*
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
#ifndef OCDM_CDMI_LOG_H_
#define OCDM_CDMI_LOG_H_
#include <ostream>
#include <sstream>
#include <string>


BEGIN_NAMESPACE_OCDM()

class Voidify {
 public:
  Voidify() {}
  void operator&(std::ostream&) {}
};

class CdmiLogMessage {
 public:
  CdmiLogMessage(const char* file, int line) {
    stream_ << "[" <<file << ":" << line << "] ";
  }
  ~CdmiLogMessage() {std::cout << std::endl;}
  std::string message() { return stream_.str(); }
 private:
  std::ostringstream stream_;
};

class CdmiLogStream {
 public:
  CdmiLogStream() {}
  std::ostream& stream() { return std::cout; }
};

#define CDM_LAZY_STREAM(stream, condition) \
  !(condition) ? (void) 0 : Voidify() & (stream)

#if defined(DEBUG)
#define CDMI_DLOG() CDM_LAZY_STREAM(CdmiLogStream().stream(), true) \
    << CdmiLogMessage(__FILE__, __LINE__).message()
#else
#define CDMI_DLOG() CDM_LAZY_STREAM(CdmiLogStream().stream(), false)
#endif

#define CDMI_ELOG() CDM_LAZY_STREAM(CdmiLogStream().stream(), true) \
    << CdmiLogMessage(__FILE__, __LINE__).message()

#define CDMI_WLOG() CDM_LAZY_STREAM(CdmiLogStream().stream(), true) \
    << CdmiLogMessage(__FILE__, __LINE__).message()

END_NAMESPACE_OCDM()

#endif //OCDM_CDMI_LOG_H_
