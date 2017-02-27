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

#ifndef OCDMI_CDMI_UNPROTECTED_BUFFER_H_
#define OCDMI_CDMI_UNPROTECTED_BUFFER_H_
#include <cdmi-defs.h>
#include <stdint.h>
#include <protected_buffer.h>

BEGIN_NAMESPACE_OCDM()

class UnProtectedBuffer {
protected:
    UnProtectedBuffer();

    friend ProtectedMemoryManager;

public:
  /* Is the buffer accessible directly.
   * The must return false in actual implementations
   */
  virtual  bool isAccessible() { return true; }

  virtual ProtectedBufferType getBufferType() {
    return CLEAR_BUF;
    }

  virtual const int8_t* getData() const {
    return buf;
    }

  virtual const unsigned int getSize() const = 0;
private:
  int8_t* buf;
};

END_NAMESPACE_OCDM()
#endif //OCDMI_CDMI_UNPROTECTED_BUFFER_H_
