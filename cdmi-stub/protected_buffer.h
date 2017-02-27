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

#ifndef OCDMI_CDMI_PROTECTED_BUFFER_H_
#define OCDMI_CDMI_PROTECTED_BUFFER_H_

#include <cdmi-defs.h>
#include <stdint.h>
#include <protected_memory_manager.h>

BEGIN_NAMESPACE_OCDM()

enum ProtectedBufferType {
  CLEAR_BUF,
  DMA_BUF,
};

class ProtectedBuffer {
protected:

    friend ProtectedMemoryManager;

public:
  /* Is the buffer accessible directly.
   * The must return false in actual implementations
   */
  virtual bool isAccessible() = 0;

  virtual ProtectedBufferType getBufferType() = 0;

  virtual const int8_t* getData() const = 0;

  virtual const unsigned int getSize() = 0;
};

END_NAMESPACE_OCDM()
#endif //$OCDMI_CDMI_PROTECTED_BUFFER_H_
