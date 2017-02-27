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

/* Transparent buffer provides no data protection. The decrypted data
 * is passed back to the the userspace and it is directly accessible
 */

#include <protected_buffer.h>

BEGIN_NAMESPACE_OCDM()

class UnprotectedBuffer : public ProtectedBuffer {
  bool isAccessible() { return true; }
  ProtectedBufferType getBufferType { return ProtectedBufferType::CLEAR};
};

END_NAMESPACE_OCDM()
