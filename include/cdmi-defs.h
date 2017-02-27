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
#ifndef OCDM_INCLUDE_CDMI_DEFS_H__
#define OCDM_INCLUDE_CDMI_DEFS_H__

#ifdef USE_PLAYREADY
 /* Note: The CDMi implementation may reside in a different
  * namespace. Here we can configure the CDMi namespace
  */
#define OCDM_NAMESPACE CDMi
#else
#define OCDM_NAMESPACE CDMi
#endif

#define BEGIN_NAMESPACE_OCDM() \
    namespace OCDM_NAMESPACE {

#define END_NAMESPACE_OCDM() }

#define USE_NAMESPACE_OCDM() using namespace CDMi;
#endif//OCDM_INCLUDE_CDMI_DEFS_H__
