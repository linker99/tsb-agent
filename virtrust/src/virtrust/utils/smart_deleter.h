/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

namespace virtrust {

template <class T> class SmartDeleter {
public:
  SmartDeleter() { core_ = nullptr; }

  explicit SmartDeleter(T *ptr) { core_ = ptr; }

  T *Get() const { return core_; }

protected:
  T *core_ = nullptr;
};

#define VIRTRUST_MAKE_DESTRUCTOR(NAME, DELETER)                                \
  ~NAME() {                                                                    \
    if (this->core_ != nullptr) {                                              \
      DELETER(this->core_);                                                    \
      this->core_ = nullptr;                                                   \
    }                                                                          \
  }

#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x, y)

#define VIRTRUST_MAKE_SMART(T, DELETER)                                        \
  class CONCAT(Smart, T) : public SmartDeleter<T> {                            \
  public:                                                                      \
    using SmartDeleter<T>::SmartDeleter;                                       \
    CONCAT(Smart, T)(const CONCAT(Smart, T) &) = delete;                       \
    CONCAT(Smart, T) &operator=(const CONCAT(Smart, T) &) = delete;            \
    VIRTRUST_MAKE_DESTRUCTOR(CONCAT(Smart, T), DELETER)                        \
  }

} // namespace virtrust
