#pragma once

namespace virtrust {

// Define templates for enum range check

template <typename EnumType, EnumType... Values> class EnumCheck {};

template <typename EnumType> class EnumCheck<EnumType> {
public:
    template <typename IntType> static bool constexpr IsValue(IntType)
    {
        return false;
    }
};

template <typename EnumType, EnumType V, EnumType... Next>
class EnumCheck<EnumType, V, Next...> : private EnumCheck<EnumType, Next...> {
    using Super = EnumCheck<EnumType, Next...>;

public:
    template <typename IntType> static bool constexpr IsValue(IntType v)
    {
        return v == static_cast<IntType>(V) || Super::IsValue(v);
    }
};

} // namespace virtrust