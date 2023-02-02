#pragma once
#include <random>
#include <type_traits>
#include <limits>

namespace Math
{
    [[maybe_unused]] inline constexpr double Pi = 3.14159265358979323846;
    [[maybe_unused]] inline constexpr double Pi2 = Pi / 2;

    namespace Impl
    {
        inline static std::random_device randomDevice;
        inline static std::mt19937 randomGenerator(randomDevice());
    }

    /** @brief Generates a random value within a given range.
     *
     *  @tparam T Arithmetic value type
     *  @param min Minimum value
     *  @param max Maximum value
     *  @return Random value between minimum and maximum */
    template<typename T = int32_t>
    [[maybe_unused, nodiscard]]
    inline constexpr typename std::enable_if<std::is_arithmetic<T>::value, T>::type Random(T min = std::numeric_limits<T>::min(), T max = std::numeric_limits<T>::max()) noexcept
    {
        if constexpr(std::is_floating_point<T>::value)
        {
            std::uniform_real_distribution<T> distribution(min, max);

            return distribution(Impl::randomGenerator);
        }
        else if constexpr(std::is_integral<T>::value)
        {
            std::uniform_int_distribution<T> distribution(min, max);

            return distribution(Impl::randomGenerator);
        }
    }
}