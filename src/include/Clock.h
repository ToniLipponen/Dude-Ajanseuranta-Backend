
#pragma once
#include <chrono>

class Clock
{
public:
    Clock()
    {
        Reset();
    }

    [[maybe_unused]]
    double Reset() noexcept /// @brief Resets clock and returns time.
    {
        const auto newBegin = std::chrono::high_resolution_clock::now();
        const double time = std::chrono::duration_cast<std::chrono::duration<double>>(newBegin - m_begin).count();
        m_begin = newBegin;
        return time;
    }

    [[maybe_unused, nodiscard]]
    double GetTime() const noexcept /// @brief Returns elapsed time in seconds.
    {
        return std::chrono::duration_cast<std::chrono::duration<double>>(std::chrono::high_resolution_clock::now() - m_begin).count();
    }
    
private:
    std::chrono::time_point<std::chrono::high_resolution_clock> m_begin;
};