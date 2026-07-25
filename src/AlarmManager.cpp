#include "AlarmManager.h"
#include <iostream>

namespace mahoraga
{

AlarmManager::AlarmManager(
    bool alarm_enabled,
    int alarm_duration_ms,
    int alarm_interval_ms,
    bool led_enabled,
    int led_pin,
    bool display_enabled
)
    : alarm_enabled_(alarm_enabled)
    , alarm_duration_ms_(alarm_duration_ms)
    , alarm_interval_ms_(alarm_interval_ms)
    , led_enabled_(led_enabled)
    , led_pin_(led_pin)
    , display_enabled_(display_enabled)
    , alert_active_(false)
    , current_level_(AlertLevel::None)
    , thread_running_(false)
{
}

AlarmManager::~AlarmManager()
{
    StopWorker();
}

void AlarmManager::TriggerAlert(AlertLevel level, const std::string& message)
{
    if (level == AlertLevel::None)
    {
        return;
    }

    StopWorker();

    {
        std::lock_guard<std::mutex> lock(message_mutex_);
        current_message_ = message;
    }

    current_level_ = level;
    alert_active_ = true;
    thread_running_ = true;

    alert_thread_ = std::thread(&AlarmManager::AlertWorker, this);
}

void AlarmManager::ClearAlert()
{
    alert_active_ = false;
    {
        std::lock_guard<std::mutex> lock(message_mutex_);
        current_message_.clear();
    }
    current_level_ = AlertLevel::None;

    std::unique_lock<std::mutex> lock(cv_mutex_);
    cv_.notify_all();
}

void AlarmManager::StopWorker()
{
    thread_running_ = false;
    alert_active_ = false;

    {
        std::unique_lock<std::mutex> lock(cv_mutex_);
        cv_.notify_all();
    }

    if (alert_thread_.joinable())
    {
        alert_thread_.join();
    }
}

bool AlarmManager::IsAlertActive() const
{
    return alert_active_.load();
}

AlertLevel AlarmManager::GetCurrentAlertLevel() const
{
    return current_level_.load();
}

std::string AlarmManager::GetCurrentAlertMessage() const
{
    std::lock_guard<std::mutex> lock(message_mutex_);
    return current_message_;
}

void AlarmManager::SetAlarmEnabled(bool enabled)
{
    alarm_enabled_ = enabled;
}

void AlarmManager::SetLEDEnabled(bool enabled)
{
    led_enabled_ = enabled;
}

void AlarmManager::SetDisplayEnabled(bool enabled)
{
    display_enabled_ = enabled;
}

void AlarmManager::SetAlarmDuration(int duration_ms)
{
    alarm_duration_ms_ = duration_ms;
}

void AlarmManager::SetAlarmInterval(int interval_ms)
{
    alarm_interval_ms_ = interval_ms;
}

void AlarmManager::AlertWorker()
{
    while (thread_running_ && alert_active_)
    {
        if (alarm_enabled_)
        {
            ActivateSiren();
        }

        if (led_enabled_)
        {
            ActivateLED();
        }

        if (display_enabled_)
        {
            UpdateDisplay();
        }

        std::unique_lock<std::mutex> lock(cv_mutex_);

        cv_.wait_for(lock, std::chrono::milliseconds(alarm_interval_ms_.load()), [this]() {
            return !thread_running_ || !alert_active_;
        });
    }

    thread_running_ = false;
}

void AlarmManager::ActivateSiren()
{
    std::cout << "\a";
    std::cout.flush();
}

void AlarmManager::ActivateLED()
{
    std::cout << "\033[5m";
    std::cout << "[LED] ALERT ACTIVE";
    std::cout << "\033[25m";
    std::cout.flush();
}

void AlarmManager::UpdateDisplay()
{
    std::string level_str;
    AlertLevel level = current_level_.load();

    switch (level)
    {
        case AlertLevel::Low:
            level_str = "LOW";
            break;
        case AlertLevel::Medium:
            level_str = "MEDIUM";
            break;
        case AlertLevel::High:
            level_str = "HIGH";
            break;
        case AlertLevel::Critical:
            level_str = "CRITICAL";
            break;
        default:
            level_str = "INFO";
            break;
    }

    std::string msg;
    {
        std::lock_guard<std::mutex> lock(message_mutex_);
        msg = current_message_;
    }

    SendNotification("[" + level_str + "] " + msg);
}

void AlarmManager::SendNotification(const std::string& message)
{
    AlertLevel level = current_level_.load();

    switch (level)
    {
        case AlertLevel::Critical:
            std::cout << "\033[1;91m";
            break;
        case AlertLevel::High:
            std::cout << "\033[1;31m";
            break;
        case AlertLevel::Medium:
            std::cout << "\033[1;33m";
            break;
        case AlertLevel::Low:
            std::cout << "\033[1;34m";
            break;
        default:
            std::cout << "\033[1;32m";
            break;
    }

    std::cout << "[DEFENSE] " << message << "\033[0m" << std::endl;
}

}
