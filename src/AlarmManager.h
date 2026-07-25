#ifndef MAHORAGA_ALARM_MANAGER_H
#define MAHORAGA_ALARM_MANAGER_H

#include <atomic>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "RogueAPDetector.h"

namespace mahoraga
{

class AlarmManager
{
public:
    AlarmManager(
        bool alarm_enabled,
        int alarm_duration_ms,
        int alarm_interval_ms,
        bool led_enabled,
        int led_pin,
        bool display_enabled
    );

    ~AlarmManager();

    void TriggerAlert(AlertLevel level, const std::string& message);
    void ClearAlert();
    bool IsAlertActive() const;
    AlertLevel GetCurrentAlertLevel() const;
    std::string GetCurrentAlertMessage() const;

    void SetAlarmEnabled(bool enabled);
    void SetLEDEnabled(bool enabled);
    void SetDisplayEnabled(bool enabled);
    void SetAlarmDuration(int duration_ms);
    void SetAlarmInterval(int interval_ms);

private:
    std::atomic<bool>  alarm_enabled_;
    std::atomic<int>   alarm_duration_ms_;
    std::atomic<int>   alarm_interval_ms_;
    std::atomic<bool>  led_enabled_;
    int                led_pin_;
    std::atomic<bool>  display_enabled_;

    std::atomic<bool>              alert_active_;
    std::atomic<AlertLevel>        current_level_;
    mutable std::mutex             message_mutex_;
    std::string                    current_message_;
    std::thread                    alert_thread_;
    std::atomic<bool>              thread_running_;

    void AlertWorker();
    void ActivateSiren();
    void ActivateLED();
    void UpdateDisplay();
    void SendNotification(const std::string& message);

    std::condition_variable cv_;
    std::mutex cv_mutex_;
    void StopWorker();
};

}

#endif

