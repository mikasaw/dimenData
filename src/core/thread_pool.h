// ============================================================
// 极简线程池（零依赖）：固定工作线程 + 任务队列 + 等待空闲
// worker_init 在每个工作线程启动时执行一次（如 COM 的 CoInitializeEx）
// ============================================================
#pragma once
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

class ThreadPool {
public:
    ThreadPool(size_t workers, std::function<void()> worker_init = nullptr) {
        for (size_t i = 0; i < workers; ++i)
            threads_.emplace_back([this, worker_init] {
                if (worker_init) worker_init();
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lk(mu_);
                        cv_.wait(lk, [&] { return stop_ || !tasks_.empty(); });
                        if (stop_ && tasks_.empty()) return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    task();
                    {
                        std::lock_guard<std::mutex> lk(mu_);
                        if (--busy_ == 0 && tasks_.empty()) done_cv_.notify_all();
                    }
                }
            });
    }

    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        for (auto& t : threads_) t.join();
    }

    void Post(std::function<void()> task) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            ++busy_;
            tasks_.push(std::move(task));
        }
        cv_.notify_one();
    }

    // 等待全部已入队任务完成（阻塞）
    void WaitIdle() {
        std::unique_lock<std::mutex> lk(mu_);
        done_cv_.wait(lk, [&] { return tasks_.empty() && busy_ == 0; });
    }

private:
    std::vector<std::thread> threads_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mu_;
    std::condition_variable cv_, done_cv_;
    bool stop_ = false;
    int  busy_ = 0;
};
