#include "EpollEngine.hpp"
#include <fcntl.h>
#include <unistd.h>

EpollEngine::EpollEngine()
    : _epoll_fd(epoll_create1(0)),
      _running(true) // Initialize here
{
    if (_epoll_fd == -1) {
        throw std::system_error(errno, std::generic_category(), "Failed to create epoll");
    }
}

EpollEngine::~EpollEngine() {
    if (_epoll_fd != -1) {
        close(_epoll_fd);
    }
}

EpollEngine::EpollEngine(EpollEngine&& other) noexcept {
    _epoll_fd = other._epoll_fd;
    _running.store(other._running.load());
    other._epoll_fd = -1;
}

EpollEngine& EpollEngine::operator=(EpollEngine&& other) noexcept {
    if (this != &other) {
        if (_epoll_fd != -1) {
            close(_epoll_fd);
        }
        _epoll_fd = other._epoll_fd;
        _running.store(other._running.load());
        other._epoll_fd = -1;
    }
    return *this;
}

void EpollEngine::set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        throw std::system_error(errno, std::system_category(), "Failed to set O_NONBLOCK");
    }
}

void EpollEngine::add(int fd, uint32_t events, EventContext* ctx) {
    control(EPOLL_CTL_ADD, fd, events | EPOLLET, ctx);
}

void EpollEngine::modify(int fd, uint32_t events, EventContext* ctx) {
    control(EPOLL_CTL_MOD, fd, events | EPOLLET, ctx);
}

void EpollEngine::remove(int fd) {
    if (epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, fd, nullptr) == -1 && errno != ENOENT) {
        throw std::system_error(errno, std::system_category(), "epoll_ctl DEL failed");
    }
}

int EpollEngine::wait(std::vector<epoll_event>& event_buffer, int timeout_ms) {
    if (!_running.load()) {
        return -1;
    }

    int nfds = epoll_wait(_epoll_fd, event_buffer.data(), static_cast<int>(event_buffer.size()), timeout_ms);

    if (nfds == -1) {
        if (errno == EINTR) {
            return 0;
        }
        throw std::system_error(errno, std::system_category(), "epoll_wait failed");
    }
    return nfds;
}

void EpollEngine::control(int op, int fd, uint32_t events, EventContext* ctx) {
    epoll_event ev{};
    ev.events = events;
    ev.data.ptr = ctx;
    if (epoll_ctl(_epoll_fd, op, fd, &ev) == -1) {
        throw std::system_error(errno, std::system_category(), "epoll_ctl error");
    }
}