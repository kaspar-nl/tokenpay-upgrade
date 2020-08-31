/**
 * Copyright (c) 2019 TokenPay
 *
 * Distributed under the MIT/X11 software license,
 * see the accompanying file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef TOR_MGR_H
#define TOR_MGR_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <chrono>
#include <future>
#include <atomic>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class TorConfigurationOptions;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * TODO TSB
 */
class TorMgr
{
public:
    using Self = TorMgr;

    ~TorMgr();

    /**
     * TODO TSB
     */
    static Self& GetInstance();

    /**
     * TODO TSB
     *
     * @return
     */
    bool isRunning() const;

    /**
     * TODO TSB
     */
    void waitToBringSocksServerUp();

    /**
     * TODO TSB
     */
    void waitToBuildCircuit();

    /**
     * TODO TSB
     */
    bool waitWithTimeoutToBringSocksServerUp(const std::chrono::milliseconds& iTimeout);

    /**
     * TODO TSB
     */
    bool waitWithTimeoutToBuildCircuit(const std::chrono::milliseconds& iTimeout);

    /**
     * TODO TSB
     *
     * @param iOptions
     */
    void run(const TorConfigurationOptions& iOptions);

    /**
     * TODO TSB
     */
    void shutdown();

private:
    std::future<bool>  r_runResult;
    std::atomic<bool>  r_isRunning;
    std::promise<void> r_socksServerBringUpPromise;
    std::future<void>  r_socksServerBringUpFuture;
    std::promise<void> r_circuitBuildPromise;
    std::future<void>  r_circuitBuildFuture;

    TorMgr();

    void runImpl(const TorConfigurationOptions& iOptions);

    void joinDaemon();

    void onRunBegin();

    void onRunEnd();

    bool onDaemonEarlyExit();
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // TOR_MGR_H
