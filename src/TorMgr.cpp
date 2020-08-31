/**
 * Copyright (c) 2019 TokenPay
 *
 * Distributed under the MIT/X11 software license,
 * see the accompanying file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <TorApi.h>
#include <TorConfigurationOptionsConstData.h>
#include <TorMgr.h>
#include <cassert>
#include <vector>
#include <TorConfigurationOptions.h>
#include <limits>
#include <algorithm>
#include <string>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace
{
    namespace TorApiNS       = TorApi;
    namespace OptionsConstNS = TorConfigurationOptionsConstData;

    /**
     * TODO TSB
     *
     * @return
     */
    template <typename FunctorT>
    bool WaitOnTorApiConditionVariable(FunctorT&& iGetCVFlagFunctor)
    {
        TorApiNS::DaemonSynchronizationMgr::LockGuard lock{};

        while (!TorApiNS::HasAnyErrorOccurred() &&
               !TorApiNS::HasShutdownBeenRequested() &&
               !iGetCVFlagFunctor())
        {
            TorApiNS::WaitOnConditionVariable();
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TorMgr::~TorMgr()
{
    if (Self::isRunning())
    {
        shutdown();
        r_runResult.wait();
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TorMgr& TorMgr::GetInstance()
{
    static Self oInstance;
    return oInstance;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool TorMgr::isRunning() const
{
    return r_isRunning.load();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorMgr::waitToBringSocksServerUp()
{
    assert(Self::isRunning());
    assert(r_socksServerBringUpFuture.valid());

    r_socksServerBringUpFuture.wait();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorMgr::waitToBuildCircuit()
{
    assert(Self::isRunning());
    assert(r_circuitBuildFuture.valid());

    r_circuitBuildFuture.wait();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool TorMgr::waitWithTimeoutToBringSocksServerUp(const std::chrono::milliseconds& iTimeout)
{
    assert(Self::isRunning());
    assert(r_socksServerBringUpFuture.valid());

    return std::future_status::ready == r_socksServerBringUpFuture.wait_for(iTimeout);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool TorMgr::waitWithTimeoutToBuildCircuit(const std::chrono::milliseconds& iTimeout)
{
    assert(Self::isRunning());
    assert(r_circuitBuildFuture.valid());

    return std::future_status::ready == r_circuitBuildFuture.wait_for(iTimeout);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorMgr::run(const TorConfigurationOptions& iOptions)
{
    // the order of all these operations matters; be careful when doing changes
    //
    assert(!Self::isRunning());

    Self::onRunBegin();

    TorApiNS::DaemonSynchronizationMgr syncMgr{};

    Self::runImpl(iOptions);

    WaitOnTorApiConditionVariable(&TorApiNS::IsMainLoopReady);
    if (!Self::onDaemonEarlyExit())
    {
        r_socksServerBringUpPromise.set_value();

        WaitOnTorApiConditionVariable(&TorApiNS::IsBootstrapReady);
        if (!Self::onDaemonEarlyExit())
        {
            r_circuitBuildPromise.set_value();
            Self::joinDaemon();
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorMgr::shutdown()
{
    assert(Self::isRunning());

    TorApiNS::StopDaemon();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TorMgr::TorMgr()
: r_runResult{},
  r_isRunning{false},
  r_socksServerBringUpPromise{},
  r_socksServerBringUpFuture{},
  r_circuitBuildPromise{},
  r_circuitBuildFuture{}
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorMgr::runImpl(const TorConfigurationOptions& iOptions)
{
    assert(Self::isRunning());
    assert(!r_runResult.valid());

    r_runResult = std::async(std::launch::async, [&iOptions]
    {
        std::vector<std::string> argumentsAsStrings{OptionsConstNS::GetFirstArgumentOptionName()};
        argumentsAsStrings.insert(argumentsAsStrings.end(), iOptions.begin(), iOptions.end());
        assert(!argumentsAsStrings.empty() && argumentsAsStrings.size() <= std::numeric_limits<int>::max());

        // avoid making deep copies that we'd have to delete after TorApiNS::StartDaemon returns
        //
        std::vector<char*> argumentsAsArgv;
        std::transform(argumentsAsStrings.begin(),
                       argumentsAsStrings.end(),
                       std::back_inserter(argumentsAsArgv),
                       [](std::string& iArgument)
        {
            return &iArgument[0];
        });

        return static_cast<bool>(TorApiNS::StartDaemon(static_cast<int>(argumentsAsArgv.size()), &argumentsAsArgv[0]));
    });
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorMgr::joinDaemon()
{
    assert(Self::isRunning());

    static_cast<void>(r_runResult.get());

    Self::onRunEnd();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorMgr::onRunBegin()
{
    r_socksServerBringUpPromise = std::promise<void>();
    r_circuitBuildPromise = std::promise<void>();

    r_socksServerBringUpFuture = r_socksServerBringUpPromise.get_future();
    r_circuitBuildFuture = r_circuitBuildPromise.get_future();

    r_isRunning.store(true);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorMgr::onRunEnd()
{
    r_isRunning.store(false);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool TorMgr::onDaemonEarlyExit()
{
    assert(Self::isRunning());

    if (TorApiNS::HasAnyErrorOccurred() || TorApiNS::HasShutdownBeenRequested())
    {
        Self::joinDaemon();

        if (!TorApiNS::IsMainLoopReady())
        {
            assert(!TorApiNS::IsBootstrapReady());

            r_socksServerBringUpPromise.set_value();
            r_circuitBuildPromise.set_value();
        }
        else if (!TorApiNS::IsBootstrapReady())
        {
            r_circuitBuildPromise.set_value();
        }

        return true;
    }

    return false;
}
