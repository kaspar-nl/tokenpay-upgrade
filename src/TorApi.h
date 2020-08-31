/**
 * Copyright (c) 2019 TokenPay
 *
 * Distributed under the MIT/X11 software license,
 * see the accompanying file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef TOR_API_H
#define TOR_API_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <atomic>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 *  API for communicating with Tor
 */
namespace TorApi
{
    /**
     * Starts the Tor daemon in the current thread and gives the parameters to its main() function
     */
    int StartDaemon(int iArgc, char* iArgv[]);
    
    /**
     * Checks if Tor has finished initial setup and has begun its event loop.
     * Does not imply anything about the bootstrapping (it may be ready too or not) -- use IsBootstrapReady().
     *
     * If this returns true then you may connect to Tor's SOCKS server.
     * (or even send messages but they will not be broadcast any further until Tor builds up its circuit)
     */
    bool IsMainLoopReady();

    /**
     * Checks if up to this point, there have been any errors
     * reported by Tor when doing its initial checks or its bootstrapping.
     * May be used at anytime but probably after StartDaemon() or WaitOnConditionVariable().
     */
    bool HasAnyErrorOccurred();

    /**
     * Checks if Tor has been told (via StopDaemon(), called from this thread or another) to shutdown.
     */
    bool HasShutdownBeenRequested();

    /**
     * Checks if Tor has finished bootstrapping
     * (meaning it's actively event looping AND connected to the Tor network).
     *
     * If this returns true then you may connect to Tor's SOCKS server (if you weren't),
     * and send messages that will indeed be broadcast on the Tor network.
     */
    bool IsBootstrapReady();

    /**
     * Blocks the current thread waiting for Tor to do either of these:
     *  - do its initial checking and start the event loop (which translates to a listening SOCKS server up)
     *  - start the bootstrap process and build its circuit (which translates to actually being part of the Tor network)
     *
     *  Do NOT call this function if Tor is not actively working to do any of the steps above.
     */
    void WaitOnConditionVariable();

    /**
     * Attempts to asynchronously terminate the Tor daemon by injecting a shutdown event into its event queue.
     *
     * May be called from any thread. Do NOT call this function if Tor hasn't been previously started with StartDaemon()
     */
    void StopDaemon();

    /**
     * TODO TSB
     */
    namespace detail
    {
        /**
         * TODO TSB
         *
         * @tparam SingletonT
         */
        template <typename SingletonT>
        class EphemeralSingletonContainer
        {
        public:
            using Singleton = SingletonT;
            using Self      = EphemeralSingletonContainer<SingletonT>;

            virtual ~EphemeralSingletonContainer();

            /**
             * TODO TSB
             *
             * @return
             */
            static bool IsInstantiated();

        protected:
            EphemeralSingletonContainer();

        private:
            static std::atomic_flag r_isInstantiated;
        };
    }

    /**
     * Encapsulates in a RAII style the logic of initializing/cleaning-up synchronization primitives
     *
     */
    class DaemonSynchronizationMgr : public detail::EphemeralSingletonContainer<DaemonSynchronizationMgr>
    {
    public:
        using Self = DaemonSynchronizationMgr;
        using Super = detail::EphemeralSingletonContainer<Self>;

        DaemonSynchronizationMgr();

        ~DaemonSynchronizationMgr();

        /**
         * TODO TSB
         */
        class LockGuard : public detail::EphemeralSingletonContainer<LockGuard>
        {
        public:
            using Self  = LockGuard;
            using Super = detail::EphemeralSingletonContainer<Self>;
            using Outer = DaemonSynchronizationMgr;

            LockGuard();

            ~LockGuard();

            /**
             * TODO TSB
             */
            void acquire();

            /**
             * TODO TSB
             */
            void release();

            /**
             * TODO TSB
             *
             * @return
             */
            bool isAcquired() const;

        private:
            bool r_isAcquired;
        };
    };
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // TOR_API_H
