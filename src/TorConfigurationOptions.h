/**
 * Copyright (c) 2019 TokenPay
 *
 * Distributed under the MIT/X11 software license,
 * see the accompanying file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef TOR_CONFIGURATION_OPTIONS_H
#define TOR_CONFIGURATION_OPTIONS_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <string>
#include <map>
#include <functional>
#include <vector>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace boost
{
    namespace filesystem
    {
        class path;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * TODO TSB
 */
class TorConfigurationOptions
{
private:
    using RawOption     = std::string;
    using RawOptionList = std::vector<RawOption>;

public:
    using Self        = TorConfigurationOptions;
    using OptionName  = std::string;
    using OptionValue = std::string;
    using Iterator    = RawOptionList::const_iterator;

    /**
     * TODO TSB
     */
    enum class LogSeverity
    {
        E_DEBUG,
        E_INFORMATION,
        E_NOTICE,
        E_WARNING,
        E_ERROR
    };

    TorConfigurationOptions();

    /**
     * TODO TSB
     *
     * @return
     */
    Iterator begin() const;

    /**
     * TODO TSB
     *
     * @return
     */
    Iterator end() const;

    /**
     * TODO TSB
     */
    void ignoreMissingConfigFile();

    /**
     * TODO TSB
     *
     * @param iLogFile
     * @param iLogSeverity
     */
    void setLogFile(const boost::filesystem::path& iLogFile, LogSeverity iLogSeverity);

    /**
     * TODO TSB
     *
     * @param iSocksPort
     */
    void setSocksPort(int iSocksPort);

    /**
     * TODO TSB
     *
     * @param iDataFolder
     */
    void setDataFolder(const boost::filesystem::path& iDataFolder);

    /**
     * TODO TSB
     *
     * @param iHiddenServiceFolder
     */
    void setHiddenServiceFolder(const boost::filesystem::path& iHiddenServiceFolder);

    /**
     * TODO TSB
     *
     * @param iHiddenServicePort
     */
    void setHiddenServicePort(int iHiddenServicePort);

    /**
     * TODO TSB
     *
     * @param iHiddenServiceVersion
     */
    void setHiddenServiceVersion(int iHiddenServiceVersion);

private:
    using OptionMap = std::map<OptionName, OptionValue, std::function<bool(const OptionName&, const OptionName&)>>;

    /**
     * TODO TSB
     *
     * @param iOptionName
     */
    void addCustomOption(const OptionName& iOptionName);

    /**
     * TODO TSB
     *
     * @param iOptionName
     * @param iOptionValue
     */
    void addCustomOptionWithValue(const OptionName& iOptionName, const OptionValue& iOptionValue);

    /**
     * TODO TSB
     *
     * @return
     */
    void ensureRawOptionListFreshness() const;

    OptionMap             r_optionMap;
    mutable RawOptionList r_rawOptionList;
    mutable bool          r_isRawListUpToDate;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // TOR_CONFIGURATION_OPTIONS_H
