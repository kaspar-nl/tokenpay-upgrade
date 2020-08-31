/**
 * Copyright (c) 2019 TokenPay
 *
 * Distributed under the MIT/X11 software license,
 * see the accompanying file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <TorConfigurationOptions.h>
#include <TorConfigurationOptionsConstData.h>
//#include <boost/filesystem/path.hpp>
#include <boost/filesystem/operations.hpp>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace
{
    namespace BoostFilesystemNS = boost::filesystem;
    namespace OptionsConstNS    = TorConfigurationOptionsConstData;

    /**
     * TODO TSB
     */
    enum class RawOptionPriority
    {
        E_PRIORITY_ONE,
        E_PRIORITY_TWO,
        E_PRIORITY_LAST
    };

    /**
     * TODO TSB
     *
     * @param iOptionName
     * @return
     */
    RawOptionPriority GetOptionPriorityByName(const TorConfigurationOptions::OptionName& iOptionName)
    {
        if (OptionsConstNS::GetFirstArgumentOptionName() == iOptionName)
        {
            return RawOptionPriority::E_PRIORITY_ONE;
        }

        if (OptionsConstNS::GetHiddenServiceFolderOptionName() == iOptionName)
        {
            return RawOptionPriority::E_PRIORITY_TWO;
        }

        return RawOptionPriority::E_PRIORITY_LAST;
    }

    /**
     * TODO TSB
     *
     * @param iLhsOptionName
     * @param iRhsOptionName
     * @return
     */
    bool HasLhsOptionHigherPriorityThanRhsOption(const TorConfigurationOptions::OptionName& iLhsOptionName,
                                                 const TorConfigurationOptions::OptionName& iRhsOptionName)
    {
        const auto C_LHS_PRIORITY = GetOptionPriorityByName(iLhsOptionName);
        const auto C_RHS_PRIORITY = GetOptionPriorityByName(iRhsOptionName);

        if (C_LHS_PRIORITY == C_RHS_PRIORITY)
        {
            return iLhsOptionName < iRhsOptionName;
        }

        return C_LHS_PRIORITY < C_RHS_PRIORITY;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TorConfigurationOptions::TorConfigurationOptions()
: r_optionMap{&HasLhsOptionHigherPriorityThanRhsOption},
  r_rawOptionList{},
  r_isRawListUpToDate{false}
{

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TorConfigurationOptions::Iterator TorConfigurationOptions::begin() const
{
    ensureRawOptionListFreshness();
    return r_rawOptionList.cbegin();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TorConfigurationOptions::Iterator TorConfigurationOptions::end() const
{
    ensureRawOptionListFreshness();
    return r_rawOptionList.cend();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorConfigurationOptions::ignoreMissingConfigFile()
{
    addCustomOption(OptionsConstNS::GetIgnoreMissingConfigFileOptionName());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorConfigurationOptions::setLogFile(const BoostFilesystemNS::path& iLogFile, LogSeverity iLogSeverity)
{
    std::string severityOptionName;
    switch (iLogSeverity)
    {
        case LogSeverity::E_DEBUG:
        {
            severityOptionName = OptionsConstNS::GetLogSeverityLevelDebugOptionName();
            break;
        }

        case LogSeverity::E_INFORMATION:
        {
            severityOptionName = OptionsConstNS::GetLogSeverityLevelInformationOptionName();
            break;
        }

        case LogSeverity::E_NOTICE:
        {
            severityOptionName = OptionsConstNS::GetLogSeverityLevelNoticeOptionName();
            break;
        }

        case LogSeverity::E_WARNING:
        {
            severityOptionName = OptionsConstNS::GetLogSeverityLevelWarningOptionName();
            break;
        }

        case LogSeverity::E_ERROR:
        {
            severityOptionName = OptionsConstNS::GetLogSeverityLevelErrorOptionName();
            break;
        }

        default:
        {
            assert(false);
        }
    }

    addCustomOptionWithValue(OptionsConstNS::GetLogFilePrefixOptionName(),
                             severityOptionName + OptionsConstNS::GetOptionValueSeparator() +
                                                      OptionsConstNS::GetLogFileSuffixOptionName() +
                                                         OptionsConstNS::GetOptionValueSeparator() + iLogFile.string());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorConfigurationOptions::setSocksPort(int iSocksPort)
{
    // TODO TSB: get port numbers range from a ConstNS
    //
    assert(0 <= iSocksPort && iSocksPort <= 65535);

    addCustomOptionWithValue(OptionsConstNS::GetSocksPortOptionName(), std::to_string(iSocksPort));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorConfigurationOptions::setDataFolder(const BoostFilesystemNS::path& iDataFolder)
{
    assert(BoostFilesystemNS::exists(iDataFolder));

    addCustomOptionWithValue(OptionsConstNS::GetDataFolderOptionName(), iDataFolder.string());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorConfigurationOptions::setHiddenServiceFolder(const BoostFilesystemNS::path& iHiddenServiceFolder)
{
    assert(BoostFilesystemNS::exists(iHiddenServiceFolder));

    addCustomOptionWithValue(OptionsConstNS::GetHiddenServiceFolderOptionName(), iHiddenServiceFolder.string());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorConfigurationOptions::setHiddenServicePort(int iHiddenServicePort)
{
    // TODO TSB: get port numbers range from a ConstNS
    //
    assert(0 <= iHiddenServicePort && iHiddenServicePort <= 65535);

    addCustomOptionWithValue(OptionsConstNS::GetHiddenServicePortOptionName(), std::to_string(iHiddenServicePort));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorConfigurationOptions::setHiddenServiceVersion(int iHiddenServiceVersion)
{
    assert(OptionsConstNS::GetMinHiddenServiceVersion() <= iHiddenServiceVersion &&
           iHiddenServiceVersion <= OptionsConstNS::GetMaxHiddenServiceVersion());

    addCustomOptionWithValue(OptionsConstNS::GetHiddenServiceVersionOptionName(),
                             std::to_string(iHiddenServiceVersion));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorConfigurationOptions::addCustomOption(const OptionName& iOptionName)
{
    assert(!iOptionName.empty());

    r_isRawListUpToDate = false;
    r_optionMap.emplace(iOptionName, OptionsConstNS::GetEmptyOptionValue());
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorConfigurationOptions::addCustomOptionWithValue(const OptionName& iOptionName, const OptionValue& iOptionValue)
{
    assert(!iOptionName.empty() && !iOptionValue.empty());

    r_isRawListUpToDate = false;
    r_optionMap.emplace(iOptionName, iOptionValue);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void TorConfigurationOptions::ensureRawOptionListFreshness() const
{
    if (!r_isRawListUpToDate)
    {
        r_rawOptionList.clear();
        r_isRawListUpToDate = true;

        for (const auto& optionPairItr : r_optionMap)
        {
            r_rawOptionList.push_back(OptionsConstNS::GetOptionNamePrefix() + optionPairItr.first);
            if (OptionsConstNS::GetEmptyOptionValue() != optionPairItr.second)
            {
                r_rawOptionList.push_back(optionPairItr.second);
            }
        }
    }
}
