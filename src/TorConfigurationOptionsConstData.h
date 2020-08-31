/**
 * Copyright (c) 2019 TokenPay
 *
 * Distributed under the MIT/X11 software license,
 * see the accompanying file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef TOR_CONFIGURATION_OPTIONS_CONST_DATA_H
#define TOR_CONFIGURATION_OPTIONS_CONST_DATA_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <string>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * TODO TSB
 */
namespace TorConfigurationOptionsConstData
{
    /**
     * TODO TSB -- move to general ConstData
     *
     * @return
     */
    const std::string& GetOptionValueSeparator();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetEmptyOptionValue();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetOptionNamePrefix();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetFirstArgumentOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetLogFilePrefixOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetLogSeverityLevelDebugOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetLogSeverityLevelInformationOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetLogSeverityLevelNoticeOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetLogSeverityLevelWarningOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetLogSeverityLevelErrorOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetLogFileSuffixOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetSocksPortOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetIgnoreMissingConfigFileOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetDataFolderOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetHiddenServiceFolderOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetHiddenServicePortOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const std::string& GetHiddenServiceVersionOptionName();

    /**
     * TODO TSB
     *
     * @return
     */
    const int& GetMinHiddenServiceVersion();

    /**
     * TODO TSB
     *
     * @return
     */
    const int& GetMaxHiddenServiceVersion();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#endif // TOR_CONFIGURATION_OPTIONS_CONST_DATA_H
