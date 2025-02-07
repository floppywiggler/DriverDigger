#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlwapi.h>
#include <winhttp.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <filesystem>
#include <unordered_set>
#include <iomanip>
#include <algorithm>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "winhttp.lib")

namespace fs = std::filesystem;

// ***********************
// Global Constants and Globals
// ***********************
const std::string BASELINE_FILE = "microsoft_drivers.txt";
const std::string REPO_FOLDER = "extracted_drivers\\";
const std::string DEFAULT_VULN_CSV = "loldrivers.csv";
const std::string VULN_CSV_URL = "https://www.loldrivers.io/api/drivers.csv";

std::unordered_set<std::string> microsoftDrivers;
std::unordered_set<std::string> vulnDrivers; // stores vulnerable driver filenames (all lowercase)
std::vector<std::string> vulnSkippedFiles;   // record filenames skipped due to vulnerability

// Command-line options (defaults)
std::string vendorFilter = "";   // if specified, only extract drivers whose CompanyName contains this (case-insensitive)
bool useVulnExclusion = false;   // if --vuln-exclude is passed, vulnerability exclusion is enabled
bool showHelp = false;

// ***********************
// Utility Functions
// ***********************
std::string toLower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

void SetConsoleColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

void PrintHelp() {
    std::cout <<
        R"(  


  ____       _                ____  _                       
 |  _ \ _ __(_)_   _____ _ __|  _ \(_) __ _  __ _  ___ _ __ 
 | | | | '__| \ \ / / _ \ '__| | | | |/ _` |/ _` |/ _ \ '__|
 | |_| | |  | |\ V /  __/ |  | |_| | | (_| | (_| |  __/ |   
 |____/|_|  |_| \_/ \___|_|  |____/|_|\__, |\__, |\___|_|   
                                      |___/ |___/           
                                                  
DriverDigger - A portable Windows kernel driver extraction tool

Usage:
  DriverDigger.exe [options]

Options:
  -h, --help          Display this help message.
  --vendor <vendor>   Only extract drivers whose CompanyName contains the specified vendor (case-insensitive).
  --vuln-exclude      Enable vulnerability exclusion. When this option is provided, the tool auto-downloads the latest CSV from loldrivers.io and uses it to skip drivers known to be vulnerable.

Examples:
  DriverDigger.exe
  DriverDigger.exe --vendor intel
  DriverDigger.exe --vuln-exclude
)" << std::endl;
}


void ParseArguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            showHelp = true;
        }
        else if (arg == "--vendor") {
            if (i + 1 < argc) {
                vendorFilter = argv[++i];
                vendorFilter = toLower(vendorFilter);
            }
        }
        else if (arg == "--vuln-exclude") {
            // Regardless of whether an extra parameter is given, enable vuln exclusion and always auto-download.
            useVulnExclusion = true;
        }
    }
    if (showHelp) {
        PrintHelp();
        exit(0);
    }
}

// ***********************
// WinHTTP Download Function
// ***********************
bool DownloadFileFromURL(const std::string& url, const std::string& localFile) {
    HINTERNET hSession = WinHttpOpen(L"DriverDigger/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        std::cerr << "[ERROR] WinHttpOpen failed.\n";
        return false;
    }

    std::wstring wurl(url.begin(), url.end());
    URL_COMPONENTS urlComp = { 0 };
    urlComp.dwStructSize = sizeof(urlComp);
    wchar_t hostName[256] = { 0 };
    wchar_t urlPath[1024] = { 0 };
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = _countof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = _countof(urlPath);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &urlComp)) {
        std::cerr << "[ERROR] WinHttpCrackUrl failed.\n";
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, hostName, urlComp.nPort, 0);
    if (!hConnect) {
        std::cerr << "[ERROR] WinHttpConnect failed.\n";
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        (urlComp.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) {
        std::cerr << "[ERROR] WinHttpOpenRequest failed.\n";
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!bResults) {
        std::cerr << "[ERROR] WinHttpSendRequest failed.\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        std::cerr << "[ERROR] WinHttpReceiveResponse failed.\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::ofstream ofs(localFile, std::ios::binary);
    if (!ofs.is_open()) {
        std::cerr << "[ERROR] Could not open " << localFile << " for writing.\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD dwSize = 0;
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            break;
        if (dwSize == 0)
            break;
        std::vector<char> buffer(dwSize);
        DWORD dwDownloaded = 0;
        if (!WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded))
            break;
        ofs.write(buffer.data(), dwDownloaded);
    } while (dwSize > 0);

    ofs.close();
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return true;
}

// ***********************
// Version Resource Extraction (Robust)
// ***********************
std::string GetVersionFieldRobust(const std::string& filePath, const std::string& fieldName) {
    DWORD dummy;
    DWORD size = GetFileVersionInfoSizeA(filePath.c_str(), &dummy);
    if (size == 0)
        return "Unknown";

    std::vector<char> versionData(size);
    if (!GetFileVersionInfoA(filePath.c_str(), 0, size, versionData.data()))
        return "Unknown";

    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    } *lpTranslate = nullptr;
    UINT cbTranslate = 0;
    if (VerQueryValueA(versionData.data(), "\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate) &&
        cbTranslate >= sizeof(LANGANDCODEPAGE)) {
        int count = cbTranslate / sizeof(LANGANDCODEPAGE);
        char subBlock[100];
        for (int i = 0; i < count; i++) {
            sprintf_s(subBlock, sizeof(subBlock), "\\StringFileInfo\\%04x%04x\\%s",
                lpTranslate[i].wLanguage, lpTranslate[i].wCodePage, fieldName.c_str());
            void* buffer = nullptr;
            UINT bufferSize = 0;
            if (VerQueryValueA(versionData.data(), subBlock, &buffer, &bufferSize) && bufferSize > 0) {
                std::string value((char*)buffer);
                if (!value.empty() && value != "Unknown")
                    return value;
            }
        }
    }
    return "Unknown";
}

std::string GetFileCompanyName(const std::string& filePath) {
    return GetVersionFieldRobust(filePath, "CompanyName");
}

std::string GetFileDescription(const std::string& filePath) {
    return GetVersionFieldRobust(filePath, "FileDescription");
}

std::string GetProductName(const std::string& filePath) {
    return GetVersionFieldRobust(filePath, "ProductName");
}

std::string GetCopyright(const std::string& filePath) {
    return GetVersionFieldRobust(filePath, "LegalCopyright");
}

// ***********************
// Heuristics for Exclusion
// ***********************
bool IsLikelyMicrosoftDriver(const std::string& filePath) {
    std::string company = toLower(GetFileCompanyName(filePath));
    std::string desc = toLower(GetFileDescription(filePath));
    std::string product = toLower(GetProductName(filePath));
    std::string copyright = toLower(GetCopyright(filePath));

    if (company.find("microsoft") != std::string::npos ||
        desc.find("microsoft") != std::string::npos ||
        product.find("microsoft") != std::string::npos ||
        copyright.find("microsoft") != std::string::npos)
        return true;

    if (company == "unknown" && desc == "unknown" &&
        product == "unknown" && copyright == "unknown") {
        std::string lowerPath = toLower(filePath);
        if (lowerPath.find("\\windows\\system32\\drivers\\") != std::string::npos ||
            lowerPath.find("\\windows\\winsxs\\") != std::string::npos ||
            lowerPath.find("\\windows\\driverstore\\") != std::string::npos)
            return true;
    }
    return false;
}

bool MatchesVendorFilter(const std::string& filePath) {
    if (vendorFilter.empty())
        return true;
    std::string company = toLower(GetFileCompanyName(filePath));
    return (company.find(vendorFilter) != std::string::npos);
}

bool IsVulnerableDriver(const std::string& filePath) {
    if (vulnDrivers.empty())
        return false;
    std::string fname = toLower(fs::path(filePath).filename().string());
    return (vulnDrivers.find(fname) != vulnDrivers.end());
}

// ***********************
// Baseline and Vulnerable List Handling
// ***********************
void LoadBaseline() {
    std::ifstream inFile(BASELINE_FILE);
    if (inFile.is_open()) {
        std::string line;
        while (std::getline(inFile, line))
            microsoftDrivers.insert(line);
        inFile.close();
    }
}

void SaveBaseline() {
    std::ofstream outFile(BASELINE_FILE);
    if (outFile.is_open()) {
        for (const auto& driver : microsoftDrivers)
            outFile << driver << "\n";
        outFile.close();
    }
}

// Load vulnerable drivers from a CSV file (assumes header and that the vulnerable filename is in the last column "Tags").
void LoadVulnerableDriversFromCSV(const std::string& csvPath) {
    std::ifstream inFile(csvPath);
    if (!inFile.is_open()) {
        std::cerr << "[WARN] Could not open vulnerability CSV file: " << csvPath << "\n";
        return;
    }
    std::string line;
    bool isHeader = true;
    while (std::getline(inFile, line)) {
        if (isHeader) { isHeader = false; continue; }
        size_t pos = line.rfind(',');
        if (pos == std::string::npos) continue;
        std::string tagField = line.substr(pos + 1);
        if (!tagField.empty() && tagField.front() == '\"' && tagField.back() == '\"')
            tagField = tagField.substr(1, tagField.size() - 2);
        tagField = toLower(tagField);
        std::istringstream iss(tagField);
        std::string token;
        while (std::getline(iss, token, ',')) {
            token.erase(token.begin(), std::find_if(token.begin(), token.end(), [](unsigned char ch) {
                return !std::isspace(ch);
                }));
            token.erase(std::find_if(token.rbegin(), token.rend(), [](unsigned char ch) {
                return !std::isspace(ch);
                }).base(), token.end());
            if (!token.empty())
                vulnDrivers.insert(token);
        }
    }
    inFile.close();
}

// ***********************
// File Enumeration
// ***********************
std::vector<std::string> FindAllSysFiles(const fs::path& directory) {
    std::vector<std::string> sysFiles;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(directory, fs::directory_options::skip_permission_denied)) {
            try {
                if (entry.path().string().find(REPO_FOLDER) != std::string::npos)
                    continue;
                std::string ext = toLower(entry.path().extension().string());
                if (entry.is_regular_file() && !entry.is_symlink() && ext == ".sys") {
                    std::cout << "[DEBUG] Checking: " << entry.path() << "\n";
                    sysFiles.push_back(entry.path().string());
                }
            }
            catch (const std::filesystem::filesystem_error& e) {
                std::cerr << "[!] Skipping file due to error: " << e.what() << "\n";
            }
        }
    }
    catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "[!] Directory access error: " << e.what() << "\n";
    }
    return sysFiles;
}

// ***********************
// Main Extraction Routine
// ***********************
void ExtractThirdPartyDrivers() {
    LoadBaseline();

    // If the user specified --vuln-exclude, auto-download vulnerability CSV and load it.
    if (useVulnExclusion) {
        if (!fs::exists(DEFAULT_VULN_CSV)) {
            std::cout << "[INFO] Auto-downloading vulnerability CSV from " << VULN_CSV_URL << "\n";
            if (!DownloadFileFromURL(VULN_CSV_URL, DEFAULT_VULN_CSV)) {
                std::cerr << "[WARN] Failed to download vulnerability CSV file. Continuing without vulnerability exclusion.\n";
            }
            else {
                std::cout << "[INFO] Downloaded vulnerability CSV to " << DEFAULT_VULN_CSV << "\n";
            }
        }
        LoadVulnerableDriversFromCSV(DEFAULT_VULN_CSV);
    }

    CreateDirectoryA(REPO_FOLDER.c_str(), NULL);
    std::ofstream report("drivers_report.csv");
    if (!report.is_open()) {
        std::cerr << "[ERROR] Failed to open report file.\n";
        return;
    }
    report << "OriginalPath,ExtractedPath,Company,FileDescription,ProductName,Copyright\n";

    DWORD drives = GetLogicalDrives();
    int totalFiles = 0, thirdPartyCount = 0, microsoftCount = 0, vulnCount = 0;
    std::vector<std::string> vulnSkippedFiles;

    for (char drive = 'A'; drive <= 'Z'; drive++) {
        if (!(drives & (1 << (drive - 'A'))))
            continue;
        std::string drivePath = std::string(1, drive) + ":\\";
        if (GetDriveTypeA(drivePath.c_str()) == DRIVE_FIXED) {
            std::cout << "\nScanning drive: " << drivePath << "\n";
            std::vector<std::string> sysFiles = FindAllSysFiles(drivePath);
            std::cout << "[DEBUG] Found " << sysFiles.size() << " .sys files on " << drivePath << "\n";

            for (size_t i = 0; i < sysFiles.size(); i++) {
                std::string filePath = sysFiles[i];
                std::string company = GetFileCompanyName(filePath);
                std::string fileDesc = GetFileDescription(filePath);
                std::string product = GetProductName(filePath);
                std::string copyright = GetCopyright(filePath);

                std::cout << "[DEBUG] File: " << filePath
                    << " | Company: " << company
                    << " | Description: " << fileDesc
                    << " | Product: " << product
                    << " | Copyright: " << copyright << "\n";
                totalFiles++;

                if (IsLikelyMicrosoftDriver(filePath)) {
                    microsoftDrivers.insert(filePath);
                    microsoftCount++;
                    continue;
                }
                if (!vendorFilter.empty() && !MatchesVendorFilter(filePath))
                    continue;
                if (useVulnExclusion && IsVulnerableDriver(filePath)) {
                    std::cout << "[DEBUG] Skipping vulnerable driver: " << fs::path(filePath).filename().string() << "\n";
                    vulnCount++;
                    vulnSkippedFiles.push_back(fs::path(filePath).filename().string());
                    continue;
                }

                std::string destPath = REPO_FOLDER + fs::path(filePath).filename().string();
                std::cout << "[DEBUG] Attempting to copy: " << filePath << " -> " << destPath << "\n";
                try {
                    fs::copy_file(filePath, destPath, fs::copy_options::overwrite_existing);
                    report << "\"" << filePath << "\",\"" << destPath << "\",\""
                        << company << "\",\"" << fileDesc << "\",\"" << product << "\",\""
                        << copyright << "\"\n";
                    SetConsoleColor(10);
                    std::cout << "[+] Extracted: " << filePath << " -> " << destPath << " (" << company << ")\n";
                    SetConsoleColor(7);
                    thirdPartyCount++;
                }
                catch (const std::filesystem::filesystem_error& e) {
                    std::cerr << "[ERROR] Failed to copy " << filePath << " -> " << destPath << ": " << e.what() << "\n";
                }

                if (i % 50 == 0 || i == sysFiles.size() - 1) {
                    SetConsoleColor(14);
                    std::cout << "\r[Progress] Scanned: " << i + 1 << "/" << sysFiles.size()
                        << " | Third-Party: " << thirdPartyCount
                        << " | Microsoft: " << microsoftCount << std::flush;
                    SetConsoleColor(7);
                }
            }
        }
    }

    report.close();
    SaveBaseline();

    std::cout << "\n\nExtraction Complete. Report saved to drivers_report.csv\n";
    std::cout << "Total Scanned: " << totalFiles << " | Third-Party: " << thirdPartyCount
        << " | Microsoft: " << microsoftCount << "\n";

    if (useVulnExclusion) {
        std::cout << "Vulnerable Drivers Excluded: " << vulnCount << "\n";
        if (!vulnSkippedFiles.empty()) {
            std::cout << "Files skipped due to vulnerability:\n";
            for (const auto& fname : vulnSkippedFiles)
                std::cout << "  " << fname << " (VULNERABLE)\n";
        }
    }
}

// ***********************
// Main Function
// ***********************
int main(int argc, char* argv[]) {
    ParseArguments(argc, argv);
    ExtractThirdPartyDrivers();
    return 0;
}
