#include <iostream>
#include <sstream>
#include <vector>

std::vector<std::wstring> output_entries;


std::wstring ConvertToJSON(const std::wstring& input)
{
    std::vector<std::pair<std::wstring, std::wstring>> keyValuePairs;
    std::wstringstream wss(input);
    std::wstring token;

    // Split by ';'
    while (std::getline(wss, token, L';'))
    {
        std::wstringstream kvStream(token);
        std::wstring key, value;

        // Split by ':'
        if (std::getline(kvStream, key, L':') && std::getline(kvStream, value))
        {
            keyValuePairs.emplace_back(key, value);
        }
    }

    // Construct JSON
    std::wstringstream jsonStream;
    jsonStream << L"{";

    bool first = true;
    for (const auto& pair : keyValuePairs)
    {
        if (!first)
        {
            jsonStream << L", ";
        }
        jsonStream << L"\"" << pair.first << L"\": \"" << pair.second << L"\"";
        first = false;
    }

    jsonStream << L"}";

    return jsonStream.str();
}


void do_output(std::wstring str) {
    // add
    //std::wcout << ConvertToJSON(str) << L"\n";
    std::wstring json = ConvertToJSON(str);
    output_entries.push_back(json);
    
    // print
    std::wcout << str << L"\n";
}


void print_all_output() {
    std::wcout << "[" << std::endl;
    for (const auto& str : output_entries) {
        std::wcout << str << ", " << std::endl;
    }
    std::wcout << "]" << std::endl;
}

