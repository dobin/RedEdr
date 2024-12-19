//
// jsonw.hpp - single header c++ json library
// See README.md for detail
//
#ifndef OCTILLION_JSONW_HEADER
#define OCTILLION_JSONW_HEADER

#include <iostream> 
#include <fstream>   // read json from file 
#include <sstream>   // string buffer
#include <cmath>     // pow
#include <queue>     // token container
#include <string>    // string and wstring
#include <map>       // json object container
#include <vector>    // array container
#include <locale>    // ucs utf8 convertor
#include <codecvt>   // ucs utf8 convertor
#include <memory>    // smart pointer

// JsonTokenW presents a token in json data. It has a static member function 
// 'parse()' that can parse the json from text to token. However, JsonW caller 
// does not need to access this class at all. See README.md for detail.
class JsonTokenW
{
public:
    enum class Type
    {
        NumberInteger,
        NumberFloat,
        String,
        LeftCurlyBracket,
        RightCurlyBracket,
        LeftSquareBracket,
        RightSquareBracket,
        Colon,
        Comma,
        Boolean,
        Null,
        Bad
    };

public:
    // parse json text from wistream instead of istream
    JsonTokenW(std::wistream& ins)
    {
        type_ = Type::Bad;
        wchar_t character;

        if (!ins.good())
        {
            return;
        }

        character = ins.peek();

        // return false if no more data to read
        if (character == std::char_traits<wchar_t>::eof())
        {
            return;
        }

        // handle single character token
        switch (character)
        {
        case L'{': type_ = Type::LeftCurlyBracket;  ins.get(); return;
        case L'}': type_ = Type::RightCurlyBracket; ins.get(); return;
        case L'[': type_ = Type::LeftSquareBracket;   ins.get(); return;
        case L']': type_ = Type::RightSquareBracket;  ins.get(); return;
        case L':': type_ = Type::Colon;              ins.get(); return;
        case L',': type_ = Type::Comma;              ins.get(); return;
        }

        // handle number
        if (iswdigit(character) || character == L'-')
        {
            std::wstring numberstr;
            std::wstring expstr;
            bool containdot = false;
            bool containexp = false;
            bool negativeexp = false;
            int exponent = 0;

            // negative value
            if (character == L'-')
            {
                numberstr.push_back(character);
                ins.get();
                character = ins.peek();
            }

            // if start with 0, it must followed by . or standalone zero
            if (character == L'0')
            {
                numberstr.push_back(character);
                ins.get();
                character = ins.peek();

                if (character != L'.')
                {
                    type_ = Type::NumberInteger;
                    integer_ = 0;
                    return;
                }

                containdot = true;
                numberstr.push_back(character);
                ins.get();
                character = ins.peek();
            }

            while (iswdigit(character) || character == L'.' || character == L'e')
            {
                // handle .
                if (character == L'.')
                {
                    if (containdot || numberstr.length() == 0)
                    {
                        return;
                    }
                    else if (numberstr.length() == 1 && !iswdigit(numberstr.at(0)))
                    {
                        return;
                    }
                    else
                    {
                        containdot = true;
                    }
                }

                if (character == L'e' || character == L'E')
                {
                    containexp = true;
                    break;
                }

                numberstr.push_back(character);
                ins.get();
                character = ins.peek();
            }

            // last character in numberstr has to be a digit
            if (numberstr.length() == 0 || !iswdigit(numberstr.back()))
            {
                return;
            }

            // first digit cannot be zero except frac or zero
            if (!containdot && numberstr.at(0) == L'0' && numberstr.length() > 1)
            {
                return;
            }

            // handle exponent notation
            if (character == L'e' || character == L'E')
            {
                ins.get();
                character = ins.peek();
                if (character == L'-')
                {
                    negativeexp = true;
                    ins.get();
                    character = ins.peek();
                }

                if (character == L'+')
                {
                    ins.get();
                    character = ins.peek();
                }

                while (iswdigit(character))
                {
                    expstr.push_back(character);
                    ins.get();
                    character = ins.peek();
                }

                if (expstr.length() == 0)
                {
                    return;
                }

                try
                {
                    exponent = std::stoi(expstr);
                }
                catch (const std::out_of_range& oor)
                {
                    std::cerr << "Out of Range error: " << oor.what() << '\n';
                    type_ = Type::Bad;
                    return;
                }
            }

            if (containdot)
            {
                try
                {
                    frac_ = std::stold(numberstr);
                }
                catch (const std::out_of_range&)
                {
                    type_ = Type::Bad;
                    return;
                }

                type_ = Type::NumberFloat;
            }
            else
            {
                try
                {
                    integer_ = std::stoll(numberstr);
                }
                catch (const std::out_of_range&)
                {
                    type_ = Type::Bad;
                    return;
                }

                type_ = Type::NumberInteger;
            }

            if (containexp)
            {
                double multiplier;
                if (negativeexp)
                {
                    multiplier = std::pow(10, -1 * exponent);
                }
                else
                {
                    multiplier = std::pow(10, exponent);
                }

                if (multiplier == HUGE_VAL || multiplier == -HUGE_VAL)
                {
                    std::cerr << "Out of Range error" << std::endl;
                    type_ = Type::Bad;
                    return;
                }

                if (type_ == Type::NumberInteger)
                {
                    frac_ = 1.0 * integer_;
                    type_ = Type::NumberFloat;
                }

                frac_ = frac_ * multiplier;
            }

            return;
        }

        // handle 'true'
        if (character == L't')
        {
            ins.get();
            character = ins.peek();
            if (character == std::char_traits<wchar_t>::eof() || character != L'r')
            {
                return;
            }

            ins.get();
            character = ins.peek();
            if (character == std::char_traits<wchar_t>::eof() || character != L'u')
            {
                return;
            }

            ins.get();
            character = ins.peek();
            if (character == std::char_traits<wchar_t>::eof() || character != L'e')
            {
                return;
            }

            ins.get();
            type_ = Type::Boolean;
            boolean_ = true;
            return;
        }

        // handle 'false'
        if (character == L'f')
        {
            ins.get();
            character = ins.peek();
            if (character == std::char_traits<wchar_t>::eof() || character != L'a')
            {
                return;
            }

            ins.get();
            character = ins.peek();
            if (character == std::char_traits<wchar_t>::eof() || character != L'l')
            {
                return;
            }

            ins.get();
            character = ins.peek();
            if (character == std::char_traits<wchar_t>::eof() || character != L's')
            {
                return;
            }

            ins.get();
            character = ins.peek();
            if (character == std::char_traits<wchar_t>::eof() || character != L'e')
            {
                return;
            }

            ins.get();
            type_ = Type::Boolean;
            boolean_ = false;
            return;
        }

        // handle 'null'
        if (character == L'n')
        {
            ins.get();
            character = ins.peek();
            if (character == std::char_traits<wchar_t>::eof() || character != L'u')
            {
                return;
            }

            ins.get();
            character = ins.peek();
            if (character == std::char_traits<wchar_t>::eof() || character != L'l')
            {
                return;
            }

            ins.get();
            character = ins.peek();
            if (character == std::char_traits<wchar_t>::eof() || character != L'l')
            {
                return;
            }

            ins.get();
            type_ = Type::Null;
            return;
        }

        // the only remaining possible token is string, must start with \"
        if (character != L'\"')
        {
            return;
        }

        // consume \"
        ins.get();
        character = ins.peek();

        // handle string
        bool backslash = false;
        std::wstring strbuf;

        while (character != std::char_traits<wchar_t>::eof())
        {
            if (backslash)
            {
                // previous character is backslash
                if (character == L'u')
                {
                    // special case for \u
                    std::wstring hexbuf(L"0x");
                    ins.get();
                    hexbuf.push_back(ins.get());
                    hexbuf.push_back(ins.get());
                    hexbuf.push_back(ins.get());
                    hexbuf.push_back(ins.get());

                    if (hexbuf.at(2) == std::char_traits<wchar_t>::eof() ||
                        hexbuf.at(3) == std::char_traits<wchar_t>::eof() ||
                        hexbuf.at(4) == std::char_traits<wchar_t>::eof() ||
                        hexbuf.at(5) == std::char_traits<wchar_t>::eof())
                    {
                        return;
                    }

                    try
                    {
                        unsigned int charvalue = std::stoul(hexbuf, NULL, 16);
                        strbuf.push_back((wchar_t)charvalue);
                        character = ins.peek();
                        backslash = false;
                        continue;
                    }
                    catch (const std::invalid_argument&)
                    {
                        return;
                    }
                    catch (const std::out_of_range&)
                    {
                        return;
                    }
                }

                // other single character cases
                switch (character)
                {
                case L'\"': strbuf.push_back(L'\"'); break;
                case L'\\': strbuf.push_back(L'\\'); break;
                case L'/': strbuf.push_back(L'/'); break;
                case L'b':  strbuf.push_back((wchar_t)0x08); break;
                case L'f':  strbuf.push_back((wchar_t)0x0c); break;
                case L'n':  strbuf.push_back(L'\n'); break;
                case L'r':  strbuf.push_back(L'\r'); break;
                case L't':  strbuf.push_back(L'\t'); break;
                }

                ins.get();
                character = ins.peek();
                backslash = false;
                continue;
            }
            else if (character == L'\\')
            {
                // special , set flag and fo next round
                backslash = true;
                ins.get();
                character = ins.peek();
                continue;
            }
            else if (character == L'\r' || character == L'\n')
            {
                // unexpected EOL
                return;
            }
            else if (character == L'\"')
            {
                ins.get();
                type_ = Type::String;
                wstring_ = strbuf;
                return;
            }
            else
            {
                strbuf.push_back(character);
                ins.get();
                character = ins.peek();
            }
        }

        // unexpected EOF
        return;
    }

public:
    enum Type type() const { return type_; }
    int_fast64_t integer() const { return integer_; }
    long double frac() const { return frac_; }
    std::wstring wstring() const { return wstring_; }
    bool boolean() const { return boolean_; }

private:
    // determine if  character is white space for json
    static bool isskippable(wchar_t character)
    {
        if (character == L' ' || character == L'\r' || character == L'\n' || character == L'\t')
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    // skip the white space and check if next non-ws is valid 
    // beginning character for json token
    static bool findnext(std::wistream& ins)
    {
        wchar_t character;
        if (!ins.good())
        {
            return false;
        }

        character = ins.peek();

        // return false if no more data to read
        if (character == std::char_traits<wchar_t>::eof())
        {
            return false;
        }

        // skip white space 
        while (isskippable(character))
        {
            ins.get();
            character = ins.peek();

            if (character == std::char_traits<wchar_t>::eof())
            {
                return false;
            }
        }

        // check next character is valid begin character for token 
        if (character == L'[' || character == L']' ||
            character == L'{' || character == L'}' ||
            character == L':' || iswdigit(character) ||
            character == L',' || character == L'\"' ||
            character == L'-' || character == L't' ||
            character == L'f' || character == L'n')
        {
            return true;
        }
        else
        {
            return false;
        }
    }

public:
    // parse text data from wistream and store tokens in queue
    static bool parse(std::wistream& ins, std::queue<JsonTokenW>& tokens)
    {
        bool success = findnext(ins);

        while (success)
        {
            JsonTokenW token(ins);

            if (token.type() == JsonTokenW::Type::Bad)
            {
                std::queue<JsonTokenW>().swap(tokens); // clear
                return false;
            }
            else
            {
                tokens.push(token);
            }

            success = findnext(ins);
        }
        return true;
    }

private:
    enum Type type_ = Type::Bad;
    int_fast64_t integer_ = 0;
    long double frac_ = 0.0;
    std::wstring wstring_;
    bool boolean_ = true;
};

// JsonW is one and the only one class that caller should access. It
// represents a json 'value' defined in json standard. In other words,
// JsonW could be a number, a string, a boolean, a null, a json array or
// an json object. See README.md for the usage.
class JsonW
{
public:
    // type of jsonw
    const static int BAD = 0;
    const static int OBJECT = 1;
    const static int ARRAY = 2;
    const static int INTEGER = 3;
    const static int FLOAT = 4;
    const static int STRING = 5;
    const static int BOOLEAN = 6;
    const static int NULLVALUE = 7;

public:
    // construtor and destructor
    // 1. default constructor - NULL value
    // 2. copy constructor - deep copy
    // 3. construct by utf8 file input stream 
    // 4. construct by utf8 string (std::string / const char*)
    // 5. construct by ucs string (std::wstring / const wchar_t*)
    // 6. construct by a sequence of token (JsonTokenW)
    // 7. destrcutor that calls help function clean()
    JsonW()
    {
        type_ = NULLVALUE;
        valid_ = true;
    }

    explicit JsonW(const JsonW& rhs)
    {
        copy(rhs);
    }

    explicit JsonW(std::ifstream& fin)
    {
        if (!fin.good())
        {
            return;
        }

        // convert to std::string
        std::string utf8str(
            (std::istreambuf_iterator<char>(fin)),
            (std::istreambuf_iterator<char>()));

        // convert to wstring
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        std::wstring wstr = conv.from_bytes(utf8str);

        // convert to wstringbuf
        std::wstringbuf strBuf(wstr.data());

        // convert to wistream
        std::wistream wins(&strBuf);

        // constructor with std::wstring parameter
        init(wins);
    }

    explicit JsonW(const char* utf8str)
    {
        // convert to wstring
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        std::wstring wstr = conv.from_bytes(utf8str);

        // convert to wstringbuf
        std::wstringbuf strBuf(wstr.data());

        // convert to wistream
        std::wistream wins(&strBuf);

        // constructor with std::wstring parameter
        init(wins);
    }

    explicit JsonW(const wchar_t* wstr)
    {
        // convert to wstringbuf
        std::wstringbuf strBuf(wstr);

        // convert to wistream
        std::wistream wins(&strBuf);

        // constructor with wistream parameter 
        init(wins);
    }

    JsonW(const wchar_t* ucsdata, size_t size)
    {
        // convert to std::wstring
        std::wstring wstr(ucsdata, size);

        // convert to wstringbuf
        std::wstringbuf strBuf(wstr);

        // convert to wistream
        std::wistream wins(&strBuf);

        // constructor with wistream parameter 
        init(wins);
    }

    JsonW(const char* utf8data, size_t length)
    {
        // convert to std::string
        std::string utf8str(utf8data, length);

        // convert to wstring
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        std::wstring wstr = conv.from_bytes(utf8str);

        // convert to wstringbuf
        std::wstringbuf strBuf(wstr.data());

        // convert to wistream
        std::wistream wins(&strBuf);

        // constructor with std::wstring parameter
        init(wins);
    }

    ~JsonW()
    {
        clean();
    }

public:
    JsonW(std::queue<JsonTokenW>& tokens)
    {
        parse(tokens);
    }

private:
    // read json data from a sequence of tokens
    void parse(std::queue<JsonTokenW>& tokens)
    {
        clean();
        type_ = BAD;

        if (tokens.empty())
            return;

        valid_ = true;

        switch (tokens.front().type())
        {
        case JsonTokenW::Type::LeftCurlyBracket: // object
            valid_ = jobject(tokens, jobject_);
            if (valid_)
            {
                type_ = OBJECT;
            }
            return;
        case JsonTokenW::Type::LeftSquareBracket: // array
            valid_ = jarray(tokens, jarray_);
            if (valid_)
            {
                type_ = ARRAY;
            }
            return;
        case JsonTokenW::Type::NumberInteger:
            type_ = INTEGER;
            integer_ = tokens.front().integer();
            tokens.pop();
            return;
        case JsonTokenW::Type::NumberFloat:
            type_ = FLOAT;
            frac_ = tokens.front().frac();
            tokens.pop();
            return;
        case JsonTokenW::Type::String:
            type_ = STRING;
            wstring_ = tokens.front().wstring();
            tokens.pop();
            return;
        case JsonTokenW::Type::Boolean:
            type_ = BOOLEAN;
            boolean_ = tokens.front().boolean();
            tokens.pop();
            return;
        case JsonTokenW::Type::Null:
            type_ = NULLVALUE;
            tokens.pop();
            return;
        default: // bad token
            valid_ = false;
            return;
        }
    }

    // deep copy from another JsonW
    void copy(const JsonW& rhs)
    {
        clean();

        type_ = rhs.type_;
        valid_ = rhs.valid_;
        integer_ = rhs.integer_;
        frac_ = rhs.frac_;
        wstring_ = rhs.wstring_;
        boolean_ = rhs.boolean_;

        for (const auto& it : rhs.jobject_)
        {
            std::wstring name = it.first;

            std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>(*(it.second.get()));
            jobject_[name] = jvalue;
        }

        for (const auto& it : rhs.jarray_)
        {
            std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>(*(it.get()));
            jarray_.push_back(jvalue);
        }
    }

public:
    // return false if json data is invalid
    bool valid() const { return valid_; }

    // get type of jsonw
    int type() const { return type_; }

    //
    // simple data accessors
    //

    // get the number of data in this json value
    // for number, string and boolean, return 1
    // for array, return the number of values inside it
    // for object, return the number of name-value pairs inside it
    // others return 0
    size_t size() const
    {
        switch (type_)
        {
        case BAD:
            return 0;
        case OBJECT:
            return jobject_.size();
        case ARRAY:
            return jarray_.size();
        case INTEGER:
        case FLOAT:
        case STRING:
        case BOOLEAN:
            return 1;
        case NULLVALUE:
        default:
            return 0;
        }
    }

    long long integer() const { return integer_; }
    long double frac() const { return frac_; }
    std::wstring wstr() const { return wstring_; }
    std::string str() const
    {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        return conv.to_bytes(wstring_);
    }
    bool boolean() const { return boolean_; }

    void integer(long long integer)
    {
        clean();
        type_ = INTEGER;
        integer_ = integer;
    }

    void frac(long double frac)
    {
        clean();
        type_ = FLOAT;
        frac_ = frac;
    }

    void wstr(const std::wstring& wstr)
    {
        clean();
        type_ = STRING;
        wstring_ = wstr;
    }

    void wstr(const wchar_t* wstr)
    {
        clean();
        type_ = STRING;
        wstring_ = wstr;
    }

    void wstr(const wchar_t* wstr, size_t length)
    {
        clean();
        type_ = STRING;
        std::wstring usc(wstr, length);
        wstring_ = usc;
    }

    void str(const std::string& str)
    {
        clean();
        type_ = STRING;
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        wstring_ = conv.from_bytes(str);
    }

    void str(const char* str)
    {
        clean();
        type_ = STRING;
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        wstring_ = conv.from_bytes(str);
    }

    void str(const char* str, size_t length)
    {
        clean();
        type_ = STRING;
        std::string utf8(str, length);
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        wstring_ = conv.from_bytes(utf8);
    }

    void boolean(bool boolean)
    {
        clean();
        type_ = BOOLEAN;
        boolean_ = boolean;
    }

    void reset()
    {
        clean();
    }

    void json(const std::string& text)
    {
        clean();

        // convert to wstring
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        std::wstring wstr = conv.from_bytes(text);

        // convert to wstringbuf
        std::wstringbuf strBuf(wstr.data());

        // convert to wistream
        std::wistream wins(&strBuf);

        // constructor with std::wstring parameter
        init(wins);
    }

    void json(const char* text)
    {
        std::string utf8(text);
        json(utf8);
    }

    void json(const char* text, size_t size)
    {
        std::string utf8(text, size);
        json(utf8);
    }

    //
    // json object accessor member
    //

    // return all available keys in either ucs or utf8 enconding
    void wkeys(std::vector<std::wstring>& keys) const
    {
        auto it = jobject_.begin();

        while (it != jobject_.end())
        {
            keys.push_back(it->first);
            it++;
        }

        return;
    }

    void keys(std::vector<std::string>& keys) const
    {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        auto it = jobject_.begin();

        while (it != jobject_.end())
        {
            keys.push_back(conv.to_bytes(it->first));
            it++;
        }

        return;
    }

    // get json value via specific key, return nullptr if
    // no such entry or 'this' is not an json object
    std::shared_ptr<JsonW> get(const std::wstring& wkey) const
    {
        auto it = jobject_.find(wkey);
        if (it == jobject_.end())
        {
            return nullptr;
        }

        return it->second;
    }

    std::shared_ptr<JsonW> get(const std::string& key) const
    {
        // convert to wstring
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        std::wstring wkey = conv.from_bytes(key.data());
        return get(wkey);
    }

    // delete a name-pair value inside json object by the name
    // return false if no such value
    bool erase(std::wstring wkey)
    {
        auto it = jobject_.find(wkey);
        if (it == jobject_.end())
        {
            return false;
        }

        jobject_.erase(it);
        return true;
    }

    bool erase(std::string key)
    {
        // convert to wstring
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        std::wstring wkey = conv.from_bytes(key.data());
        return erase(wkey);
    }

    // set json value using specific key, return false
    // if key length is 0
    bool add(std::wstring wkey, std::shared_ptr<JsonW> jvalue)
    {
        if (wkey.length() == 0)
        {
            return false;
        }

        if (type_ != OBJECT)
        {
            clean();
            type_ = OBJECT;
        }

        auto it = jobject_.find(wkey);
        jobject_[wkey] = jvalue;
        return true;
    }

    bool add(std::string key, std::shared_ptr<JsonW> jvalue)
    {
        // convert to wstring
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        std::wstring wkey = conv.from_bytes(key.data());

        return add(wkey, jvalue);
    }

    bool add(std::wstring wkey, long long integer)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->integer(integer);
        return add(wkey, jvalue);
    }

    bool add(std::wstring wkey, long integer)
    {
        return add(wkey, (long long)integer);
    }

    bool add(std::wstring wkey, int integer)
    {
        return add(wkey, (long long)integer);
    }

    bool add(std::wstring wkey, short integer)
    {
        return add(wkey, (long long)integer);
    }

    bool add(std::string key, long long integer)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->integer(integer);
        return add(key, jvalue);
    }

    bool add(std::string key, long integer)
    {
        return add(key, (long long)integer);
    }

    bool add(std::string key, int integer)
    {
        return add(key, (long long)integer);
    }

    bool add(std::string key, short integer)
    {
        return add(key, (long long)integer);
    }

    bool add(std::wstring wkey, long double frac)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->frac(frac);
        return add(wkey, jvalue);
    }

    bool add(std::wstring wkey, double frac)
    {
        return add(wkey, (long double)frac);
    }

    bool add(std::wstring wkey, float frac)
    {
        return add(wkey, (long double)frac);
    }

    bool add(std::string key, long double frac)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->frac(frac);
        return add(key, jvalue);
    }

    bool add(std::string key, double frac)
    {
        return add(key, (long double)frac);
    }

    bool add(std::string key, float frac)
    {
        return add(key, (long double)frac);
    }

    bool add(std::wstring wkey, std::wstring wstr)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->wstr(wstr);
        return add(wkey, jvalue);
    }

    bool add(std::string key, std::string str)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->str(str);
        return add(key, jvalue);
    }

    bool add(std::wstring wkey, bool boolean)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->boolean(boolean);
        return add(wkey, jvalue);
    }

    bool add(std::string key, bool boolean)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->boolean(boolean);
        return add(key, jvalue);
    }

    //
    // json array accessors
    //

    // retrieve the json value in array
    std::shared_ptr<JsonW> get(size_t idx) const
    {
        if (idx >= jarray_.size())
        {
            return nullptr;
        }

        return jarray_.at(idx);
    }

    // add one json value into array
    bool add(std::shared_ptr<JsonW> junit)
    {
        if (type_ != ARRAY)
        {
            clean();
            type_ = ARRAY;
        }

        if (junit == nullptr)
        {
            // NULLVALUE json value
            jarray_.push_back(std::make_shared<JsonW>());
        }
        else
        {
            jarray_.push_back(junit);
        }

        valid_ = true;
        return true;
    }

    bool add(long long integer)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->integer(integer);
        return add(jvalue);
    }

    bool add(long integer)
    {
        return add((long long)integer);
    }

    bool add(int integer)
    {
        return add((long long)integer);
    }

    bool add(short integer)
    {
        return add((long long)integer);
    }

    bool add(long double frac)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->frac(frac);
        return add(jvalue);
    }

    bool add(double frac)
    {
        return add((long double)frac);
    }

    bool add(float frac)
    {
        return add((long double)frac);
    }

    bool add(std::wstring wstr)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->wstr(wstr);
        return add(jvalue);
    }

    bool add(std::string str)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->str(str);
        return add(jvalue);
    }

    bool add(bool boolean)
    {
        std::shared_ptr<JsonW> jvalue = std::make_shared<JsonW>();
        jvalue->boolean(boolean);
        return add(jvalue);
    }

    // delete a value inside json array by index, 
    // return false if no such value.
    bool erase(size_t idx)
    {
        if (type_ != ARRAY)
        {
            return false;
        }

        if (size() <= idx)
        {
            return false;
        }

        jarray_.erase(jarray_.begin() + idx);

        return true;
    }

public:
    //
    // operator overloading
    //
    JsonW& operator=(short value)
    {
        clean();

        type_ = INTEGER;
        valid_ = true;
        integer_ = value;

        return *this;
    }

    JsonW& operator=(int value)
    {
        clean();

        type_ = INTEGER;
        valid_ = true;
        integer_ = value;

        return *this;
    }

    JsonW& operator=(long value)
    {
        clean();

        type_ = INTEGER;
        valid_ = true;
        integer_ = value;

        return *this;
    }

    JsonW& operator=(long long value)
    {
        clean();

        type_ = INTEGER;
        valid_ = true;
        integer_ = value;

        return *this;
    }

    JsonW& operator=(long double value)
    {
        clean();

        type_ = FLOAT;
        valid_ = true;
        frac_ = value;

        return *this;
    }

    JsonW& operator=(double value)
    {
        clean();

        type_ = FLOAT;
        valid_ = true;
        frac_ = value;

        return *this;
    }

    JsonW& operator=(float value)
    {
        clean();

        type_ = FLOAT;
        valid_ = true;
        frac_ = value;

        return *this;
    }

    JsonW& operator=(const wchar_t* value)
    {
        clean();

        type_ = STRING;
        valid_ = true;
        wstring_ = value;

        return *this;
    }

    JsonW& operator=(const std::wstring& value)
    {
        clean();

        type_ = STRING;
        valid_ = true;
        wstring_ = value;

        return *this;
    }

    JsonW& operator=(const char* value)
    {
        clean();

        type_ = STRING;
        valid_ = true;
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        wstring_ = conv.from_bytes(value);

        return *this;
    }

    JsonW& operator=(std::string value)
    {
        clean();

        type_ = STRING;
        valid_ = true;
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        wstring_ = conv.from_bytes(value.data());

        return *this;
    }

    JsonW& operator=(bool boolean)
    {
        clean();

        type_ = BOOLEAN;
        valid_ = true;
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        boolean_ = boolean;

        return *this;
    }

    JsonW& operator=(const JsonW& junit)
    {
        copy(junit);
        return *this;
    }

    JsonW& operator[] (size_t index)
    {
        if (type_ != ARRAY)
        {
            clean();
            type_ = ARRAY;
            valid_ = true;
        }

        if (index >= size())
        {
            for (size_t i = size(); i <= index; i++)
            {
                add(std::make_shared<JsonW>());
            }
        }

        return *(get(index));
    }

    JsonW& operator[] (int index)
    {
        if (index < 0)
        {
            return bad();
        }

        if (type_ != ARRAY)
        {
            clean();
            type_ = ARRAY;
            valid_ = true;
        }

        if (index >= (int)size())
        {
            for (size_t i = size(); i <= (size_t)index; i++)
            {
                add(std::make_shared<JsonW>());
            }
        }

        return *(get(index));
    }

    JsonW& operator[] (const char* name)
    {
        // convert to wstring
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        std::wstring wname = conv.from_bytes(name);

        if (wname.length() == 0)
        {
            return bad();
        }

        if (type_ != OBJECT)
        {
            clean();
            type_ = OBJECT;
            valid_ = true;
        }

        if (jobject_.find(wname) == jobject_.end())
        {
            jobject_.insert(std::pair<std::wstring, std::shared_ptr<JsonW>>(wname, std::make_shared<JsonW>()));
        }

        return *(jobject_.find(wname)->second);
    }

    JsonW& operator[] (const std::string& name)
    {
        // convert to wstring
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        std::wstring wname = conv.from_bytes(name);

        if (wname.length() == 0)
        {
            return bad();
        }

        if (type_ != OBJECT)
        {
            clean();
            type_ = OBJECT;
            valid_ = true;
        }

        if (jobject_.find(wname) == jobject_.end())
        {
            jobject_.insert(std::pair<std::wstring, std::shared_ptr<JsonW>>(wname, std::make_shared<JsonW>()));
        }

        return *(jobject_.find(wname)->second);
    }

    JsonW& operator[] (const wchar_t* name)
    {
        // convert to wstring
        std::wstring wname(name);

        if (wname.length() == 0)
        {
            return bad();
        }

        if (type_ != OBJECT)
        {
            clean();
            type_ = OBJECT;
            valid_ = true;
        }

        if (jobject_.find(wname) == jobject_.end())
        {
            jobject_.insert(std::pair<std::wstring, std::shared_ptr<JsonW>>(wname, std::make_shared<JsonW>()));
        }

        return *(jobject_.find(wname)->second);
    }

    JsonW& operator[] (const std::wstring& wname)
    {
        if (wname.length() == 0)
        {
            return bad();
        }

        if (type_ != OBJECT)
        {
            clean();
            type_ = OBJECT;
            valid_ = true;
        }

        if (jobject_.find(wname) == jobject_.end())
        {
            jobject_.insert(std::pair<std::wstring, std::shared_ptr<JsonW>>(wname, std::make_shared<JsonW>()));
        }

        return *(jobject_.find(wname)->second);
    }

    // format json data into utf8 text in json standard
    std::wstring wtext(bool singleline = true) const
    {
        std::wstringstream wss;
        wss_jvalue(wss, *this, singleline);
        return wss.str();
    }

    // format json data into ucs text
    std::string text(bool singleline = true) const
    {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        return conv.to_bytes(wtext(singleline));
    }

    friend std::ostream& operator<<(std::ostream& os, const JsonW& rhs)
    {
        os << rhs.text();
        return os;
    }

    friend std::wostream& operator<<(std::wostream& wos, const JsonW& rhs)
    {
        wos << rhs.wtext();
        return wos;
    }

public:
    // Singleton bad JsonW instance
    static JsonW& bad()
    {
        static JsonW instance;
        instance.type_ = BAD;
        instance.valid_ = false;
        return instance;
    }

private:
    // private static help function - parse token into json object 
    static bool jobject(std::queue<JsonTokenW>& tokens, std::map<std::wstring, std::shared_ptr<JsonW>>& jobject)
    {
        // Object must start with LeftCurlyBracket:'{' and minimum size is 2 '{' + '}'
        if (tokens.size() < 2 ||
            tokens.front().type() != JsonTokenW::Type::LeftCurlyBracket)
        {
            return false;
        }
        tokens.pop();

        while (!tokens.empty())
        {
            std::wstring key;
            switch (tokens.front().type())
            {
            case JsonTokenW::Type::RightCurlyBracket:
                tokens.pop();
                return true;
            case JsonTokenW::Type::String:
                key = tokens.front().wstring();
                if (key.length() == 0)
                {
                    return false;
                }
                else if (jobject.count(key) > 0)
                {
                    return false; // not allow duplicate key
                }

                tokens.pop();
                if (tokens.empty())
                {
                    return false;
                }
                else if (tokens.front().type() != JsonTokenW::Type::Colon)
                {
                    return false;
                }

                tokens.pop();
                if (tokens.empty())
                {
                    return false;
                }
                else
                {
                    std::shared_ptr<JsonW> junit = std::make_shared<JsonW>(tokens);

                    if (junit->valid() == false)
                    {
                        return false;
                    }
                    else
                    {
                        jobject[key] = junit;
                    }
                }

                if (!tokens.empty() && tokens.front().type() == JsonTokenW::Type::Comma)
                {
                    // consume comma and expect next key-data set
                    tokens.pop();
                }

                break;
            case JsonTokenW::Type::LeftCurlyBracket:
            case JsonTokenW::Type::LeftSquareBracket:
            case JsonTokenW::Type::RightSquareBracket:
            case JsonTokenW::Type::NumberInteger:
            case JsonTokenW::Type::NumberFloat:
            case JsonTokenW::Type::Boolean:
            case JsonTokenW::Type::Null:
            case JsonTokenW::Type::Colon:
            case JsonTokenW::Type::Comma:
            case JsonTokenW::Type::Bad:
            default:
                return false;
            }
        }

        return false;
    }

    // private static help function - parse tokens into json array
    static bool jarray(std::queue<JsonTokenW>& tokens, std::vector<std::shared_ptr<JsonW>>& jarray)
    {
        // Object must start with LeftCurlyBracket:'[' and minimum size is 2 '[' + ']'
        if (tokens.size() < 2 ||
            tokens.front().type() != JsonTokenW::Type::LeftSquareBracket)
        {
            return false;
        }
        tokens.pop();

        while (!tokens.empty())
        {
            switch (tokens.front().type())
            {
            case JsonTokenW::Type::RightSquareBracket:
                tokens.pop();
                return true;
            case JsonTokenW::Type::LeftCurlyBracket:
            case JsonTokenW::Type::LeftSquareBracket:
            case JsonTokenW::Type::NumberInteger:
            case JsonTokenW::Type::NumberFloat:
            case JsonTokenW::Type::Boolean:
            case JsonTokenW::Type::String:
            case JsonTokenW::Type::Null:
            {
                std::shared_ptr<JsonW> junit = std::make_shared<JsonW>(tokens);
                if (junit->valid() == false)
                {
                    return false;
                }

                jarray.push_back(junit);

                // if followed by comma, continually read next JsonUnitW
                if (!tokens.empty() && tokens.front().type() == JsonTokenW::Type::Comma)
                {
                    tokens.pop();
                    continue;
                }
                else if (!tokens.empty() && tokens.front().type() == JsonTokenW::Type::RightSquareBracket)
                {
                    tokens.pop();
                    return true;
                }
                else
                {
                    return false;
                }
            }

            // invalid
            case JsonTokenW::Type::RightCurlyBracket:
            case JsonTokenW::Type::Colon:
            case JsonTokenW::Type::Comma:
            case JsonTokenW::Type::Bad:
            default:
                return false;
            }
        }

        return false;
    }

    // private static help function, write value into string buffer in json format 
    static std::wstringstream& wss_jvalue(std::wstringstream& wss, const JsonW& jvalue, bool singleline = true, size_t level = 0)
    {
        if (jvalue.valid() == false)
        {
            return wss;
        }

        switch (jvalue.type())
        {
        case JsonW::INTEGER:
            wss << std::to_wstring(jvalue.integer());
            return wss;
        case JsonW::FLOAT:
            wss << std::to_wstring(jvalue.frac());
            return wss;
        case JsonW::BOOLEAN:
            if (jvalue.boolean())
            {
                wss << L"true";
                return wss;
            }
            else
            {
                wss << L"false";
                return wss;
            }
        case JsonW::NULLVALUE:
            wss << L"null";
            return wss;
        case JsonW::STRING:
            return wss_string(wss, jvalue.wstr());
        case JsonW::OBJECT:
        {
            if (singleline)
            {
                return wss_jobject(wss, jvalue);
            }
            else
            {
                return wss_jobject(wss, jvalue, singleline, level);
            }
        }
        case JsonW::ARRAY:
        {
            std::wstringstream wsstmp;
            wss_jarray(wsstmp, jvalue);
            std::wstring wstr = wsstmp.str();

            if (singleline || wstr.length() <= 20)
            {
                wss << wstr;
                return wss;
            }
            else
            {
                return wss_jarray(wss, jvalue, singleline, level);
            }
        }
        case JsonW::BAD:
        default:
            return wss;
        }
    }

    static std::wstringstream& wss_jobject(std::wstringstream& wss, const JsonW& jobject,
        bool singleline = true, size_t level = 0, bool addcomma = false)
    {
        std::vector<std::wstring> wkeys;
        jobject.wkeys(wkeys);
        size_t level_plus = 0;

        if (singleline == false)
        {
            level_plus = level + 1;
        }

        wss_intent(wss, level) << L"{";

        if (singleline == false)
        {
            wss << std::endl;
        }

        for (size_t i = 0; i < wkeys.size(); i++)
        {
            bool newline = false;
            bool comma_in_function = true;

            wss_intent(wss, level_plus);
            wss_string(wss, wkeys.at(i)) << L":";

            // 'name : value'
            // when we need to add std::endl after ':'
            // 1. value is json object
            // 2. value is json array and length + level*4 > 40
            std::shared_ptr<JsonW> jvalue = jobject.get(wkeys.at(i));

            if (singleline == false)
            {
                size_t estimate_size = 0;
                std::wstringstream wsstmp;
                wss_jvalue(wsstmp, *(jvalue.get()));
                estimate_size = wsstmp.str().length();

                if (jvalue->type() == JsonW::OBJECT && jvalue->size() > 1)
                {
                    if (jvalue->size() > 1 || estimate_size > 20)
                    {
                        newline = true;
                        wss << std::endl;
                    }
                }
                else if (jvalue->type() == JsonW::ARRAY)
                {
                    bool has_object_array = false;

                    for (size_t j = 0; j < jvalue->size(); j++)
                    {
                        if (jvalue->get(j)->type() == JsonW::ARRAY ||
                            jvalue->get(j)->type() == JsonW::OBJECT)
                        {
                            has_object_array = true;
                        }
                    }

                    if (has_object_array || wsstmp.str().length() > 20)
                    {
                        newline = true;
                        wss << std::endl;
                    }
                }
            }

            if (newline == false)
            {
                if (i < wkeys.size() - 1)
                {
                    wss_jvalue(wss, *(jvalue.get())) << L",";
                }
                else
                {
                    wss_jvalue(wss, *(jvalue.get()));
                }
            }
            else
            {
                if (i < wkeys.size() - 1)
                {
                    if (jvalue->type() == JsonW::OBJECT)
                    {
                        comma_in_function = false;
                        wss_jobject(wss, *(jvalue.get()), singleline, level_plus, true);
                    }
                    else if (jvalue->type() == JsonW::ARRAY)
                    {
                        comma_in_function = false;
                        wss_jarray(wss, *(jvalue.get()), singleline, level_plus, true);
                    }
                    else
                    {
                        wss_jvalue(wss, *(jvalue.get()), singleline, level_plus) << L",";
                    }
                }
                else
                {
                    wss_jvalue(wss, *(jvalue.get()));
                }
            }

            if (singleline == false && comma_in_function)
            {
                wss << std::endl;
            }
        }

        if (singleline)
        {
            wss << L"}";
        }
        else if (addcomma)
        {
            wss_intent(wss, level) << L"}," << std::endl;
        }
        else
        {
            wss_intent(wss, level) << L"}" << std::endl;
        }

        return wss;
    }

    static std::wstringstream& wss_jarray(std::wstringstream& wss, const JsonW& jarray,
        bool singleline = true, size_t level = 0, bool addcomma = false)
    {
        size_t size = jarray.size();
        size_t level_plus = 0;

        if (singleline == false)
        {
            level_plus = level + 1;
        }

        wss_intent(wss, level) << L"[";

        if (singleline == false)
        {
            wss << std::endl;
        }

        for (size_t i = 0; i < size; i++)
        {
            std::shared_ptr<JsonW> jvalue = jarray.get(i);
            bool newline_end = true;

            if (singleline == false)
            {
                size_t estimate_size = 0;
                std::wstringstream wsstmp;
                wss_jvalue(wsstmp, *(jvalue.get()));
                estimate_size = wsstmp.str().length();

                if (jvalue->type() == JsonW::OBJECT &&
                    (jvalue->size() > 1 || estimate_size > 20))
                {
                    newline_end = false;
                    if (i < size - 1)
                    {
                        wss_jobject(wss, *(jvalue.get()), singleline, level_plus, true);
                    }
                    else
                    {
                        wss_jobject(wss, *(jvalue.get()), singleline, level_plus);
                    }
                }
                else if (jvalue->type() == JsonW::ARRAY && estimate_size > 20)
                {
                    newline_end = false;
                    if (i < size - 1)
                    {
                        wss_jarray(wss, *(jvalue.get()), singleline, level_plus, true);
                    }
                    else
                    {
                        wss_jarray(wss, *(jvalue.get()), singleline, level_plus);
                    }
                }
                else
                {
                    wss_intent(wss, level_plus);
                    wss_jvalue(wss, *(jvalue.get()));

                    if (i < size - 1)
                    {
                        wss << L",";
                    }
                }
            }
            else
            {
                wss_jvalue(wss, *(jvalue.get()), singleline, level_plus);

                if (i < size - 1)
                {
                    wss << L",";
                }
            }

            if (singleline == false && newline_end)
            {
                wss << std::endl;
            }
        }

        if (singleline)
        {
            wss << L"]";
        }
        else if (addcomma)
        {
            wss_intent(wss, level) << L"]," << std::endl;
        }
        else
        {
            wss_intent(wss, level) << L"]" << std::endl;
        }

        return wss;
    }

    static std::wstringstream& wss_intent(std::wstringstream& wss, size_t level)
    {
        if (level == 0)
        {
            return wss;
        }

        std::wstring intent(level * 4, L' ');
        wss << intent;
        return wss;
    }

    // private static help function, write string into string buffer in json format 
    static std::wstringstream& wss_string(std::wstringstream& wss, const std::wstring& wstr)
    {
        wss << L"\"";

        for (size_t i = 0; i < wstr.length(); i++)
        {
            wchar_t wchar = wstr.at(i);

            switch (wchar)
            {
            case 0x22: wss << L"\\\""; break;
            case 0x5C: wss << L"\\\\"; break;
            case 0x2F: wss << L"\\/"; break;
            case 0x08: wss << L"\\b"; break;
            case 0x0C: wss << L"\\f"; break;
            case 0x0A: wss << L"\\n"; break;
            case 0x0D: wss << L"\\r"; break;
            case 0x09: wss << L"\\t"; break;
            default: wss << wchar;
            }
        }

        wss << L"\"";

        return wss;
    }

private:
    // private help function, release all resource 
    void clean()
    {
        jobject_.clear();
        jarray_.clear();

        type_ = NULLVALUE;
        valid_ = true;
    }

    // private help function, read json data from wistream   
    void init(std::wistream& ins)
    {
        // set locale to utf8
        std::queue<JsonTokenW> tokens;
        ins.imbue(std::locale(ins.getloc(), new std::codecvt_utf8<wchar_t>));

        // parse tokens
        JsonTokenW::parse(ins, tokens);

        // convert to junit
        parse(tokens);
    }

private:
    // private member data
    int type_ = NULLVALUE;
    bool valid_ = false;

    long long integer_ = 0;
    long double frac_ = 0.0;
    std::wstring wstring_;
    bool boolean_ = true;

    std::map<std::wstring, std::shared_ptr<JsonW>> jobject_;
    std::vector<std::shared_ptr<JsonW>> jarray_;

};

#endif // OCTILLION_JSONW_HEADER