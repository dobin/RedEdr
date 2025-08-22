
#include <krabs.hpp>
#include <json.hpp>

nlohmann::json KrabsEtwEventToJsonStr(const EVENT_RECORD& record, krabs::schema schema);
