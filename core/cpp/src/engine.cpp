#include "sentinel/engine.hpp"
#include <algorithm>
#include <cctype>

namespace {
std::string upper(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
  return value;
}
bool untrusted(const std::string& destination) {
  auto value = upper(destination);
  return value == "UNTRUSTED" || value == "" || value == "EXTERNAL";
}
}
namespace sentinel {
Engine::Engine(std::string policy_name) : policy_name_(std::move(policy_name)) {}
Result Engine::evaluate(const Event& event) const {
  if (upper(event.event_type) == "NETWORK_SEND" &&
      upper(event.data_classification) == "SECRET" && untrusted(event.destination)) {
    return {Decision::Block, policy_name_, "SECRET_EXFILTRATION"};
  }
  return {Decision::Allow, policy_name_, ""};
}
}
