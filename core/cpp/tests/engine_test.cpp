#include "sentinel/engine.hpp"
#include <cassert>
int main() {
  sentinel::Engine engine;
  auto blocked = engine.evaluate({"NETWORK_SEND", "r", "API_KEY", "UNTRUSTED", "SECRET", "o"});
  assert(blocked.decision == sentinel::Decision::Block);
  assert(blocked.reason == "SECRET_EXFILTRATION");
  auto trusted = engine.evaluate({"NETWORK_SEND", "r", "API_KEY", "TRUSTED", "SECRET", "o"});
  assert(trusted.decision == sentinel::Decision::Allow);
  auto normal = engine.evaluate({"NETWORK_SEND", "r", "", "UNTRUSTED", "PUBLIC", "o"});
  assert(normal.decision == sentinel::Decision::Allow);
}
