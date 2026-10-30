// The C++ side of the inspector: a few functions with C linkage between the inspector
// and libmodsecurity, which has a C++ interface. The functions never throw: every
// exception is caught here and comes back as a fixed code or a null pointer, so that
// nothing unwinds into Rust. The text of an error of libmodsecurity holds the paths of
// the rules and is dropped here.

#include <memory>

#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>

namespace {

// libmodsecurity writes the text of a matched rule, with the values of the request, to
// the standard error unless a log callback is set. Nothing is to be written.
void discard_log(void *, const void *) {}

constexpr int kOk = 0;
constexpr int kRulesRefused = 1;
constexpr int kFailed = 2;

}  // namespace

extern "C" {

// The version of the libmodsecurity headers this bridge was built with.
const char *tkv_engine_version() noexcept { return MODSECURITY_VERSION; }

modsecurity::ModSecurity *tkv_engine_new() noexcept {
  try {
    std::unique_ptr<modsecurity::ModSecurity> engine(modsecurity::msc_init());
    if (!engine) {
      return nullptr;
    }
    engine->setServerLogCb(discard_log, modsecurity::RuleMessageLogProperty);
    return engine.release();
  } catch (...) {
    return nullptr;
  }
}

void tkv_engine_free(modsecurity::ModSecurity *engine) noexcept {
  try {
    modsecurity::msc_cleanup(engine);
  } catch (...) {
  }
}

modsecurity::RulesSet *tkv_rules_new() noexcept {
  try {
    return modsecurity::msc_create_rules_set();
  } catch (...) {
    return nullptr;
  }
}

// Adds the rules of one file. 0 when they were added, 1 when libmodsecurity refused the
// file (it could not be read, or a rule is wrong), 2 for any other failure.
int tkv_rules_add_file(modsecurity::RulesSet *rules, const char *path) noexcept {
  try {
    const char *error = nullptr;
    if (modsecurity::msc_rules_add_file(rules, path, &error) < 0) {
      modsecurity::msc_rules_error_cleanup(error);
      return kRulesRefused;
    }
    return kOk;
  } catch (...) {
    return kFailed;
  }
}

void tkv_rules_free(modsecurity::RulesSet *rules) noexcept {
  try {
    modsecurity::msc_rules_cleanup(rules);
  } catch (...) {
  }
}

}  // extern "C"
