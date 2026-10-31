// The C++ side of the inspector: a few functions with C linkage between the inspector
// and libmodsecurity, which has a C++ interface. The functions never throw: every
// exception is caught here and comes back as a fixed code or a null pointer, so that
// nothing unwinds into Rust. The text of an error of libmodsecurity holds the paths of
// the rules and is dropped here.
//
// Private members that are read. The look at the built rules and the description of them (which the
// Rust side compares with what it read of the rule files) need members that libmodsecurity keeps private
// and offers no accessor for. Each is read through a member pointer made in an explicit instantiation (see
// `Open` below), which the language allows to name a private member. Every such member is here:
//
//   RuleWithActions::m_disruptiveAction   the action of a rule that stops it or lets it pass (deny, drop,
//                                         redirect, pass, allow): which one decides what a rule does and
//                                         whether it needs a message
//   RuleWithActions::m_actionsRuntimePos  the actions that run when the rule matches, in order (log,
//                                         nolog, ctl, skip, skipAfter, block, ...)
//   RuleWithActions::m_actionsSetVar      the setvar actions: how many, and the text of each (below)
//   RuleWithActions::m_actionsTag         the tag actions: how many, and the text of each (below)
//   RuleWithActions::m_transformations    the t: actions: how many (their names are not compared)
//   RuleMarker::m_name                    the name of a SecMarker, which a skipAfter has to match byte
//                                         by byte
//   RulesExceptions::m_numbers            the ids that SecRuleRemoveById takes out
//   RulesExceptions::m_ranges             and the ranges of ids
//   AuditLog::m_status                    the SecAuditEngine state
//   AuditLog::m_type                      the SecAuditLogType
//   AuditLog::m_relevant                  the SecAuditLogRelevantStatus
//   AuditLog::m_ctlAuditEngineActive      whether a ctl action turned the audit engine on
//   RuleWithOperator::m_variables         the variables of a rule, after the excluded ones are taken out
//   RuleWithOperator::m_operator          the operator of a rule: its negation and its argument
//   RuleWithActions::m_msg                the message of a rule, as a text with macros
//   RuleWithActions::m_logData            the log data of a rule, the same
//   actions::Tag::m_string                the text of a tag, the same
//   actions::disruptive::Redirect::m_string, actions::SetSID::m_string, actions::SetUID::m_string,
//   actions::SetRSC::m_string, actions::ExpireVar::m_string, actions::InitCol::m_string
//                                         the text of redirect, setsid, setuid, setrsc, expirevar and
//                                         initcol, the same
//   actions::SetVar::m_operation          what a setvar does (set, add, subtract, set to one, remove)
//   actions::SetVar::m_variable           the variable that a setvar writes to
//   actions::SetVar::m_string             the value of a setvar
//   RunTimeString::m_elements             the pieces of a text with macros: a string, or a variable
//
// The classes of variables, operators and texts are not among the installed headers. Their headers come from
// the source of the same version, which scripts/build-modsecurity.sh copies (the header files of src/ only) to a
// directory of the prefix, and build.rs reads as system headers.
//
// libmodsecurity is pinned by scripts/build-modsecurity.sh, which checks the sha256 of its source archive.
// The names above are looked up in the headers of that version when this file is compiled, so a version that
// renames, moves or drops one of them stops the build, and never changes what is read without notice. A
// version that only adds a member, or changes a behaviour, would not, so the version number is checked as well
// (below), and any other version stops the build.

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <list>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <modsecurity/audit_log.h>
#include <modsecurity/debug_log.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rule_marker.h>
#include <modsecurity/rule_with_actions.h>
#include <modsecurity/rule_with_operator.h>
#include <modsecurity/rules_exceptions.h>
#include <modsecurity/rules_set.h>

#include "src/actions/disruptive/redirect.h"
#include "src/actions/expire_var.h"
#include "src/actions/init_col.h"
#include "src/actions/log_data.h"
#include "src/actions/msg.h"
#include "src/actions/set_rsc.h"
#include "src/actions/set_sid.h"
#include "src/actions/set_uid.h"
#include "src/actions/set_var.h"
#include "src/actions/tag.h"
#include "src/operators/operator.h"
#include "src/run_time_string.h"
#include "src/variables/global.h"
#include "src/variables/ip.h"
#include "src/variables/resource.h"
#include "src/variables/session.h"
#include "src/variables/tx.h"
#include "src/variables/user.h"
#include "src/variables/variable.h"

static_assert(MODSECURITY_VERSION_NUM == 30170100,
              "the bridge reads private members of libmodsecurity 3.0.17 and no other version");

namespace {

// libmodsecurity writes the text of a matched rule, with the values of the request, to
// the standard error unless a log callback is set. Nothing is to be written.
void discard_log(void *, const void *) {}

constexpr int kOk = 0;
constexpr int kRulesRefused = 1;
constexpr int kFailed = 2;

// What a rules set holds about the rule engine, as the fixed numbers that the Rust side reads.
constexpr int kEngineOff = 0;
constexpr int kEngineDetectionOnly = 1;
constexpr int kEngineOn = 2;
constexpr int kNotSet = 3;

// What the look at the built rules found, as the fixed numbers that the Rust side reads.
constexpr int kFoundNothing = 0;
constexpr int kFoundForeign = 1;
constexpr int kFoundReservedId = 2;
constexpr int kFoundExec = 3;
constexpr int kFoundSetenv = 4;
constexpr int kFoundCtl = 5;
constexpr int kFoundNoLog = 6;
constexpr int kFoundSetting = 7;
constexpr int kFoundOther = 8;

// The ids that the inspector keeps for its own rules.
constexpr int64_t kFirstReservedId = 4000001;
constexpr int64_t kLastReservedId = 4000011;

// A member pointer to a private member can be made in an explicit instantiation, which the language
// allows to name one. The members that are read this way are listed at the top of this file.
template <typename Tag, typename Tag::type Member>
struct Open {
  friend typename Tag::type open(Tag) { return Member; }
};

struct DisruptiveAction {
  using type = modsecurity::actions::Action *modsecurity::RuleWithActions::*;
  friend type open(DisruptiveAction);
};

struct RuntimeActions {
  using type = modsecurity::MatchActions modsecurity::RuleWithActions::*;
  friend type open(RuntimeActions);
};

struct SetVarActions {
  using type = modsecurity::SetVars modsecurity::RuleWithActions::*;
  friend type open(SetVarActions);
};

struct TagActions {
  using type = modsecurity::Tags modsecurity::RuleWithActions::*;
  friend type open(TagActions);
};

struct TransformationActions {
  using type = modsecurity::Transformations modsecurity::RuleWithActions::*;
  friend type open(TransformationActions);
};

struct MarkerName {
  using type = const std::string modsecurity::RuleMarker::*;
  friend type open(MarkerName);
};

struct RemovedNumbers {
  using type = std::list<int> modsecurity::RulesExceptions::*;
  friend type open(RemovedNumbers);
};

struct RemovedRanges {
  using type = std::list<std::pair<int, int>> modsecurity::RulesExceptions::*;
  friend type open(RemovedRanges);
};

struct AuditStatus {
  using type = modsecurity::audit_log::AuditLog::AuditLogStatus modsecurity::audit_log::AuditLog::*;
  friend type open(AuditStatus);
};

struct AuditType {
  using type = modsecurity::audit_log::AuditLog::AuditLogType modsecurity::audit_log::AuditLog::*;
  friend type open(AuditType);
};

struct AuditRelevant {
  using type = std::string modsecurity::audit_log::AuditLog::*;
  friend type open(AuditRelevant);
};

struct AuditCtlActive {
  using type = bool modsecurity::audit_log::AuditLog::*;
  friend type open(AuditCtlActive);
};

struct OperatorMember {
  using type = modsecurity::operators::Operator *modsecurity::RuleWithOperator::*;
  friend type open(OperatorMember);
};

struct VariablesMember {
  using type = modsecurity::variables::Variables *modsecurity::RuleWithOperator::*;
  friend type open(VariablesMember);
};

struct MessageMember {
  using type = modsecurity::actions::Msg *modsecurity::RuleWithActions::*;
  friend type open(MessageMember);
};

struct LogDataMember {
  using type = modsecurity::actions::LogData *modsecurity::RuleWithActions::*;
  friend type open(LogDataMember);
};

struct TagText {
  using type = std::unique_ptr<modsecurity::RunTimeString> modsecurity::actions::Tag::*;
  friend type open(TagText);
};

struct RedirectText {
  using type =
      std::unique_ptr<modsecurity::RunTimeString> modsecurity::actions::disruptive::Redirect::*;
  friend type open(RedirectText);
};

struct SetSidText {
  using type = std::unique_ptr<modsecurity::RunTimeString> modsecurity::actions::SetSID::*;
  friend type open(SetSidText);
};

struct SetUidText {
  using type = std::unique_ptr<modsecurity::RunTimeString> modsecurity::actions::SetUID::*;
  friend type open(SetUidText);
};

struct SetRscText {
  using type = std::unique_ptr<modsecurity::RunTimeString> modsecurity::actions::SetRSC::*;
  friend type open(SetRscText);
};

struct ExpireVarText {
  using type = std::unique_ptr<modsecurity::RunTimeString> modsecurity::actions::ExpireVar::*;
  friend type open(ExpireVarText);
};

struct InitColText {
  using type = std::unique_ptr<modsecurity::RunTimeString> modsecurity::actions::InitCol::*;
  friend type open(InitColText);
};

struct SetVarOperationMember {
  using type = modsecurity::actions::SetVarOperation modsecurity::actions::SetVar::*;
  friend type open(SetVarOperationMember);
};

struct SetVarVariable {
  using type = std::unique_ptr<modsecurity::variables::Variable> modsecurity::actions::SetVar::*;
  friend type open(SetVarVariable);
};

struct SetVarText {
  using type = std::unique_ptr<modsecurity::RunTimeString> modsecurity::actions::SetVar::*;
  friend type open(SetVarText);
};

struct TextElements {
  using type = std::list<std::unique_ptr<modsecurity::RunTimeElementHolder>>
      modsecurity::RunTimeString::*;
  friend type open(TextElements);
};

template struct Open<DisruptiveAction, &modsecurity::RuleWithActions::m_disruptiveAction>;
template struct Open<RuntimeActions, &modsecurity::RuleWithActions::m_actionsRuntimePos>;
template struct Open<SetVarActions, &modsecurity::RuleWithActions::m_actionsSetVar>;
template struct Open<TagActions, &modsecurity::RuleWithActions::m_actionsTag>;
template struct Open<TransformationActions, &modsecurity::RuleWithActions::m_transformations>;
template struct Open<MarkerName, &modsecurity::RuleMarker::m_name>;
template struct Open<RemovedNumbers, &modsecurity::RulesExceptions::m_numbers>;
template struct Open<RemovedRanges, &modsecurity::RulesExceptions::m_ranges>;
template struct Open<AuditStatus, &modsecurity::audit_log::AuditLog::m_status>;
template struct Open<AuditType, &modsecurity::audit_log::AuditLog::m_type>;
template struct Open<AuditRelevant, &modsecurity::audit_log::AuditLog::m_relevant>;
template struct Open<AuditCtlActive, &modsecurity::audit_log::AuditLog::m_ctlAuditEngineActive>;
template struct Open<OperatorMember, &modsecurity::RuleWithOperator::m_operator>;
template struct Open<VariablesMember, &modsecurity::RuleWithOperator::m_variables>;
template struct Open<MessageMember, &modsecurity::RuleWithActions::m_msg>;
template struct Open<LogDataMember, &modsecurity::RuleWithActions::m_logData>;
template struct Open<TagText, &modsecurity::actions::Tag::m_string>;
template struct Open<RedirectText, &modsecurity::actions::disruptive::Redirect::m_string>;
template struct Open<SetSidText, &modsecurity::actions::SetSID::m_string>;
template struct Open<SetUidText, &modsecurity::actions::SetUID::m_string>;
template struct Open<SetRscText, &modsecurity::actions::SetRSC::m_string>;
template struct Open<ExpireVarText, &modsecurity::actions::ExpireVar::m_string>;
template struct Open<InitColText, &modsecurity::actions::InitCol::m_string>;
template struct Open<SetVarOperationMember, &modsecurity::actions::SetVar::m_operation>;
template struct Open<SetVarVariable, &modsecurity::actions::SetVar::m_variable>;
template struct Open<SetVarText, &modsecurity::actions::SetVar::m_string>;
template struct Open<TextElements, &modsecurity::RunTimeString::m_elements>;

// The name of an action keeps the capitals that the rule was written with.
std::string lower(const std::string &text) {
  std::string out(text);
  for (char &c : out) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return out;
}

// The ctl actions that are allowed: the operator's policy about rules and targets, the audit
// engine and parts, what the engine does with an XML body, and the processor of the body, which
// the inspection checks against the one the Content-Type gives. The rest (the rule engine, the
// request body access, and any other) are not.
bool ctl_is_allowed(const std::string &payload) {
  static const char *const allowed[] = {
      "auditengine",          "auditlogparts",        "forcerequestbodyvariable",
      "parsexmlintoargs",     "requestbodyprocessor", "ruleremovebyid",
      "ruleremovebytag",      "ruleremovetargetbyid", "ruleremovetargetbytag"};
  const std::string name = lower(payload.substr(0, payload.find('=')));
  for (const char *const one : allowed) {
    if (name == one) {
      return true;
    }
  }
  return false;
}

// What the actions of one rule do about a stop and a message.
struct Actions {
  bool stops = false;
  bool nolog = false;
};

// Looks at one action: what is not allowed at all, or else what it adds to `seen`.
int look_at(const modsecurity::actions::Action &action, Actions &seen) {
  if (!action.m_name) {
    return kFoundOther;
  }
  const std::string name = lower(*action.m_name);
  if (name == "exec") {
    return kFoundExec;
  }
  if (name == "setenv") {
    return kFoundSetenv;
  }
  if (name == "ctl") {
    return ctl_is_allowed(action.m_parser_payload) ? kFoundNothing : kFoundCtl;
  }
  if (name == "nolog" || name == "noauditlog") {
    seen.nolog = true;
  }
  if (name == "block") {
    seen.stops = true;
  }
  return kFoundNothing;
}

// One rule of a chain. A rule that stops a request and leaves no message is not allowed:
// nothing would say which rule stopped the request.
int check_link(modsecurity::RuleWithActions &link, const std::set<std::string> &loaded) {
  if (loaded.count(link.getFileName()) == 0) {
    return kFoundForeign;
  }
  if (link.m_ruleId >= kFirstReservedId && link.m_ruleId <= kLastReservedId) {
    return kFoundReservedId;
  }
  Actions seen;
  const modsecurity::actions::Action *disruptive = link.*open(DisruptiveAction());
  if (disruptive != nullptr) {
    const int found = look_at(*disruptive, seen);
    if (found != kFoundNothing) {
      return found;
    }
    // Of the disruptive actions only pass and allow let the request go on. Every other one stops it
    // (deny, drop, redirect), and none is listed by name: the library gives the action that it builds
    // for redirect the name `redirert`.
    const std::string name = lower(*disruptive->m_name);
    if (name != "pass" && name != "allow") {
      seen.stops = true;
    }
  }
  for (const modsecurity::actions::Action *action : link.*open(RuntimeActions())) {
    if (action == nullptr) {
      return kFoundOther;
    }
    const int found = look_at(*action, seen);
    if (found != kFoundNothing) {
      return found;
    }
  }
  return seen.stops && seen.nolog ? kFoundNoLog : kFoundNothing;
}

// A rule and the rules chained after it, or a marker.
int check_rule(modsecurity::Rule &rule, const std::set<std::string> &loaded) {
  if (rule.isMarker()) {
    return loaded.count(rule.getFileName()) == 0 ? kFoundForeign : kFoundNothing;
  }
  auto *first = dynamic_cast<modsecurity::RuleWithActions *>(&rule);
  if (first == nullptr) {
    return kFoundOther;
  }
  for (modsecurity::RuleWithActions *link = first; link != nullptr;
       link = link->m_chainedRuleChild.get()) {
    const int found = check_link(*link, loaded);
    if (found != kFoundNothing) {
      return found;
    }
  }
  return kFoundNothing;
}

// The limits of the body and of the arguments, the upload and temporary-file settings and the
// audit log are the ones that the rules were not given: the inspector counts the body itself
// and writes no file.
bool settings_are_clear(const modsecurity::RulesSet &rules) {
  using Properties = modsecurity::RulesSetProperties;
  using AuditLog = modsecurity::audit_log::AuditLog;
  if (!rules.m_auditLog) {
    return false;
  }
  const AuditLog &audit = *rules.m_auditLog;
  return !rules.m_requestBodyLimit.m_set && !rules.m_requestBodyNoFilesLimit.m_set &&
         !rules.m_argumentsLimit.m_set &&
         rules.m_requestBodyLimitAction == Properties::PropertyNotSetBodyLimitAction &&
         rules.m_uploadKeepFiles == Properties::PropertyNotSetConfigBoolean &&
         rules.m_tmpSaveUploadedFiles == Properties::PropertyNotSetConfigBoolean &&
         !rules.m_uploadDirectory.m_set && !rules.m_uploadTmpDirectory.m_set &&
         !rules.m_uploadFileLimit.m_set && !rules.m_uploadFileMode.m_set &&
         audit.m_path1.empty() && audit.m_path2.empty() && audit.m_storage_dir.empty() &&
         audit.m_prefix.empty() && audit.m_format == AuditLog::NotSetAuditLogFormat;
}

int check_rules(modsecurity::RulesSet &rules, const std::set<std::string> &loaded) {
  for (int phase = 0; phase < modsecurity::Phases::NUMBER_OF_PHASES; phase++) {
    for (const std::shared_ptr<modsecurity::Rule> &rule :
         rules.m_rulesSetPhases.at(phase)->m_rules) {
      if (!rule) {
        return kFoundOther;
      }
      const int found = check_rule(*rule, loaded);
      if (found != kFoundNothing) {
        return found;
      }
    }
  }
  // The actions of a SecDefaultAction are added to the rules of their phase, so they are looked at
  // as well, and one with nolog is not allowed whatever else it has.
  for (int phase = 0; phase < modsecurity::Phases::NUMBER_OF_PHASES; phase++) {
    for (const std::shared_ptr<modsecurity::actions::Action> &action :
         rules.m_defaultActions[phase]) {
      if (!action) {
        return kFoundOther;
      }
      Actions seen;
      const int found = look_at(*action, seen);
      if (found != kFoundNothing) {
        return found;
      }
      if (seen.nolog) {
        return kFoundNoLog;
      }
    }
  }
  // Actions that a directive adds to a rule that is already there.
  if (!rules.m_exceptions.m_action_pre_update_target_by_id.empty() ||
      !rules.m_exceptions.m_action_pos_update_target_by_id.empty()) {
    return kFoundOther;
  }
  return settings_are_clear(rules) ? kFoundNothing : kFoundSetting;
}

// What the rules and the settings are made of, as the text that the Rust side compares with its own. One item
// to a line: a word, a number, or a string as its length, a colon and its bytes. The same order and the
// same words are written by `Out` in `rules/model.rs`.
class Out {
 public:
  void word(const char *w) {
    text_ += w;
    text_ += '\n';
  }
  void num(int64_t n) {
    text_ += std::to_string(n);
    text_ += '\n';
  }
  void flag(bool b) { num(b ? 1 : 0); }
  void count(size_t n) { num(static_cast<int64_t>(n)); }
  void str(const std::string &s) {
    text_ += std::to_string(s.size());
    text_ += ':';
    text_ += s;
    text_ += '\n';
  }
  const std::string &text() const { return text_; }

 private:
  std::string text_;
};

std::string pieces_text(const modsecurity::RunTimeString &text);

// A text with macros that a rule may not have: whether it has one, and its pieces.
void put_optional_text(Out &out, const modsecurity::RunTimeString *text) {
  out.flag(text != nullptr);
  out.str(text != nullptr ? pieces_text(*text) : std::string());
}

// The text of a variable that is made of text and macros (the selector of a variable that a setvar writes to).
const modsecurity::RunTimeString *dynamic_text(const modsecurity::variables::Variable &variable) {
  namespace v = modsecurity::variables;
  if (const auto *one = dynamic_cast<const v::Tx_DynamicElement *>(&variable)) {
    return one->m_string.get();
  }
  if (const auto *one = dynamic_cast<const v::Ip_DynamicElement *>(&variable)) {
    return one->m_string.get();
  }
  if (const auto *one = dynamic_cast<const v::Global_DynamicElement *>(&variable)) {
    return one->m_string.get();
  }
  if (const auto *one = dynamic_cast<const v::Resource_DynamicElement *>(&variable)) {
    return one->m_string.get();
  }
  if (const auto *one = dynamic_cast<const v::Session_DynamicElement *>(&variable)) {
    return one->m_string.get();
  }
  if (const auto *one = dynamic_cast<const v::User_DynamicElement *>(&variable)) {
    return one->m_string.get();
  }
  return nullptr;
}

// A variable: its collection in lower case, and what follows it. The library keeps the expression of a regular
// expression selector of two collections as a plain name (see `Kind` in rules/reader/variable.rs).
std::string variable_text(const modsecurity::variables::Variable &variable) {
  Out out;
  out.str(lower(variable.m_collectionName));
  if (const auto *regex = dynamic_cast<const modsecurity::variables::VariableRegex *>(&variable)) {
    out.word("regex");
    out.str(regex->m_regex);
  } else if (const modsecurity::RunTimeString *text = dynamic_text(variable)) {
    out.word("dynamic");
    out.str(pieces_text(*text));
  } else if (variable.m_name.empty()) {
    out.word("bare");
  } else {
    out.word("element");
    out.str(variable.m_name);
  }
  return out.text();
}

// A text with macros as its pieces: how many, and for each a string or a variable.
std::string pieces_text(const modsecurity::RunTimeString &text) {
  Out out;
  const auto &elements = text.*open(TextElements());
  out.count(elements.size());
  for (const auto &element : elements) {
    if (!element) {
      out.word("null");
    } else if (element->m_var) {
      out.word("var");
      out.str(variable_text(*element->m_var));
    } else {
      out.word("text");
      out.str(element->m_string);
    }
  }
  return out.text();
}

// A variable of a list: what is in front of it (nothing, `&` or `!`), the variable, and what the excluded
// variables of the list leave out of it.
std::string listed_text(const modsecurity::variables::Variable &listed) {
  namespace v = modsecurity::variables;
  const v::Variable *base = &listed;
  const char *modifier = "plain";
  if (const auto *exclusion = dynamic_cast<const v::VariableModificatorExclusion *>(&listed)) {
    modifier = "exclusion";
    base = exclusion->m_base.get();
  } else if (const auto *count = dynamic_cast<const v::VariableModificatorCount *>(&listed)) {
    modifier = "count";
    base = count->m_base.get();
  }
  Out out;
  out.word(modifier);
  out.str(base != nullptr ? variable_text(*base) : std::string("null"));
  out.count(listed.m_keyExclusion.size());
  for (const auto &key : listed.m_keyExclusion) {
    if (const auto *regex = dynamic_cast<const v::KeyExclusionRegex *>(key.get())) {
      out.word("regex");
      out.str(regex->m_re.pattern);
    } else if (const auto *name = dynamic_cast<const v::KeyExclusionString *>(key.get())) {
      out.word("string");
      out.str(name->m_key);
    } else {
      out.word("other");
    }
  }
  return out.text();
}

// The text that an action keeps in a member of its own, as its pieces; empty when it has none.
std::string held_text(const std::unique_ptr<modsecurity::RunTimeString> &text) {
  return text ? pieces_text(*text) : std::string();
}

// A tag: its text.
std::string tag_text(const modsecurity::actions::Tag &tag) {
  return held_text(tag.*open(TagText()));
}

// A setvar: what it does, the variable that it writes to, and its value.
std::string set_var_text(const modsecurity::actions::SetVar &set_var) {
  Out out;
  out.num(static_cast<int>(set_var.*open(SetVarOperationMember())));
  const auto &variable = set_var.*open(SetVarVariable());
  out.str(variable ? variable_text(*variable) : std::string());
  put_optional_text(out, (set_var.*open(SetVarText())).get());
  return out.text();
}

// The text of an action that keeps one apart from its payload: the message, the log data, a tag and a setvar,
// and redirect, setsid, setuid, setrsc, expirevar and initcol. A rule keeps the first four apart from its
// actions to run, so they are only met here in a default action; the six others are among the actions to run
// of a rule, or are its disruptive action.
std::string action_detail(const modsecurity::actions::Action &action) {
  if (const auto *msg = dynamic_cast<const modsecurity::actions::Msg *>(&action)) {
    return msg->m_string ? pieces_text(*msg->m_string) : std::string();
  }
  if (const auto *log_data = dynamic_cast<const modsecurity::actions::LogData *>(&action)) {
    return log_data->m_string ? pieces_text(*log_data->m_string) : std::string();
  }
  if (const auto *tag = dynamic_cast<const modsecurity::actions::Tag *>(&action)) {
    return tag_text(*tag);
  }
  if (const auto *set_var = dynamic_cast<const modsecurity::actions::SetVar *>(&action)) {
    return set_var_text(*set_var);
  }
  if (const auto *redirect =
          dynamic_cast<const modsecurity::actions::disruptive::Redirect *>(&action)) {
    return held_text(redirect->*open(RedirectText()));
  }
  if (const auto *set_sid = dynamic_cast<const modsecurity::actions::SetSID *>(&action)) {
    return held_text(set_sid->*open(SetSidText()));
  }
  if (const auto *set_uid = dynamic_cast<const modsecurity::actions::SetUID *>(&action)) {
    return held_text(set_uid->*open(SetUidText()));
  }
  if (const auto *set_rsc = dynamic_cast<const modsecurity::actions::SetRSC *>(&action)) {
    return held_text(set_rsc->*open(SetRscText()));
  }
  if (const auto *expire_var = dynamic_cast<const modsecurity::actions::ExpireVar *>(&action)) {
    return held_text(expire_var->*open(ExpireVarText()));
  }
  if (const auto *init_col = dynamic_cast<const modsecurity::actions::InitCol *>(&action)) {
    return held_text(init_col->*open(InitColText()));
  }
  return std::string();
}

// An action: its name in lower case as the library stores it, its payload where the payload is
// compared (the ones whose value decides where a request goes: skip, skipAfter, ctl), and its text.
void put_action(Out &out, const modsecurity::actions::Action &action) {
  if (!action.m_name) {
    out.word("nameless");
    return;
  }
  const std::string name = lower(*action.m_name);
  out.str(name);
  const bool valued = name == "skip" || name == "skipafter" || name == "ctl";
  out.str(valued ? action.m_parser_payload : std::string());
  out.str(action_detail(action));
}

// One rule of a chain. What a rule has of actions is in several members: the action that stops or lets
// it pass, the ones that run when it matches, and those that the library keeps apart (the message, the
// log data, the severity, the setvar and tag actions, the transformations). The ones that only set a
// field when the rule is made (id, phase, chain, rev, ver, accuracy, maturity, capture, multiMatch) are
// in the fields.
void describe_link(Out &out, modsecurity::RuleWithActions &link) {
  auto *with_operator = dynamic_cast<modsecurity::RuleWithOperator *>(&link);
  if (with_operator != nullptr) {
    out.word("rule");
    out.str(lower(with_operator->getOperatorName()));
    const modsecurity::operators::Operator *op = (*with_operator).*open(OperatorMember());
    out.flag(op != nullptr && op->m_negation);
    put_optional_text(out, op != nullptr ? op->m_string.get() : nullptr);
    const modsecurity::variables::Variables *variables = (*with_operator).*open(VariablesMember());
    out.count(variables != nullptr ? variables->size() : 0);
    if (variables != nullptr) {
      for (const modsecurity::variables::Variable *variable : *variables) {
        out.str(variable != nullptr ? listed_text(*variable) : std::string("null"));
      }
    }
  } else {
    out.word("action");
  }
  out.num(link.m_ruleId);
  out.num(link.getPhase());
  out.flag(link.isChained());
  const modsecurity::actions::Action *disruptive = link.*open(DisruptiveAction());
  if (disruptive != nullptr) {
    out.word("disruptive");
    put_action(out, *disruptive);
  } else {
    out.word("passive");
  }
  const modsecurity::MatchActions &runtime = link.*open(RuntimeActions());
  out.count(runtime.size());
  for (const modsecurity::actions::Action *action : runtime) {
    if (action == nullptr) {
      out.word("null");
    } else {
      put_action(out, *action);
    }
  }
  out.flag(link.hasCaptureAction());
  out.flag(link.hasMultimatch());
  out.flag(link.hasBlockAction());
  out.num(link.hasSeverity() ? link.severity() : -1);
  const modsecurity::actions::Msg *msg = link.*open(MessageMember());
  put_optional_text(out, msg != nullptr ? msg->m_string.get() : nullptr);
  const modsecurity::actions::LogData *log_data = link.*open(LogDataMember());
  put_optional_text(out, log_data != nullptr ? log_data->m_string.get() : nullptr);
  const modsecurity::SetVars &set_vars = link.*open(SetVarActions());
  out.count(set_vars.size());
  for (const modsecurity::actions::SetVar *set_var : set_vars) {
    out.str(set_var != nullptr ? set_var_text(*set_var) : std::string("null"));
  }
  const modsecurity::Tags &tags = link.*open(TagActions());
  out.count(tags.size());
  for (const modsecurity::actions::Tag *tag : tags) {
    out.str(tag != nullptr ? tag_text(*tag) : std::string("null"));
  }
  out.count((link.*open(TransformationActions())).size());
  out.str(link.m_rev);
  out.str(link.m_ver);
  out.num(link.m_accuracy);
  out.num(link.m_maturity);
}

// A rule and the rules chained after it, one after the other (a chain is not read by recursion).
void describe_chain(Out &out, modsecurity::RuleWithActions &first) {
  for (modsecurity::RuleWithActions *link = &first; link != nullptr;
       link = link->m_chainedRuleChild.get()) {
    describe_link(out, *link);
    out.word(link->m_chainedRuleChild ? "child" : "end");
  }
}

void describe_rules(Out &out, modsecurity::RulesSet &rules) {
  out.word("rules");
  out.num(modsecurity::Phases::NUMBER_OF_PHASES);
  for (int phase = 0; phase < modsecurity::Phases::NUMBER_OF_PHASES; phase++) {
    const auto &list = rules.m_rulesSetPhases.at(phase)->m_rules;
    out.word("phase");
    out.num(phase);
    out.count(list.size());
    for (const std::shared_ptr<modsecurity::Rule> &rule : list) {
      if (!rule) {
        out.word("null");
      } else if (auto *marker = dynamic_cast<modsecurity::RuleMarker *>(rule.get())) {
        out.word("marker");
        out.str(marker->*open(MarkerName()));
      } else if (auto *with_actions = dynamic_cast<modsecurity::RuleWithActions *>(rule.get())) {
        describe_chain(out, *with_actions);
      } else {
        out.word("other");
      }
    }
  }
  for (int phase = 0; phase < modsecurity::Phases::NUMBER_OF_PHASES; phase++) {
    const auto &list = rules.m_defaultActions[phase];
    out.word("defaults");
    out.num(phase);
    out.count(list.size());
    for (const std::shared_ptr<modsecurity::actions::Action> &action : list) {
      if (!action) {
        out.word("null");
      } else {
        put_action(out, *action);
      }
    }
  }
}

using Properties = modsecurity::RulesSetProperties;
using AuditLog = modsecurity::audit_log::AuditLog;

const char *boolean(Properties::ConfigBoolean v) {
  switch (v) {
    case Properties::TrueConfigBoolean:
      return "true";
    case Properties::FalseConfigBoolean:
      return "false";
    case Properties::PropertyNotSetConfigBoolean:
      return "unset";
  }
  return "unknown";
}

const char *body_limit_action(Properties::BodyLimitAction v) {
  switch (v) {
    case Properties::ProcessPartialBodyLimitAction:
      return "processpartial";
    case Properties::RejectBodyLimitAction:
      return "reject";
    case Properties::PropertyNotSetBodyLimitAction:
      return "unset";
  }
  return "unknown";
}

const char *remote_rules_action(Properties::OnFailedRemoteRulesAction v) {
  switch (v) {
    case Properties::AbortOnFailedRemoteRulesAction:
      return "abort";
    case Properties::WarnOnFailedRemoteRulesAction:
      return "warn";
    case Properties::PropertyNotSetRemoteRulesAction:
      return "unset";
  }
  return "unknown";
}

const char *audit_status(AuditLog::AuditLogStatus v) {
  switch (v) {
    case AuditLog::NotSetLogStatus:
      return "unset";
    case AuditLog::OnAuditLogStatus:
      return "on";
    case AuditLog::OffAuditLogStatus:
      return "off";
    case AuditLog::RelevantOnlyAuditLogStatus:
      return "relevantonly";
  }
  return "unknown";
}

const char *audit_type(AuditLog::AuditLogType v) {
  switch (v) {
    case AuditLog::NotSetAuditLogType:
      return "unset";
    case AuditLog::SerialAuditLogType:
      return "serial";
    case AuditLog::ParallelAuditLogType:
      return "parallel";
    case AuditLog::HttpsAuditLogType:
      return "https";
  }
  return "unknown";
}

const char *audit_format(AuditLog::AuditLogFormat v) {
  switch (v) {
    case AuditLog::NotSetAuditLogFormat:
      return "unset";
    case AuditLog::JSONAuditLogFormat:
      return "json";
    case AuditLog::NativeAuditLogFormat:
      return "native";
  }
  return "unknown";
}

template <typename Value>
void put_number(Out &out, const char *label, const Value &v) {
  out.word(label);
  out.flag(v.m_set);
  out.num(static_cast<int64_t>(v.m_value));
}

void put_string(Out &out, const char *label, const modsecurity::ConfigString &v) {
  out.word(label);
  out.flag(v.m_set);
  out.str(v.m_value);
}

void put_strings(Out &out, const char *label, std::vector<std::string> list) {
  std::sort(list.begin(), list.end());
  out.word(label);
  out.count(list.size());
  for (const std::string &one : list) {
    out.str(one);
  }
}

void put_entries(Out &out, const char *label, std::vector<std::string> entries) {
  std::sort(entries.begin(), entries.end());
  out.word(label);
  out.count(entries.size());
  for (const std::string &entry : entries) {
    out.str(entry);
  }
}

// The key of an update of a target by id is a double: an id is written as the whole number that it is,
// and anything else cannot be a rule id.
int64_t id_key(double key) {
  return key == std::floor(key) && std::fabs(key) < 9e15 ? static_cast<int64_t>(key) : INT64_MIN;
}

// Every member of the properties of the rules set, whether a directive sets it or not: the ones that
// the rule files may set hold what the Rust side read, and all the others are at their defaults.
void describe_settings(Out &out, modsecurity::RulesSet &rules) {
  out.word("settings");
  out.word("engine");
  switch (rules.m_secRuleEngine) {
    case Properties::DisabledRuleEngine:
      out.word("off");
      break;
    case Properties::EnabledRuleEngine:
      out.word("on");
      break;
    case Properties::DetectionOnlyRuleEngine:
      out.word("detectiononly");
      break;
    case Properties::PropertyNotSetRuleEngine:
      out.word("unset");
      break;
  }
  out.word("request_body_access");
  out.word(boolean(rules.m_secRequestBodyAccess));
  out.word("response_body_access");
  out.word(boolean(rules.m_secResponseBodyAccess));
  out.word("xml_external_entity");
  out.word(boolean(rules.m_secXMLExternalEntity));
  out.word("xml_parse_into_args");
  switch (rules.m_secXMLParseXmlIntoArgs) {
    case Properties::TrueConfigXMLParseXmlIntoArgs:
      out.word("true");
      break;
    case Properties::FalseConfigXMLParseXmlIntoArgs:
      out.word("false");
      break;
    case Properties::OnlyArgsConfigXMLParseXmlIntoArgs:
      out.word("onlyargs");
      break;
    case Properties::PropertyNotSetConfigXMLParseXmlIntoArgs:
      out.word("unset");
      break;
  }
  out.word("tmp_save_uploaded_files");
  out.word(boolean(rules.m_tmpSaveUploadedFiles));
  out.word("upload_keep_files");
  out.word(boolean(rules.m_uploadKeepFiles));
  out.word("request_body_limit_action");
  out.word(body_limit_action(rules.m_requestBodyLimitAction));
  out.word("response_body_limit_action");
  out.word(body_limit_action(rules.m_responseBodyLimitAction));
  put_number(out, "arguments_limit", rules.m_argumentsLimit);
  put_number(out, "json_depth_limit", rules.m_requestBodyJsonDepthLimit);
  put_number(out, "request_body_limit", rules.m_requestBodyLimit);
  put_number(out, "request_body_no_files_limit", rules.m_requestBodyNoFilesLimit);
  put_number(out, "response_body_limit", rules.m_responseBodyLimit);
  put_number(out, "pcre_match_limit", rules.m_pcreMatchLimit);
  put_number(out, "upload_file_limit", rules.m_uploadFileLimit);
  put_number(out, "upload_file_mode", rules.m_uploadFileMode);
  put_string(out, "http_bl_key", rules.m_httpblKey);
  put_string(out, "upload_directory", rules.m_uploadDirectory);
  put_string(out, "upload_tmp_directory", rules.m_uploadTmpDirectory);
  put_string(out, "argument_separator", rules.m_secArgumentSeparator);
  put_string(out, "web_app_id", rules.m_secWebAppId);
  out.word("unicode_map");
  out.flag(rules.m_unicodeMapTable.m_set);
  out.word("remote_rules_action");
  out.word(remote_rules_action(rules.m_remoteRulesActionOnFailed));
  out.word("response_body_types");
  out.flag(rules.m_responseBodyTypeToBeInspected.m_set);
  out.flag(rules.m_responseBodyTypeToBeInspected.m_clear);
  out.count(rules.m_responseBodyTypeToBeInspected.m_value.size());
  for (const std::string &type : rules.m_responseBodyTypeToBeInspected.m_value) {
    out.str(type);
  }
  out.word("components");
  out.count(rules.m_components.size());
  for (const std::string &component : rules.m_components) {
    out.str(component);
  }

  const modsecurity::RulesExceptions &exceptions = rules.m_exceptions;
  out.word("removed_numbers");
  const std::list<int> &numbers = exceptions.*open(RemovedNumbers());
  out.count(numbers.size());
  for (int number : numbers) {
    out.num(number);
  }
  out.word("removed_ranges");
  const std::list<std::pair<int, int>> &ranges = exceptions.*open(RemovedRanges());
  out.count(ranges.size());
  for (const std::pair<int, int> &range : ranges) {
    out.num(range.first);
    out.num(range.second);
  }
  put_strings(out, "removed_by_msg",
              std::vector<std::string>(exceptions.m_remove_rule_by_msg.begin(),
                                       exceptions.m_remove_rule_by_msg.end()));
  put_strings(out, "removed_by_tag",
              std::vector<std::string>(exceptions.m_remove_rule_by_tag.begin(),
                                       exceptions.m_remove_rule_by_tag.end()));
  // An update of a target is one entry for each of its variables: what it names, and the variable.
  std::vector<std::string> by_id;
  for (const auto &entry : exceptions.m_variable_update_target_by_id) {
    Out one;
    one.num(id_key(entry.first));
    one.str(entry.second ? listed_text(*entry.second) : std::string("null"));
    by_id.push_back(one.text());
  }
  put_entries(out, "update_target_by_id", by_id);
  std::vector<std::string> by_tag;
  for (const auto &entry : exceptions.m_variable_update_target_by_tag) {
    Out one;
    one.str(*entry.first);
    one.str(entry.second ? listed_text(*entry.second) : std::string("null"));
    by_tag.push_back(one.text());
  }
  put_entries(out, "update_target_by_tag", by_tag);
  std::vector<std::string> by_msg;
  for (const auto &entry : exceptions.m_variable_update_target_by_msg) {
    Out one;
    one.str(*entry.first);
    one.str(entry.second ? listed_text(*entry.second) : std::string("null"));
    by_msg.push_back(one.text());
  }
  put_entries(out, "update_target_by_msg", by_msg);
  out.word("action_updates");
  out.count(exceptions.m_action_pre_update_target_by_id.size());
  out.count(exceptions.m_action_pos_update_target_by_id.size());

  out.word("audit");
  const AuditLog *audit = rules.m_auditLog;
  if (audit == nullptr) {
    out.word("none");
  } else {
    out.str(audit->m_path1);
    out.str(audit->m_path2);
    out.str(audit->m_storage_dir);
    out.str(audit->m_prefix);
    out.word(audit_format(audit->m_format));
    out.word(audit_status(audit->*open(AuditStatus())));
    out.word(audit_type(audit->*open(AuditType())));
    out.str(audit->*open(AuditRelevant()));
    out.num(audit->getParts());
    out.num(audit->getFilePermission());
    out.num(audit->getDirectoryPermission());
    out.flag(audit->*open(AuditCtlActive()));
  }
  out.word("debug");
  modsecurity::debug_log::DebugLog *debug = rules.m_debugLog;
  if (debug == nullptr) {
    out.word("none");
  } else {
    out.flag(debug->isLogFileSet());
    out.flag(debug->isLogLevelSet());
  }
}

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

// Adds the rules in a text, with the same codes as tkv_rules_add_file. The text is not a
// file: nothing is read from the disk for it unless a rule in it names a file.
int tkv_rules_add_text(modsecurity::RulesSet *rules, const char *text) noexcept {
  try {
    const char *error = nullptr;
    if (modsecurity::msc_rules_add(rules, text, &error) < 0) {
      modsecurity::msc_rules_error_cleanup(error);
      return kRulesRefused;
    }
    return kOk;
  } catch (...) {
    return kFailed;
  }
}

// Reads what the rules set holds after the rules were added: the rule engine (0 off, 1 only
// detects, 2 on, 3 not set), whether the request body is accessed (0 no, 1 yes, 3 not set),
// and the depth limit of a JSON body (a flag that says whether it is set, and the value).
// 0 when all were read, 2 otherwise.
int tkv_rules_settings(const modsecurity::RulesSet *rules, int *engine, int *body_access,
                       int *json_depth_set, uint64_t *json_depth) noexcept {
  try {
    switch (rules->m_secRuleEngine) {
      case modsecurity::RulesSetProperties::DisabledRuleEngine:
        *engine = kEngineOff;
        break;
      case modsecurity::RulesSetProperties::DetectionOnlyRuleEngine:
        *engine = kEngineDetectionOnly;
        break;
      case modsecurity::RulesSetProperties::EnabledRuleEngine:
        *engine = kEngineOn;
        break;
      case modsecurity::RulesSetProperties::PropertyNotSetRuleEngine:
        *engine = kNotSet;
        break;
      default:
        return kFailed;
    }
    switch (rules->m_secRequestBodyAccess) {
      case modsecurity::RulesSetProperties::FalseConfigBoolean:
        *body_access = 0;
        break;
      case modsecurity::RulesSetProperties::TrueConfigBoolean:
        *body_access = 1;
        break;
      case modsecurity::RulesSetProperties::PropertyNotSetConfigBoolean:
        *body_access = kNotSet;
        break;
      default:
        return kFailed;
    }
    *json_depth_set = rules->m_requestBodyJsonDepthLimit.m_set ? 1 : 0;
    *json_depth = static_cast<uint64_t>(rules->m_requestBodyJsonDepthLimit.m_value);
    return kOk;
  } catch (...) {
    return kFailed;
  }
}

// Looks at the rules that were built, and not at the text they came from, for the first thing
// that must not be in them (see `check_rules`): a rule that no loaded file holds, an id that
// is reserved, an action that is not allowed, a stop that leaves no message, a setting that
// must not be set. `files` are the `count` paths of the rules files that were added, as they
// were given to tkv_rules_add_file. 0 when the look was made, and then `found` says what it
// found (0 for nothing), 2 otherwise.
int tkv_rules_check(modsecurity::RulesSet *rules, const char *const *files, size_t count,
                    int *found) noexcept {
  try {
    std::set<std::string> loaded;
    for (size_t i = 0; i < count; i++) {
      loaded.insert(files[i]);
    }
    *found = check_rules(*rules, loaded);
    return kOk;
  } catch (...) {
    return kFailed;
  }
}

// Writes the description of the rules that were built and of their settings into `buffer`, when it holds
// `capacity` bytes and they are enough, and gives the length of the description in `length` either way.
// 0 when the description was made, 2 otherwise. A caller that does not know the length calls it with no
// buffer first.
int tkv_rules_describe(modsecurity::RulesSet *rules, uint8_t *buffer, size_t capacity,
                       size_t *length) noexcept {
  try {
    Out out;
    describe_rules(out, *rules);
    describe_settings(out, *rules);
    *length = out.text().size();
    if (buffer != nullptr && out.text().size() <= capacity) {
      std::memcpy(buffer, out.text().data(), out.text().size());
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
