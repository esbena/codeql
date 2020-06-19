/**
 * @name Incomplete multi-character sanitization
 * @description A sanitizer that removes a sequence of characters may reintroduce the dangerous sequence.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id js/incomplete-multi-character-sanitization
 * @tags correctness
 *       security
 *       external/cwe/cwe-20
 *       external/cwe/cwe-116
 */

import javascript
import semmle.javascript.security.IncompleteBlacklistSanitizer

/**
 * Holds if `result` is a lower-cased prefix of the strings that `t` matches.
 */
string getAMatchedPrefixLC(EmptyReplaceRegExpTerm t) {
  exists(string raw | raw = getAMatchedPrefix(t) |
    result = raw.toLowerCase().prefix([1, raw.length()])
  )
}

/**
 * A regexp term that is used to match substrings that should be replaced with the empty string.
 */
class EmptyReplaceRegExpTerm extends RegExpTerm {
  EmptyReplaceRegExpTerm() {
    exists(StringReplaceCall replace |
      [replace.getRawReplacement(), replace.getCallback(1).getAReturn()].mayHaveStringValue("") and
      this = replace.getRegExp().getRoot().getAChild*()
    )
  }
}

/**
 * Holds if `result` is a prefix of the strings that `t` matches.
 */
string getAMatchedPrefix(EmptyReplaceRegExpTerm t) {
  exists(string r |
    r = t.getConstantValue()
    or
    (t instanceof RegExpOpt or t instanceof RegExpStar) and
    (
      r = "" or
      r = getAMatchedPrefix(t.getAChild())
    )
    or
    (
      t instanceof RegExpPlus
      or
      t instanceof RegExpGroup
      or
      t instanceof RegExpAlt
    ) and
    r = getAMatchedPrefix(t.getAChild())
    or
    exists(RegExpCharacterClass c |
      c = t and not c.isInverted() and r = c.getAChild().getConstantValue()
    )
  |
    result = r
    or
    result = r + getAMatchedPrefix(t.getSuccessor())
  )
}

/**
 * Holds if `t` may match the dangerous string `mayMatch`, indicating intent to prevent a vulnerablity of kind `kind`.
 */
predicate isDangerous(EmptyReplaceRegExpTerm t, string mayMatch, string kind) {
  kind = "path injection" and
  getAMatchedPrefixLC(t) = mayMatch and
  mayMatch = ["/..", "../"] and
  not t.getSuccessor*().getAMatchedString().regexpMatch("(?i).*[a-z0-9_-]+.*") // explicit path name mentions make this an unlikely sanitizer
  or
  kind = "HTML element injection" and
  (
    getAMatchedPrefixLC(t) = mayMatch and
    mayMatch = "<!--" and
    not t.getSuccessor*().getAMatchedString().regexpMatch("(?i).*[a-z0-9s_]+.*") // explicit comment content mentions make this an unlikely sanitizer
    or
    // the `cript|scrip` case has been observed in the wild, not sure what the goal of that pattern is...
    getAMatchedPrefixLC(t) = mayMatch and
    mayMatch = "<" + ["iframe", "script", "cript", "scrip", "style"]
  )
  or
  kind = "HTML attribute injection" and
  exists(string dangerousPrefix | dangerousPrefix = ["ng-", "on"] and mayMatch = dangerousPrefix |
    t.getAMatchedString().regexpMatch("(i?)" + dangerousPrefix + "[a-z]+")
    or
    exists(EmptyReplaceRegExpTerm start, EmptyReplaceRegExpTerm event | start = t.getAChild() |
      start.getConstantValue().regexpMatch("(?i)[^a-z]*" + dangerousPrefix) and
      event = start.getSuccessor() and
      exists(EmptyReplaceRegExpTerm quantified | quantified = event.(RegExpQuantifier).getChild(0) |
        quantified
            .(RegExpCharacterClass)
            .getAChild()
            .(RegExpCharacterRange)
            .isRange(["a", "A"], ["z", "Z"]) or
        [quantified, quantified.(RegExpRange).getAChild()].(RegExpCharacterClassEscape).getValue() =
          "w"
      )
    )
  )
}

from
  StringReplaceCall replace, EmptyReplaceRegExpTerm regexp, EmptyReplaceRegExpTerm dangerous,
  string mayMatch, string kind
where
  regexp = replace.getRegExp().getRoot() and
  dangerous.getRootTerm() = regexp and
  // only warn about the longest match (presumably the most descriptive)
  mayMatch = max(string m | isDangerous(dangerous, m, kind) | m order by m.length()) and
  // only warn once per kind
  not exists(EmptyReplaceRegExpTerm other |
    other = dangerous.getAChild+() or other = dangerous.getPredecessor+()
  |
    isDangerous(other, _, kind)
  ) and
  // avoid anchored terms
  not exists(RegExpAnchor a | a.getRootTerm() = regexp) and
  // don't flag replace operations in a loop
  not replace.getAMethodCall*().flowsTo(replace.getReceiver())
select replace,
  "This string may still contain a substring that starts matching at $@, which may cause a " + kind +
    " vulnerability.", dangerous, mayMatch
