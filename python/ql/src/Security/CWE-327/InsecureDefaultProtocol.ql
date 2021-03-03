/**
 * @name Default version of SSL/TLS may be insecure
 * @description Leaving the SSL/TLS version unspecified may result in an insecure
 *              default protocol being used.
 * @id py/insecure-default-protocol
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @tags security
 *       external/cwe/cwe-327
 */

// Connections are generally created based on a context which controls the range of acceptable
// protocols. This query alerts on the deprecated way of creating connections without referring
// to a context (via `ssl.wrap_socket`). Doing this and not specifying which protocols are
// acceptable means that connections will be created with the insecure default settings.
//
// Detecting that a connection is created with a context that has not been suitably configured
// is handled by the data-flow query py/insecure-protocol.
import python
import semmle.python.ApiGraphs

CallNode unsafe_call(string method_name) {
  result = API::moduleImport("ssl").getMember("wrap_socket").getACall().asCfgNode() and
  not exists(result.getArgByName("ssl_version")) and
  method_name = "deprecated method ssl.wrap_socket"
}

from CallNode call, string method_name
where call = unsafe_call(method_name)
select call,
  "Call to " + method_name +
    " does not specify a protocol, which may result in an insecure default being used."
