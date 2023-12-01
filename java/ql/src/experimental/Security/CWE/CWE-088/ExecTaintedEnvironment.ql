/**
 * @name Command execution with tainted environment
 * @description Using a tainted environment in a call to exec() may allow an attacker to execute arbitrary commands.
 * @problem.severity error
 * @kind path-problem
 * @security-severity 9.8
 * @precision medium
 * @id java/exec-tainted-environment-bash
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import java
import TaintedEnvironmentVariableQuery
import ExecTaintedEnvironmentFlow::PathGraph

from ExecTaintedEnvironmentFlow::PathNode source, ExecTaintedEnvironmentFlow::PathNode sink
where ExecTaintedEnvironmentFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This command will be execute with a tainted environment variable."
