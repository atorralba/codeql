/**
 * @name Command execution with tainted environment
 * @description Using a tainted environment in a call to exec() may allow an attacker to execute arbitrary commands.
 * @problem.severity error
 * @kind path-problem
 * @security-severity 9.8
 * @precision medium
 * @id java/exec-tainted-environment
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import go
import semmle.go.dataflow.DataFlow

abstract private class Sink extends DataFlow::Node {
  abstract DataFlow::Node getEnvNode();
}

private class GoShSetEnv extends Sink, DataFlow::CallNode {
  GoShSetEnv() {
    // Catch method calls on the `Session` object:
    exists(Method method |
      method.hasQualifiedName(package("github.com/codeskyblue/go-sh", ""), "Session", "SetEnv")
    |
      this = method.getACall()
    )
  }

  override DataFlow::Node getEnvNode() { result = this.getArgument(0) }
}

private class ExecEnv extends Sink {
  ExecEnv() {
    exists(Field f, Write w |
      f.hasQualifiedName(_, "Cmd", "Env") and
      w.writesField(_, f, this)
    )
  }

  override DataFlow::Node getEnvNode() { result = this }
}

private class SyscallEnv extends Sink, DataFlow::CallNode {
  int envArg;

  SyscallEnv() {
    exists(string pkg, string name | this.getTarget().hasQualifiedName(pkg, name) |
      pkg = "syscall" and
      name = "Exec" and
      envArg = 2
      or
      pkg = "syscall" and
      name = "CreateProcess" and
      envArg = 6
      or
      pkg = "syscall" and
      name = "CreateProcessAsUser" and
      envArg = 7
    )
  }

  override DataFlow::Node getEnvNode() { result = this.getSyntacticArgument(envArg) }
}

private module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof UntrustedFlowSource }

  predicate isSink(DataFlow::Node sink) { sink = any(Sink s).getEnvNode() }
}

module Flow = TaintTracking::Global<Config>;

import Flow::PathGraph

from Flow::PathNode src, Flow::PathNode sink
where Flow::flowPath(src, sink)
select sink, src, sink, "environ injection"
