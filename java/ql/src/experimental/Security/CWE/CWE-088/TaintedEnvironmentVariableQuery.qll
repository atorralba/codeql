/** Modules to reason about the tainting of environment variables */

private import semmle.code.java.dataflow.ExternalFlow
private import semmle.code.java.dataflow.FlowSources
private import semmle.code.java.dataflow.TaintTracking
private import semmle.code.java.Maps
private import semmle.code.java.JDK
private import BashCommandExec

private module ProcessBuilderEnvironmentConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(MethodCall mc | mc = source.asExpr() |
      mc.getMethod().hasQualifiedName("java.lang", "ProcessBuilder", "environment")
    )
  }

  predicate isSink(DataFlow::Node sink) { sink.asExpr() = any(MapMutation mm).getQualifier() }
}

private module ProcessBuilderEnvironmentFlow = DataFlow::Global<ProcessBuilderEnvironmentConfig>;

private predicate bashCommandQualifier(DataFlow::Node src) {
  exists(DataFlow::Node cmdi | sinkNode(cmdi, "command-injection") |
    BashCmdFlow::flowTo(cmdi) and
    cmdi.asExpr().(Argument).getCall().getQualifier() = src.asExpr()
  )
}

private module BashCommandQualifier = DataFlow::SimpleGlobal<bashCommandQualifier/1>;

/**
 * A taint-tracking configuration that tracks flow from unvalidated data to an environment variable for a subprocess.
 */
module ExecTaintedEnvironmentConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ThreatModelFlowSource }

  predicate isSink(DataFlow::Node sink) {
    (
      sinkNode(sink, "environment-injection")
      or
      // sink is an added to a `ProcessBuilder::environment` map.
      exists(MapPutCall mm | mm.getKey() = sink.asExpr() |
        ProcessBuilderEnvironmentFlow::flowToExpr(mm.getQualifier())
      )
    ) and
    (
      BashCmdFlow::flowToExpr(sink.asExpr().(Argument).getCall().getAnArgument())
      or
      BashCommandQualifier::flowsTo(DataFlow::exprNode(sink.asExpr()
              .(Argument)
              .getCall()
              .getQualifier()))
    )
  }
}

/**
 * Taint-tracking flow for unvalidated data to an environment variable for a subprocess.
 */
module ExecTaintedEnvironmentFlow = TaintTracking::Global<ExecTaintedEnvironmentConfig>;
