import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.ExternalFlow

class Conf extends TaintTracking::Configuration {
  Conf() { this = "qltest:fieldinit" }

  override predicate isSource(DataFlow::Node n) {
    n.asExpr().(CompileTimeConstantExpr).getStringValue() = "src"
  }

  override predicate isSink(DataFlow::Node n) {
    n.asExpr().(Argument).getCall().getCallee().hasName("sink")
  }
}

from DataFlow::Node src, DataFlow::Node sink, Conf conf
where conf.hasFlow(src, sink)
select src, sink
