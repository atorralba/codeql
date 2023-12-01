import java
private import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.ExternalFlow
private import semmle.code.java.dataflow.TaintTracking

class UnsafeExecutable extends string {
  bindingset[this]
  UnsafeExecutable() { this.matches("%bash%") }
}

module BashCmdFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source.asExpr().(CompileTimeConstantExpr).getStringValue() instanceof UnsafeExecutable
  }

  predicate isSink(DataFlow::Node sink) { sinkNode(sink, "command-injection") }

  predicate isBarrier(DataFlow::Node node) {
    node instanceof AssignToNonZeroIndex or
    node instanceof ArrayInitAtNonZeroIndex or
    node instanceof StreamConcatAtNonZeroIndex or
    node.getType() instanceof PrimitiveType or
    node.getType() instanceof BoxedType
  }
}

// array[3] = node
class AssignToNonZeroIndex extends DataFlow::Node {
  AssignToNonZeroIndex() {
    exists(AssignExpr assign, ArrayAccess access |
      assign.getDest() = access and
      access.getIndexExpr().(IntegerLiteral).getValue().toInt() != 0 and
      assign.getSource() = this.asExpr()
    )
  }
}

// String[] array = {"a", "b, "c"};
class ArrayInitAtNonZeroIndex extends DataFlow::Node {
  ArrayInitAtNonZeroIndex() {
    exists(ArrayInit init, int index |
      init.getInit(index) = this.asExpr() and
      index != 0
    )
  }
}

// Stream.concat(Arrays.stream(array_1), Arrays.stream(array_2))
class StreamConcatAtNonZeroIndex extends DataFlow::Node {
  StreamConcatAtNonZeroIndex() {
    exists(MethodCall call, int index |
      call.getMethod().getQualifiedName() = "java.util.stream.Stream.concat" and
      call.getArgument(index) = this.asExpr() and
      index != 0
    )
  }
}

module BashCmdFlow = TaintTracking::Global<BashCmdFlowConfig>;
