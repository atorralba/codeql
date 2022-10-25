/** Provides classes and predicates related to insufficient key sizes in Java. */

private import semmle.code.java.security.Encryption
private import semmle.code.java.dataflow.DataFlow

/** A source for an insufficient key size. */
abstract class InsufficientKeySizeSource extends DataFlow::Node {
  /** Holds if this source has the specified `state`. */
  predicate hasState(DataFlow::FlowState state) { state instanceof DataFlow::FlowStateEmpty }
}

/** A sink for an insufficient key size. */
abstract class InsufficientKeySizeSink extends DataFlow::Node {
  /** Holds if this sink has the specified `state`. */
  predicate hasState(DataFlow::FlowState state) { state instanceof DataFlow::FlowStateEmpty }
}

abstract private class KeyGeneratorInit extends MethodAccess {
  /** Gets the `keysize` argument of this call. */
  Argument getKeySizeArg() { result = this.getArgument(0) }
}

/** An instance of a generator that specifies an encryption algorithm. */
abstract private class NamedCryptoAlgoSpec extends CryptoAlgoSpec {
  /** Returns an uppercase string representing the algorithm name specified by this generator object. */
  string getAlgoName() { result = this.getAlgoSpec().(StringLiteral).getValue().toUpperCase() }
}

private signature int minKeySizeSig();

private signature class KeyInitSig extends KeyGeneratorInit;

private signature class CryptoAlgoGenSig extends NamedCryptoAlgoSpec;

private module SourceSink<
minKeySizeSig/0 getMinKeySize, KeyInitSig KeyInit, CryptoAlgoGenSig CryptoAlgoGen> {
  class Source instanceof DataFlow::Node {
    Source() { this.asExpr().(IntegerLiteral).getIntValue() < getMinKeySize() }

    predicate hasState(DataFlow::FlowState state) { state = getMinKeySize().toString() }

    string toString() { result = super.toString() }
  }

  class Sink instanceof DataFlow::Node {
    Sink() {
      exists(KeyInit ma, CryptoAlgoGen kg |
        DataFlow::localExprFlow(kg, ma.getQualifier()) and
        this.asExpr() = ma.getKeySizeArg()
      )
    }

    predicate hasState(DataFlow::FlowState state) { state = getMinKeySize().toString() }

    string toString() { result = super.toString() }
  }
}

private module Symmetric {
  private module M = SourceSink<getMinKeySize/0, KeyInit, AlgoGen>;

  /** Returns the minimum recommended key size for AES algorithms. */
  private int getMinKeySize() { result = 128 }

  /** A source for an insufficient key size used in AES algorithms. */
  private class Source extends InsufficientKeySizeSource instanceof M::Source {
    override predicate hasState(DataFlow::FlowState state) { M::Source.super.hasState(state) }
  }

  /** A sink for an insufficient key size used in AES algorithms. */
  private class Sink extends InsufficientKeySizeSink instanceof M::Sink {
    override predicate hasState(DataFlow::FlowState state) { M::Sink.super.hasState(state) }
  }

  /** An instance of a `javax.crypto.KeyGenerator`. */
  private class CryptoAlgoGen extends NamedCryptoAlgoSpec instanceof JavaxCryptoKeyGenerator {
    override Expr getAlgoSpec() { result = JavaxCryptoKeyGenerator.super.getAlgoSpec() }
  }

  private class AlgoGen extends CryptoAlgoGen {
    AlgoGen() { this.getAlgoName() = "AES" }
  }

  /** A call to the `init` method declared in `javax.crypto.KeyGenerator`. */
  private class KeyInit extends KeyGeneratorInit {
    KeyInit() { this.getMethod() instanceof KeyGeneratorInitMethod }
  }
}

private module Asymmetric {
  /**
   * An instance of a `java.security.KeyPairGenerator`
   * or of a `java.security.AlgorithmParameterGenerator`.
   */
  private class CryptoAlgoGen extends NamedCryptoAlgoSpec {
    CryptoAlgoGen() {
      this instanceof JavaSecurityKeyPairGenerator or
      this instanceof JavaSecurityAlgoParamGenerator
    }

    override Expr getAlgoSpec() { result = this.(CryptoAlgoSpec).getAlgoSpec() }
  }

  /**
   * A call to the `initialize` method declared in `java.security.KeyPairGenerator`
   * or to the `init` method declared in `java.security.AlgorithmParameterGenerator`.
   */
  private class KeyInit extends KeyGeneratorInit {
    KeyInit() {
      this.getMethod() instanceof KeyPairGeneratorInitMethod or
      this.getMethod() instanceof AlgoParamGeneratorInitMethod
    }
  }

  module NonEc {
    private module M = SourceSink<getMinKeySize/0, KeyInit, AlgoGen>;

    /** Returns the minimum recommended key size for RSA, DSA, and DH algorithms. */
    private int getMinKeySize() { result = 2048 }

    /** A source for an insufficient key size used in RSA, DSA, and DH algorithms. */
    private class Source extends InsufficientKeySizeSource instanceof M::Source {
      override predicate hasState(DataFlow::FlowState state) { M::Source.super.hasState(state) }
    }

    /** A sink for an insufficient key size used in RSA, DSA, and DH algorithms. */
    private class Sink extends InsufficientKeySizeSink instanceof M::Sink {
      override predicate hasState(DataFlow::FlowState state) { M::Sink.super.hasState(state) }
    }

    private class SpecSink extends InsufficientKeySizeSink {
      SpecSink() { this.asExpr() = any(Spec spec).getKeySizeArg() }

      override predicate hasState(DataFlow::FlowState state) { state = getMinKeySize().toString() }
    }

    private class AlgoGen extends CryptoAlgoGen {
      AlgoGen() { this.getAlgoName().matches(["RSA", "DSA", "DH"]) }
    }

    /** An instance of an RSA, DSA, or DH algorithm specification. */
    private class Spec extends ClassInstanceExpr {
      Spec() {
        this.getConstructedType() instanceof RsaKeyGenParameterSpec or
        this.getConstructedType() instanceof DsaGenParameterSpec or
        this.getConstructedType() instanceof DhGenParameterSpec
      }

      /** Gets the `keysize` argument of this instance. */
      Argument getKeySizeArg() { result = this.getArgument(0) }
    }
  }

  private module Ec {
    private module M = SourceSink<getMinKeySize/0, KeyInit, AlgoGen>;

    /** Returns the minimum recommended key size for elliptic curve (EC) algorithms. */
    private int getMinKeySize() { result = 256 }

    /** A source for an insufficient key size used in elliptic curve (EC) algorithms. */
    private class Source extends InsufficientKeySizeSource instanceof M::Source {
      override predicate hasState(DataFlow::FlowState state) { M::Source.super.hasState(state) }
    }

    private class SpecSource extends InsufficientKeySizeSource {
      SpecSource() { getKeySize(this.asExpr().(StringLiteral).getValue()) < getMinKeySize() }

      override predicate hasState(DataFlow::FlowState state) { state = getMinKeySize().toString() }
    }

    /** A sink for an insufficient key size used in elliptic curve (EC) algorithms. */
    private class Sink extends InsufficientKeySizeSink instanceof M::Sink {
      override predicate hasState(DataFlow::FlowState state) { M::Sink.super.hasState(state) }
    }

    private class SpecSink extends InsufficientKeySizeSink {
      SpecSink() { this.asExpr() = any(Spec spec).getKeySizeArg() }

      override predicate hasState(DataFlow::FlowState state) { state = getMinKeySize().toString() }
    }

    /** Returns the key size from an EC algorithm's curve name string */
    bindingset[algorithm]
    private int getKeySize(string algorithm) {
      algorithm.matches("sec%") and // specification such as "secp256r1"
      result = algorithm.regexpCapture("sec[p|t](\\d+)[a-zA-Z].*", 1).toInt()
      or
      algorithm.matches("X9.62%") and //specification such as "X9.62 prime192v2"
      result = algorithm.regexpCapture("X9\\.62 .*[a-zA-Z](\\d+)[a-zA-Z].*", 1).toInt()
      or
      (algorithm.matches("prime%") or algorithm.matches("c2tnb%")) and //specification such as "prime192v2"
      result = algorithm.regexpCapture(".*[a-zA-Z](\\d+)[a-zA-Z].*", 1).toInt()
    }

    private class AlgoGen extends CryptoAlgoGen {
      AlgoGen() { this.getAlgoName().matches("EC%") }
    }

    /** An instance of an elliptic curve (EC) algorithm specification. */
    private class Spec extends ClassInstanceExpr {
      Spec() { this.getConstructedType() instanceof EcGenParameterSpec }

      /** Gets the `keysize` argument of this instance. */
      Argument getKeySizeArg() { result = this.getArgument(0) }
    }
  }
}
