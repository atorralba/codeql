// generated by codegen/codegen.py
private import codeql.swift.generated.Synth
private import codeql.swift.generated.Raw
import codeql.swift.elements.AstNode
import codeql.swift.elements.decl.ModuleDecl

module Generated {
  class Decl extends Synth::TDecl, AstNode {
    /**
     * Gets the module of this declaration.
     *
     * This includes nodes from the "hidden" AST. It can be overridden in subclasses to change the
     * behavior of both the `Immediate` and non-`Immediate` versions.
     */
    ModuleDecl getImmediateModule() {
      result =
        Synth::convertModuleDeclFromRaw(Synth::convertDeclToRaw(this).(Raw::Decl).getModule())
    }

    /**
     * Gets the module of this declaration.
     */
    final ModuleDecl getModule() { result = getImmediateModule().resolve() }
  }
}
