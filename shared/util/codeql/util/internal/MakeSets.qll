/**
 * INTERNAL: This module may be replaced without notice.
 *
 * Provides a module to create first-class representations of sets of values.
 */

/** The input signature for `MakeSets`. */
signature module MkSetsInp {
  class Key;

  class Value;

  Value getAValue(Key k);

  int totalorder(Value v);
}

/**
 * Given a binary predicate `getAValue`, this module groups the `Value` column
 * by `Key` and constructs the corresponding sets of `Value`s as single entities.
 *
 * The output is a functional predicate, `getValueSet`, such that
 * `getValueSet(k).contains(v)` is equivalent to `v = getAValue(k)`, and a
 * class, `ValueSet`, that canonically represents a set of `Value`s. In
 * particular, if two keys `k1` and `k2` relate to the same set of values, then
 * `getValueSet(k1) = getValueSet(k2)`.
 */
module MakeSets<MkSetsInp Inp> {
  private import Inp

  private predicate rankedValue(Key k, Value v, int r) {
    v = rank[r](Value v0 | v0 = getAValue(k) | v0 order by totalorder(v0))
  }

  private int maxRank(Key k) { result = max(int r | rankedValue(k, _, r)) }

  predicate consistency(int r, int bs) { bs = strictcount(Value v | totalorder(v) = r) and bs != 1 }

  private newtype TValList =
    TValListNil() or
    TValListCons(Value head, int r, TValList tail) { hasValListCons(_, head, r, tail) }

  private predicate hasValListCons(Key k, Value head, int r, TValList tail) {
    rankedValue(k, head, r) and
    hasValList(k, r - 1, tail)
  }

  private predicate hasValList(Key k, int r, TValList l) {
    exists(getAValue(k)) and r = 0 and l = TValListNil()
    or
    exists(Value head, TValList tail |
      l = TValListCons(head, r, tail) and
      hasValListCons(k, head, r, tail)
    )
  }

  private predicate hasValueSet(Key k, TValListCons vs) { hasValList(k, maxRank(k), vs) }

  /** A set of `Value`s. */
  class ValueSet extends TValListCons {
    ValueSet() { hasValueSet(_, this) }

    string toString() { result = "ValueSet" }

    private predicate sublist(TValListCons l) {
      this = l or
      this.sublist(TValListCons(_, _, l))
    }

    /** Holds if this set contains `v`. */
    predicate contains(Value v) { this.sublist(TValListCons(v, _, _)) }
  }

  /**
   * Gets the set of values such that `getValueSet(k).contains(v)` is equivalent
   * to `v = getAValue(k)`.
   */
  ValueSet getValueSet(Key k) { hasValueSet(k, result) }
}
