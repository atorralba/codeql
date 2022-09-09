import java
private import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.ExternalFlow
private import semmle.code.java.dataflow.FlowSteps

// ! Remember to add 'private' annotation as needed to new classes/predicates below.
// ! and clean-up comments, etc. in below in general before marking as ready-for-review.
/**
 * The class `android.content.Intent`.
 */
class TypeIntent extends Class {
  TypeIntent() { this.hasQualifiedName("android.content", "Intent") }
}

/** The class `android.content.ComponentName`. */
class TypeComponentName extends Class {
  TypeComponentName() { this.hasQualifiedName("android.content", "ComponentName") }
}

/**
 * The class `android.app.Activity`.
 */
class TypeActivity extends Class {
  TypeActivity() { this.hasQualifiedName("android.app", "Activity") }
}

/**
 * The class `android.app.Service`.
 */
class TypeService extends Class {
  TypeService() { this.hasQualifiedName("android.app", "Service") }
}

/**
 * The class `android.content.Context`.
 */
class TypeContext extends RefType {
  // Not inlining this makes it more likely to be used as a sentinel,
  // which is useful when running Android queries on non-Android projects.
  pragma[noinline]
  TypeContext() { this.hasQualifiedName("android.content", "Context") }
}

/**
 * The class `android.content.BroadcastReceiver`.
 */
class TypeBroadcastReceiver extends Class {
  TypeBroadcastReceiver() { this.hasQualifiedName("android.content", "BroadcastReceiver") }
}

/**
 * The method `Activity.getIntent`
 */
class AndroidGetIntentMethod extends Method {
  AndroidGetIntentMethod() {
    this.hasName("getIntent") and this.getDeclaringType() instanceof TypeActivity
  }
}

/**
 * The method `BroadcastReceiver.onReceive`.
 */
class AndroidReceiveIntentMethod extends Method {
  AndroidReceiveIntentMethod() {
    this.hasName("onReceive") and this.getDeclaringType() instanceof TypeBroadcastReceiver
  }
}

// ! not sure if I like the name of the below class, but
// ! trying to be consistent with `AndroidReceiveIntentMethod`
// ! and `AndroidGetIntentMethod`...
/**
 * A method of type Service that receives an Intent.
 * Namely, `Service.onStart`, `onStartCommand`, `onBind`,
 * `onRebind`, `onUnbind`, or `onTaskRemoved`
 */
class AndroidServiceIntentMethod extends Method {
  AndroidServiceIntentMethod() {
    (
      this.getName().matches("onStart%") or
      this.getName().matches("on%ind") or
      this.hasName("onTaskRemoved")
    ) and
    this.getDeclaringType() instanceof TypeService
  }
}

/**
 * The method `Context.startActivity`, `Context.startActivities`,
 * `Activity.startActivity`,`Activity.startActivities`,
 * `Activity.startActivityForResult`, `Activity.startActivityIfNeeded`,
 * `Activity.startNextMatchingActivity`, `Activity.startActivityFromChild`,
 * or `Activity.startActivityFromFragment`.
 */
class StartActivityMethod extends Method {
  StartActivityMethod() {
    this.getName().matches("start%Activit%") and
    (
      this.getDeclaringType() instanceof TypeContext or
      this.getDeclaringType() instanceof TypeActivity
    )
  }
}

/**
 * The method `Context.sendBroadcast`, `sendBroadcastAsUser`,
 * `sendOrderedBroadcast`, `sendOrderedBroadcastAsUser`,
 * `sendStickyBroadcast`, `sendStickyBroadcastAsUser`,
 * `sendStickyOrderedBroadcast`, `sendStickyOrderedBroadcastAsUser`,
 * or `sendBroadcastWithMultiplePermissions`.
 */
class SendBroadcastMethod extends Method {
  SendBroadcastMethod() {
    this.getName().matches("send%Broadcast%") and
    this.getDeclaringType() instanceof TypeContext
  }
}

// ! remove reference from below QLDoc?
/**
 * The method `Context.startService`, `startForegroundService`,
 * `bindIsolatedService`, `bindService`, or `bindServiceAsUser`.
 *
 * From https://developer.android.com/reference/android/app/Service:
 * "Services can be started with Context.startService() and Context.bindService()."
 */
class StartServiceMethod extends Method {
  StartServiceMethod() {
    (
      this.getName().matches("start%Service") or
      this.getName().matches("bind%Service%")
    ) and
    this.getDeclaringType() instanceof TypeContext
  }
}

/**
 * Specifies that if an `Intent` is tainted, then so are its synthetic fields.
 */
private class IntentFieldsInheritTaint extends DataFlow::SyntheticFieldContent,
  TaintInheritingContent {
  IntentFieldsInheritTaint() { this.getField().matches("android.content.Intent.%") }
}

/**
 * The method `Intent.getParcelableExtra`.
 */
class IntentGetParcelableExtraMethod extends Method {
  IntentGetParcelableExtraMethod() {
    this.hasName("getParcelableExtra") and
    this.getDeclaringType() instanceof TypeIntent
  }
}

/** The class `android.os.BaseBundle`, or a class that extends it. */
class AndroidBundle extends Class {
  AndroidBundle() { this.getAnAncestor().hasQualifiedName("android.os", "BaseBundle") }
}

/**
 * An `Intent` that explicitly sets a destination component.
 *
 * The `Intent` is not considered explicit if a `null` value ever flows to the destination
 * component, even if only conditionally.
 *
 * For example, in the following code, `intent` is not considered an `ExplicitIntent`:
 * ```java
 * intent.setClass(condition ? null : "MyClass");
 * ```
 */
class ExplicitIntent extends Expr {
  ExplicitIntent() {
    exists(MethodAccess ma, Method m |
      ma.getMethod() = m and
      m.getDeclaringType() instanceof TypeIntent and
      m.hasName(["setPackage", "setClass", "setClassName", "setComponent"]) and
      not exists(NullLiteral nullLiteral | DataFlow::localExprFlow(nullLiteral, ma.getAnArgument())) and
      ma.getQualifier() = this
    )
    or
    exists(ConstructorCall cc, Argument classArg |
      cc.getConstructedType() instanceof TypeIntent and
      cc.getAnArgument() = classArg and
      classArg.getType() instanceof TypeClass and
      not exists(NullLiteral nullLiteral | DataFlow::localExprFlow(nullLiteral, classArg)) and
      cc = this
    )
  }
}

/**
 * A sanitizer for explicit intents.
 *
 * Use this when you want to work only with implicit intents
 * in a `DataFlow` or `TaintTracking` configuration.
 */
class ExplicitIntentSanitizer extends DataFlow::Node {
  ExplicitIntentSanitizer() {
    exists(ExplicitIntent explIntent | DataFlow::localExprFlow(explIntent, this.asExpr()))
  }
}

private class BundleExtrasSyntheticField extends SyntheticField {
  BundleExtrasSyntheticField() { this = "android.content.Intent.extras" }

  override RefType getType() { result instanceof AndroidBundle }
}

/**
 * Holds if extras may be implicitly read from the Intent `node`.
 */
predicate allowIntentExtrasImplicitRead(DataFlow::Node node, DataFlow::Content c) {
  node.getType() instanceof TypeIntent and
  (
    c instanceof DataFlow::MapValueContent
    or
    c.(DataFlow::SyntheticFieldContent).getType() instanceof AndroidBundle
  )
}

/**
 * The fields to grant URI permissions of the class `android.content.Intent`:
 *
 * - `Intent.FLAG_GRANT_READ_URI_PERMISSION`
 * - `Intent.FLAG_GRANT_WRITE_URI_PERMISSION`
 * - `Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION`
 * - `Intent.FLAG_GRANT_PREFIX_URI_PERMISSION`
 */
class GrantUriPermissionFlag extends Field {
  GrantUriPermissionFlag() {
    this.getDeclaringType() instanceof TypeIntent and
    this.getName().matches("FLAG_GRANT_%_URI_PERMISSION")
  }
}

/** The field `Intent.FLAG_GRANT_READ_URI_PERMISSION`. */
class GrantReadUriPermissionFlag extends GrantUriPermissionFlag {
  GrantReadUriPermissionFlag() { this.hasName("FLAG_GRANT_READ_URI_PERMISSION") }
}

/** The field `Intent.FLAG_GRANT_WRITE_URI_PERMISSION`. */
class GrantWriteUriPermissionFlag extends GrantUriPermissionFlag {
  GrantWriteUriPermissionFlag() { this.hasName("FLAG_GRANT_WRITE_URI_PERMISSION") }
}

// ! OLD VERSION - need to delete - keeping for now for reference
// /**
//  * A value-preserving step from the Intent argument of a `startActivity` call to
//  * a `getIntent` call in the Activity the Intent pointed to in its constructor.
//  */
// private class StartActivityIntentStep extends AdditionalValueStep {
//   override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
//     exists(MethodAccess startActivity, MethodAccess getIntent, ClassInstanceExpr newIntent |
//       startActivity.getMethod().overrides*(any(ContextStartActivityMethod m)) and
//       getIntent.getMethod().overrides*(any(AndroidGetIntentMethod m)) and
//       newIntent.getConstructedType() instanceof TypeIntent and
//       DataFlow::localExprFlow(newIntent, startActivity.getArgument(0)) and
//       newIntent.getArgument(1).getType().(ParameterizedType).getATypeArgument() =
//         getIntent.getReceiverType() and
//       n1.asExpr() = startActivity.getArgument(0) and
//       n2.asExpr() = getIntent
//     )
//   }
// }
/*
 * // ! TODO: create a parent class for the below three steps?
 * // ! e.g. something like the below?
 * // ! could put `getClassArgOfIntentConstructor` in parent class?
 *
 * // ! Also look into whether it's possible to reduce any code duplication
 * // ! across the three steps in general.
 * // class StartComponentIntentStep extends AdditionalValueStep { }
 */

// The `android.Content.Intent` class has two constructors with an argument of type
// `Class<?>`. One has the argument at position 1 and the other at position 3.
// https://developer.android.com/reference/android/content/Intent#public-constructors
private Argument getClassArgOfIntentConstructor(ClassInstanceExpr classInstanceExpr) {
  classInstanceExpr.getConstructedType() instanceof TypeIntent and
  if classInstanceExpr.getNumArgument() = 2
  then result = classInstanceExpr.getArgument(1)
  else result = classInstanceExpr.getArgument(3)
}

/**
 * A value-preserving step from the Intent argument of a `startActivity` call to
 * a `getIntent` call in the Activity the Intent pointed to in its constructor.
 */
private class StartActivityIntentStep extends AdditionalValueStep {
  // The `startActivityFromChild` and `startActivityFromFragment` methods have
  // an argument of type `Intent` at position 1, but the rest of the methods of
  // type `StartActivityMethod` have an argument of type `Intent` at position 0.
  private Argument getIntentArgOfStartActMethod(MethodAccess methodAccess) {
    methodAccess.getMethod().overrides*(any(StartActivityMethod m)) and
    if
      methodAccess.getMethod().hasName("startActivityFromChild") or
      methodAccess.getMethod().hasName("startActivityFromFragment")
    then result = methodAccess.getArgument(1)
    else result = methodAccess.getArgument(0)
  }

  // // The `android.Content.Intent` class has two constructors with an argument of type
  // // `Class<?>`. One has the argument at position 1 and the other at position 3.
  // // https://developer.android.com/reference/android/content/Intent#public-constructors
  // private Argument getClassArgOfIntentConstructor(ClassInstanceExpr classInstanceExpr) {
  //   classInstanceExpr.getConstructedType() instanceof TypeIntent and
  //   if classInstanceExpr.getNumArgument() = 2
  //   then result = classInstanceExpr.getArgument(1)
  //   else result = classInstanceExpr.getArgument(3)
  // }
  override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
    exists(MethodAccess startActivity, MethodAccess getIntent, ClassInstanceExpr newIntent |
      startActivity.getMethod().overrides*(any(StartActivityMethod m)) and
      getIntent.getMethod().overrides*(any(AndroidGetIntentMethod m)) and
      newIntent.getConstructedType() instanceof TypeIntent and
      DataFlow::localExprFlow(newIntent, getIntentArgOfStartActMethod(startActivity)) and
      getClassArgOfIntentConstructor(newIntent).getType().(ParameterizedType).getATypeArgument() =
        getIntent.getReceiverType() and
      n1.asExpr() = getIntentArgOfStartActMethod(startActivity) and
      n2.asExpr() = getIntent
    )
  }
}

/**
 * A value-preserving step from the Intent argument of a `sendBroadcast` call to
 * the `Intent` parameter in the `onReceive` method of the BroadcastReceiver the
 * Intent pointed to in its constructor.
 */
private class SendBroadcastReceiverIntentStep extends AdditionalValueStep {
  override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
    exists(MethodAccess sendBroadcast, Method onReceive, ClassInstanceExpr newIntent |
      sendBroadcast.getMethod().overrides*(any(SendBroadcastMethod m)) and
      onReceive.overrides*(any(AndroidReceiveIntentMethod m)) and
      newIntent.getConstructedType() instanceof TypeIntent and
      DataFlow::localExprFlow(newIntent, sendBroadcast.getArgument(0)) and
      getClassArgOfIntentConstructor(newIntent).getType().(ParameterizedType).getATypeArgument() =
        onReceive.getDeclaringType() and
      n1.asExpr() = sendBroadcast.getArgument(0) and
      n2.asParameter() = onReceive.getParameter(1)
    )
  }
}

// ! potentially reword QLDoc
/**
 * A value-preserving step from the Intent argument of a `startService` call to
 * the `Intent` parameter in an `AndroidServiceIntentMethod` of the Service the
 * Intent pointed to in its constructor.
 */
private class StartServiceIntentStep extends AdditionalValueStep {
  override predicate step(DataFlow::Node n1, DataFlow::Node n2) {
    exists(MethodAccess startService, Method serviceIntent, ClassInstanceExpr newIntent |
      startService.getMethod().overrides*(any(StartServiceMethod m)) and
      serviceIntent.overrides*(any(AndroidServiceIntentMethod m)) and
      newIntent.getConstructedType() instanceof TypeIntent and
      DataFlow::localExprFlow(newIntent, startService.getArgument(0)) and
      getClassArgOfIntentConstructor(newIntent).getType().(ParameterizedType).getATypeArgument() =
        serviceIntent.getDeclaringType() and
      n1.asExpr() = startService.getArgument(0) and
      n2.asParameter() = serviceIntent.getParameter(0)
    )
  }
}

private class IntentBundleFlowSteps extends SummaryModelCsv {
  override predicate row(string row) {
    row =
      [
        //"namespace;type;subtypes;name;signature;ext;input;output;kind"
        "android.os;BaseBundle;true;get;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;BaseBundle;true;getString;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;BaseBundle;true;getString;(String,String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;BaseBundle;true;getString;(String,String);;Argument[1];ReturnValue;value;manual",
        "android.os;BaseBundle;true;getStringArray;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;BaseBundle;true;keySet;();;Argument[-1].MapKey;ReturnValue.Element;value;manual",
        "android.os;BaseBundle;true;putAll;(PersistableBundle);;Argument[0].MapKey;Argument[-1].MapKey;value;manual",
        "android.os;BaseBundle;true;putAll;(PersistableBundle);;Argument[0].MapValue;Argument[-1].MapValue;value;manual",
        "android.os;BaseBundle;true;putBoolean;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;BaseBundle;true;putBooleanArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;BaseBundle;true;putDouble;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;BaseBundle;true;putDoubleArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;BaseBundle;true;putInt;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;BaseBundle;true;putIntArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;BaseBundle;true;putLong;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;BaseBundle;true;putLongArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;BaseBundle;true;putString;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;BaseBundle;true;putString;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;BaseBundle;true;putStringArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;BaseBundle;true;putStringArray;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;false;Bundle;(Bundle);;Argument[0].MapKey;Argument[-1].MapKey;value;manual",
        "android.os;Bundle;false;Bundle;(Bundle);;Argument[0].MapValue;Argument[-1].MapValue;value;manual",
        "android.os;Bundle;false;Bundle;(PersistableBundle);;Argument[0].MapKey;Argument[-1].MapKey;value;manual",
        "android.os;Bundle;false;Bundle;(PersistableBundle);;Argument[0].MapValue;Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;clone;();;Argument[-1].MapKey;ReturnValue.MapKey;value;manual",
        "android.os;Bundle;true;clone;();;Argument[-1].MapValue;ReturnValue.MapValue;value;manual",
        // model for Bundle.deepCopy is not fully precise, as some map values aren't copied by value
        "android.os;Bundle;true;deepCopy;();;Argument[-1].MapKey;ReturnValue.MapKey;value;manual",
        "android.os;Bundle;true;deepCopy;();;Argument[-1].MapValue;ReturnValue.MapValue;value;manual",
        "android.os;Bundle;true;getBinder;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getBundle;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getByteArray;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getCharArray;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getCharSequence;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getCharSequence;(String,CharSequence);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getCharSequence;(String,CharSequence);;Argument[1];ReturnValue;value;manual",
        "android.os;Bundle;true;getCharSequenceArray;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getCharSequenceArrayList;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getParcelable;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getParcelableArray;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getParcelableArrayList;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getSerializable;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getSparseParcelableArray;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;getStringArrayList;(String);;Argument[-1].MapValue;ReturnValue;value;manual",
        "android.os;Bundle;true;putAll;(Bundle);;Argument[0].MapKey;Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putAll;(Bundle);;Argument[0].MapValue;Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putBinder;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putBinder;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putBundle;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putBundle;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putByte;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putByteArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putByteArray;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putChar;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putCharArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putCharArray;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putCharSequence;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putCharSequence;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putCharSequenceArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putCharSequenceArray;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putCharSequenceArrayList;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putCharSequenceArrayList;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putFloat;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putFloatArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putIntegerArrayList;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putParcelable;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putParcelable;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putParcelableArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putParcelableArray;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putParcelableArrayList;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putParcelableArrayList;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putSerializable;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putSerializable;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putShort;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putShortArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putSize;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putSizeF;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putSparseParcelableArray;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putSparseParcelableArray;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;putStringArrayList;;;Argument[0];Argument[-1].MapKey;value;manual",
        "android.os;Bundle;true;putStringArrayList;;;Argument[1];Argument[-1].MapValue;value;manual",
        "android.os;Bundle;true;readFromParcel;;;Argument[0];Argument[-1].MapKey;taint;manual",
        "android.os;Bundle;true;readFromParcel;;;Argument[0];Argument[-1].MapValue;taint;manual",
        // currently only the Extras part of the intent and the data field are fully modeled
        "android.content;Intent;false;Intent;(Intent);;Argument[0].SyntheticField[android.content.Intent.extras].MapKey;Argument[-1].SyntheticField[android.content.Intent.extras].MapKey;value;manual",
        "android.content;Intent;false;Intent;(Intent);;Argument[0].SyntheticField[android.content.Intent.extras].MapValue;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;value;manual",
        "android.content;Intent;false;Intent;(String,Uri);;Argument[1];Argument[-1].SyntheticField[android.content.Intent.data];value;manual",
        "android.content;Intent;false;Intent;(String,Uri,Context,Class);;Argument[1];Argument[-1].SyntheticField[android.content.Intent.data];value;manual",
        "android.content;Intent;true;addCategory;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;addFlags;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;false;createChooser;;;Argument[0..2];ReturnValue.SyntheticField[android.content.Intent.extras].MapValue;value;manual",
        "android.content;Intent;true;getBundleExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getByteArrayExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getCharArrayExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getCharSequenceArrayExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getCharSequenceArrayListExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getCharSequenceExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getData;;;Argument[-1].SyntheticField[android.content.Intent.data];ReturnValue;value;manual",
        "android.content;Intent;true;getDataString;;;Argument[-1].SyntheticField[android.content.Intent.data];ReturnValue;taint;manual",
        "android.content;Intent;true;getExtras;();;Argument[-1].SyntheticField[android.content.Intent.extras];ReturnValue;value;manual",
        "android.content;Intent;false;getIntent;;;Argument[0];ReturnValue.SyntheticField[android.content.Intent.data];taint;manual",
        "android.content;Intent;false;getIntentOld;;;Argument[0];ReturnValue.SyntheticField[android.content.Intent.data];taint;manual",
        "android.content;Intent;true;getParcelableArrayExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getParcelableArrayListExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getParcelableExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getSerializableExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getStringArrayExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getStringArrayListExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;true;getStringExtra;(String);;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;ReturnValue;value;manual",
        "android.content;Intent;false;parseUri;;;Argument[0];ReturnValue.SyntheticField[android.content.Intent.data];taint;manual",
        "android.content;Intent;true;putCharSequenceArrayListExtra;;;Argument[0];Argument[-1].SyntheticField[android.content.Intent.extras].MapKey;value;manual",
        "android.content;Intent;true;putCharSequenceArrayListExtra;;;Argument[1];Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;value;manual",
        "android.content;Intent;true;putCharSequenceArrayListExtra;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;putExtra;;;Argument[0];Argument[-1].SyntheticField[android.content.Intent.extras].MapKey;value;manual",
        "android.content;Intent;true;putExtra;;;Argument[1];Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;value;manual",
        "android.content;Intent;true;putExtra;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;putExtras;(Bundle);;Argument[0].MapKey;Argument[-1].SyntheticField[android.content.Intent.extras].MapKey;value;manual",
        "android.content;Intent;true;putExtras;(Bundle);;Argument[0].MapValue;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;value;manual",
        "android.content;Intent;true;putExtras;(Bundle);;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;putExtras;(Intent);;Argument[0].SyntheticField[android.content.Intent.extras].MapKey;Argument[-1].SyntheticField[android.content.Intent.extras].MapKey;value;manual",
        "android.content;Intent;true;putExtras;(Intent);;Argument[0].SyntheticField[android.content.Intent.extras].MapValue;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;value;manual",
        "android.content;Intent;true;putExtras;(Intent);;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;putIntegerArrayListExtra;;;Argument[0];Argument[-1].SyntheticField[android.content.Intent.extras].MapKey;value;manual",
        "android.content;Intent;true;putIntegerArrayListExtra;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;putParcelableArrayListExtra;;;Argument[0];Argument[-1].SyntheticField[android.content.Intent.extras].MapKey;value;manual",
        "android.content;Intent;true;putParcelableArrayListExtra;;;Argument[1];Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;value;manual",
        "android.content;Intent;true;putParcelableArrayListExtra;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;putStringArrayListExtra;;;Argument[0];Argument[-1].SyntheticField[android.content.Intent.extras].MapKey;value;manual",
        "android.content;Intent;true;putStringArrayListExtra;;;Argument[1];Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;value;manual",
        "android.content;Intent;true;putStringArrayListExtra;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;replaceExtras;(Bundle);;Argument[0].MapKey;Argument[-1].SyntheticField[android.content.Intent.extras].MapKey;value;manual",
        "android.content;Intent;true;replaceExtras;(Bundle);;Argument[0].MapValue;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;value;manual",
        "android.content;Intent;true;replaceExtras;(Bundle);;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;replaceExtras;(Intent);;Argument[0].SyntheticField[android.content.Intent.extras].MapKey;Argument[-1].SyntheticField[android.content.Intent.extras].MapKey;value;manual",
        "android.content;Intent;true;replaceExtras;(Intent);;Argument[0].SyntheticField[android.content.Intent.extras].MapValue;Argument[-1].SyntheticField[android.content.Intent.extras].MapValue;value;manual",
        "android.content;Intent;true;replaceExtras;(Intent);;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setAction;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setClass;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setClassName;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setComponent;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setData;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setData;;;Argument[0];Argument[-1].SyntheticField[android.content.Intent.data];value;manual",
        "android.content;Intent;true;setDataAndNormalize;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setDataAndNormalize;;;Argument[0];Argument[-1].SyntheticField[android.content.Intent.data];value;manual",
        "android.content;Intent;true;setDataAndType;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setDataAndType;;;Argument[0];Argument[-1].SyntheticField[android.content.Intent.data];value;manual",
        "android.content;Intent;true;setDataAndTypeAndNormalize;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setDataAndTypeAndNormalize;;;Argument[0];Argument[-1].SyntheticField[android.content.Intent.data];value;manual",
        "android.content;Intent;true;setFlags;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setIdentifier;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setPackage;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setType;;;Argument[-1];ReturnValue;value;manual",
        "android.content;Intent;true;setTypeAndNormalize;;;Argument[-1];ReturnValue;value;manual"
      ]
  }
}

private class IntentComponentTaintSteps extends SummaryModelCsv {
  override predicate row(string s) {
    s =
      [
        "android.content;Intent;true;Intent;(Intent);;Argument[0];Argument[-1];taint;manual",
        "android.content;Intent;true;Intent;(Context,Class);;Argument[1];Argument[-1];taint;manual",
        "android.content;Intent;true;Intent;(String,Uri,Context,Class);;Argument[3];Argument[-1];taint;manual",
        "android.content;Intent;true;getIntent;(String);;Argument[0];ReturnValue;taint;manual",
        "android.content;Intent;true;getIntentOld;(String);;Argument[0];ReturnValue;taint;manual",
        "android.content;Intent;true;parseUri;(String,int);;Argument[0];ReturnValue;taint;manual",
        "android.content;Intent;true;setPackage;;;Argument[0];Argument[-1];taint;manual",
        "android.content;Intent;true;setClass;;;Argument[1];Argument[-1];taint;manual",
        "android.content;Intent;true;setClassName;(Context,String);;Argument[1];Argument[-1];taint;manual",
        "android.content;Intent;true;setClassName;(String,String);;Argument[0..1];Argument[-1];taint;manual",
        "android.content;Intent;true;setComponent;;;Argument[0];Argument[-1];taint;manual",
        "android.content;ComponentName;false;ComponentName;(String,String);;Argument[0..1];Argument[-1];taint;manual",
        "android.content;ComponentName;false;ComponentName;(Context,String);;Argument[1];Argument[-1];taint;manual",
        "android.content;ComponentName;false;ComponentName;(Context,Class);;Argument[1];Argument[-1];taint;manual",
        "android.content;ComponentName;false;ComponentName;(Parcel);;Argument[0];Argument[-1];taint;manual",
        "android.content;ComponentName;false;createRelative;(String,String);;Argument[0..1];ReturnValue;taint;manual",
        "android.content;ComponentName;false;createRelative;(Context,String);;Argument[1];ReturnValue;taint;manual",
        "android.content;ComponentName;false;flattenToShortString;;;Argument[-1];ReturnValue;taint;manual",
        "android.content;ComponentName;false;flattenToString;;;Argument[-1];ReturnValue;taint;manual",
        "android.content;ComponentName;false;getClassName;;;Argument[-1];ReturnValue;taint;manual",
        "android.content;ComponentName;false;getPackageName;;;Argument[-1];ReturnValue;taint;manual",
        "android.content;ComponentName;false;getShortClassName;;;Argument[-1];ReturnValue;taint;manual",
        "android.content;ComponentName;false;unflattenFromString;;;Argument[0];ReturnValue;taint;manual"
      ]
  }
}
