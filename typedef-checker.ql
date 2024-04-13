/**
 * Typedef checker
 *
 * @name Typedef checker
 * @kind problem
 * @problem.severity warning
 * @id postgresql/typedef-checker
 */

import cpp

predicate ignoredTypes(Type ty) {
  ty.getName() =
    [
      "size_t", "uintptr_t", "float8", "uint8", "int8", "uint16", "int16", "uint32", "int32",
      "uint64", "int64", "__m128i", "Vector8", "__off_t", "__off64_t", "__uid_t", "__mode_t",
      "__gid_t", "key_t", "__pid_t", "__time_t", "Datum", "yy_size_t", "pg_wchar", "wchar_t",
      "fmStringInfo", "pid_t", "ssize_t", "off_t"
    ]
}

predicate ignoredFunctions(Function f) {
  f.getName() =
    [
      "FunctionalCall1Coll", "FunctionalCall2Coll", "fmgr_info_cxt", "fmgr_info",
      "check_amproc_signature", "format_procedure", "check_amoptsproc_signature",
      "check_hash_func_signature"
    ]
}

predicate ignoredPairs(Type ty1, Type ty2) {
  ty1.getName() = ["Oid", "RegProcedure"] and ty2.getName() = ["Oid", "RegProcudure"]
  or
  ty1.getName() = ["Oid", "RepOriginId"] and ty2.getName() = ["Oid", "RepOriginId"]
  or
  ty1.getName() = ["TimestampTz", "Timestamp"] and ty2.getName() = ["TimestampTz", "Timestamp"]
  or
  ty1.getName() = ["core_yyscan_t", "yyscan_t"] and ty2.getName() = ["core_yyscan_t", "yyscan_t"]
  or
  ty1.getName() = ["Item", "IndexTuple"] and ty2.getName() = ["Item", "IndexTuple"]
  or
  ty1.getName() = ["Item", "HeapTupleHeader"] and ty2.getName() = ["Item", "HeapTupleHeader"]
  or
  ty1.getName() = ["Item", "SpGistInnerTuple"] and ty2.getName() = ["Item", "SpGistInnerTuple"]
  or
  ty1.getName() = ["Item", "SpGistLeafTuple"] and ty2.getName() = ["Item", "SpGistLeafTuple"]
  or
  ty1.getName() = ["Item", "SpGistDeadTuple"] and ty2.getName() = ["Item", "SpGistDeadTuple"]
  or
  ty1.getName() = ["File", "Index"] and ty2.getName() = ["File", "Index"]
  or
  ty1.getName() = ["MemoryContext", "AllocSet"] and ty2.getName() = ["MemoryContext", "AllocSet"]
  or
  ty1.getName() = ["Page", "BulkWriteBuffer"] and ty2.getName() = ["Page", "BulkWriteBuffer"]
  or
  ty1.getName() = ["TimestampTz", "PgStat_Counter"] and
  ty2.getName() = ["TimestampTz", "PgStat_Counter"]
  or
  ty1.getName() = ["Block", "Page"] and ty2.getName() = ["Block", "Page"]
  or
  ty1.getName() = ["TransactionId", "MultiXactOffset"] and
  ty2.getName() = ["TransactionId", "MultiXactOffset"]
  or
  ty1.getName() = ["TableScanDesc", "HeapScanDesc"] and
  ty2.getName() = ["TableScanDesc", "HeapScanDesc"]
  or
  ty1.getName() = ["ExprContextCallbackFunction", "fmExprContextCallbackFunction"] and
  ty2.getName() = ["ExprContextCallbackFunction", "fmExprContextCallbackFunction"]
  or
  ty1.getName() = ["I32", "STRLEN"] and ty2.getName() = ["I32", "STRLEN"]
  or
  ty1.getName() = ["Oid", "VariableSetKind"] and ty2.getName() = ["Oid", "VariableSetKind"]
  or
  ty1.getName() = ["TransactionId", "LocalTransactionId"] and
  ty2.getName() = ["TransactionId", "LocalTransactionId"]
}

from
  FunctionCall functionCall, Function functionDecl, Parameter param, VariableAccess arg,
  Variable argVar, int argIndex, TypedefType paramTy, Type paramTypedefTy, TypedefType argTy,
  Type argTypedefTy
where
  functionDecl = functionCall.getTarget() and
  arg = functionCall.getArgument(argIndex).(VariableAccess) and
  argVar = arg.getTarget() and
  param = functionDecl.getParameter(argIndex) and
  argTy = argVar.getType().(TypedefType) and
  paramTy = param.getType().(TypedefType) and
  argTypedefTy = argTy.getBaseType() and
  paramTypedefTy = paramTy.getBaseType() and
  not ignoredFunctions(functionDecl) and
  not ignoredTypes(argTy) and
  not ignoredTypes(paramTy) and
  not ignoredPairs(argTy, paramTy) and
  not paramTy.getName() = argTy.getName() and
  not (paramTypedefTy.getName() = argTy.getName() or paramTy.getName() = argTypedefTy.getName())
select arg, "Unexpected argument type: " + argTy.getName() + " Expected: " + paramTy.getName()
