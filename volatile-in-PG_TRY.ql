/**
 * @name Find missing volatile qualifier in PG_TRY()
 * @kind problem
 * @problem.severity warning
 * @id cpp/example/missing-volatile-in-pg-try
 */

import cpp

predicate pgTryCatchBlocks(Stmt tryBlock, Stmt catchBlock) {
  exists(IfStmt ifStmt, FunctionCall sigsetjmpCall, BinaryOperation op, Literal zero |
    sigsetjmpCall.getTarget().hasName("__sigsetjmp") and
    ifStmt.getCondition().(BinaryOperation) = op and
    op.getOperator() = "==" and
    op.hasOperands(sigsetjmpCall, zero) and
    /* Reduce false positives. */
    ifStmt.isAffectedByMacro() and
    tryBlock = ifStmt.getThen() and
    catchBlock = ifStmt.getElse()
  )
}

predicate varMaybeModified(Stmt stmt, VariableAccess va) {
  va = stmt.getAChild*().(Assignment).getLValue().(VariableAccess)
}

predicate varReadAccess(Stmt stmt, VariableAccess va) {
  (
    va = stmt.getAChild*().(FunctionCall).getAnArgument().(VariableAccess) and
    va.isRValue()
    or
    va = stmt.getAChild*().(Assignment).getRValue().(VariableAccess)
  )
}

from Stmt tryBlock, Stmt catchBlock, LocalVariable var, VariableAccess va1, VariableAccess va2
where
  pgTryCatchBlocks(tryBlock, catchBlock) and
  va1 = var.getAnAccess() and
  varMaybeModified(tryBlock, va1) and
  va2 = var.getAnAccess() and
  varReadAccess(catchBlock, va2) and
  not var.isVolatile()
select var,
  "Object being modified in the PG_TRY() (" + va1.getLocation().getStartLine() + "," +
    va1.getLocation().getStartColumn() + ") block and read in the PG_CATCH() (" +
    va2.getLocation().getStartLine() + "," + va2.getLocation().getStartColumn() +
    ") block should be qualified with volatile"
