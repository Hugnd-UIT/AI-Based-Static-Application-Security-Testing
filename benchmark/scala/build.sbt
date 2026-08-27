name := "benchmark-scala"
version := "0.1"
scalaVersion := "2.13.8"

// Vulnerable dependencies
libraryDependencies += "org.apache.logging.log4j" % "log4j-core" % "2.14.1"
libraryDependencies += "com.fasterxml.jackson.core" % "jackson-databind" % "2.9.10"
libraryDependencies += "org.apache.commons" % "commons-text" % "1.9"
libraryDependencies += "org.yaml" % "snakeyaml" % "1.30"
libraryDependencies += "org.apache.commons" % "commons-compress" % "1.20"
