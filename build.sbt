import Dependencies._

ThisBuild / scalaVersion     := "2.12.13"
ThisBuild / version          := "1.0.0-dev"
ThisBuild / organization     := "com.cloud-apim"
ThisBuild / organizationName := "Cloud-APIM"

lazy val excludesSlf4j = Seq(
  ExclusionRule(organization = "org.slf4j"),
)

lazy val root = (project in file("."))
  .settings(
    name := "otoroshi-plugin-webhook-validator",
    assembly / test  := {},
    assembly / assemblyJarName := "otoroshi-plugin-webhook-validator-assembly_2.12-dev.jar",
    libraryDependencies ++= Seq(
      "fr.maif" %% "otoroshi" % "17.13.0" % "provided",
      munit % Test
    )
  )