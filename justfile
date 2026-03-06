#!/usr/bin/env just --justfile

VERSION := env_var_or_default("VERSION", "")

# Gradle Variables
in_ci := env_var_or_default("GITHUB_ACTIONS", "")
gradlew_local := justfile_directory() + '/gradlew -p ' + justfile_directory()
gradlew_ci := 'TERM=dumb ' + gradlew_local + ' -q'
gradlew := if in_ci == "" { gradlew_local } else { gradlew_ci }

# Print a list of available recipes
_default:
  @just --justfile {{justfile()}} --list --unsorted


# Build
build:
    {{gradlew}} -configuration-cache build -x check --warning-mode all

# Deletes all build outputs & artifacts
clean:
    {{gradlew}} -configuration-cache clean

# Build and publish to maven central
publish version=(VERSION):
    VERSION="{{version}}" {{gradlew}} lintKotlin test publishAggregationToCentralPortal

# Build and publish to local maven repository (~/.m2)
publish-local version=(VERSION):
    VERSION="{{version}}" {{gradlew}} lintKotlin test nmcpPublishAggregationToMavenLocal

# Run unit tests (when all="true" all tests will run, otherwise only outdated tests run)
test all="false":
    {{gradlew}} -configuration-cache {{ if all == "true" { "cleanTest test" } else { "test" } }}

# Run Gradle checks (lint, test, complexity).
check:
    {{gradlew}} -configuration-cache check

# Generate a code coverage report (via Jacoco).
coverage:
    {{gradlew}} -configuration-cache jacocoTestReport

# Verify source code style.
lint:
    {{gradlew}} -configuration-cache lintKotlin

# Format the source code.
format:
    {{gradlew}} -configuration-cache versionCatalogFormat formatKotlin

# Calculates code complexity.
complexity:
    {{gradlew}} -configuration-cache detekt

# Checks for library updates.
update-check:
    {{gradlew}} dependencyUpdates -Drevision=release

# Automatically updates all dependencies in the version catalog.
update-apply:
    {{gradlew}} versionCatalogUpdate

api-check:
    {{gradlew}} apiCheck

api-dump:
    {{gradlew}} apiDump
