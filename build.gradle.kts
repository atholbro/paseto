import org.gradle.testing.jacoco.plugins.JacocoTaskExtension
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    java
    jacoco
    `version-catalog`

    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlinter)
    alias(libs.plugins.detekt)
    alias(libs.plugins.gradleVersions)
    alias(libs.plugins.gradleVersions.filter)
    alias(libs.plugins.gradleVersions.update)
}

repositories {
    mavenLocal()
    mavenCentral()
}

allprojects {
    apply(plugin = "java")
    apply(plugin = "org.jmailen.kotlinter")
    apply(plugin = "io.gitlab.arturbosch.detekt")

    repositories {
        mavenLocal()
        mavenCentral()
    }

    dependencies {
        with (rootProject) {
            testImplementation(libs.kotest.assertions.core)
            testImplementation(libs.junit.jupiter.api)
            testImplementation(libs.junit.jupiter.params)

            testRuntimeOnly(libs.junit.jupiter.engine)
            testRuntimeOnly(libs.junit.platform.launcher)
        }
    }

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(rootProject.libs.versions.jvm.get()))
        }
    }

    tasks {
        withType<KotlinCompile>().configureEach {
            compilerOptions {
                jvmTarget.set(
                    JvmTarget.valueOf(
                        "JVM_" + rootProject.libs.versions.jvm.get().replace('.', '_')
                    )
                )
            }
        }

        withType<JavaCompile> { options.encoding = "UTF-8" }
    }

    detekt {
        buildUponDefaultConfig = true
        config.setFrom(files("${project.rootDir}/detekt-config.yml"))
    }
}

jacoco {
    toolVersion = libs.versions.jacoco.get()
}

tasks.register<JacocoReport>("codeCoverageReport") {
    val includedProjects = subprojects.filterNot { it.path == ":vector-gen" }
    val testTasks = includedProjects.flatMap { it.tasks.withType<Test>() }

    dependsOn(testTasks)

    executionData.setFrom(testTasks.map { it.extensions.getByType<JacocoTaskExtension>().destinationFile })

    includedProjects.forEach {
        val mainSourceSet = it.extensions.getByType<JavaPluginExtension>().sourceSets.getByName("main")
        sourceDirectories.from(mainSourceSet.allSource.sourceDirectories)
        classDirectories.from(mainSourceSet.output)
    }

    reports {
        xml.required.set(true)
        xml.outputLocation.set(file("${layout.buildDirectory.get()}/reports/jacoco/report.xml"))
        html.required.set(false)
        csv.required.set(false)
    }
}
