import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    `java-library`
    `java-test-fixtures`
    `maven-publish`
    signing
    jacoco

    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)

    alias(libs.plugins.nmcp)
    alias(libs.plugins.nmcp.aggregation)
}

dependencies {
    implementation(libs.bouncycastle)
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.mockk)

    testFixturesImplementation(libs.mockk)
    testFixturesImplementation(libs.kotlinx.serialization.json)

    nmcpAggregation(project(":paseto"))
}

java {
    withJavadocJar()
    withSourcesJar()
}

jacoco {
    toolVersion = libs.versions.jacoco.get()
}

tasks {
    jar {
        archiveBaseName.set("paseto")
    }

    withType<JavaCompile>().configureEach {
        options.release.set(17)
    }

    withType<KotlinCompile>().configureEach {
        compilerOptions {
            freeCompilerArgs.add("-opt-in=net.aholbrook.paseto.InternalApi")
        }
    }


    withType<AbstractPublishToMaven>().configureEach {
        dependsOn(rootProject.tasks.named("check"))
    }

    withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }

    withType<Javadoc>().configureEach {
        options {
            (this as StandardJavadocDocletOptions).addStringOption("Xdoclint:none", "-quiet")
        }
    }

    jacocoTestReport {
        dependsOn(test)

        reports {
            xml.required = true
            csv.required = true
            html.required = true
        }
    }
}

publishing {
    publications {
        group = "net.aholbrook.paseto"
        version = System.getenv("VERSION") ?: ""

        create<MavenPublication>("maven") {
            artifactId = "paseto"
            from(components["java"])

            pom {
                name.set("Paseto")
                description.set("Kotlin Paseto library.")
                url.set("https://github.com/atholbro/paseto")

                licenses {
                    license {
                        name.set("The MIT License (MIT)")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }

                developers {
                    developer {
                        id.set("aholbrook")
                        name.set("Andrew Holbrook")
                        email.set("atholbro@gmail.com")
                    }
                }

                scm {
                    connection.set("scm:git:git@github.com:atholbro/paseto.git")
                    developerConnection.set("scm:git:git@github.com:atholbro/paseto.git")
                    url.set("https://github.com/atholbro/paseto")
                }
            }
        }
    }

    repositories {
        maven {
            url = if (version.toString().endsWith("SNAPSHOT")) {
                uri("https://central.sonatype.com/repository/maven-snapshots/")
            } else {
                uri("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
            }

            credentials {
                username = System.getenv("PUBLISH_USER")
                password = System.getenv("PUBLISH_PASS")
            }
        }
    }
}

signing {
    useInMemoryPgpKeys(
        System.getenv("GPG_KEY"),
        System.getenv("GPG_PASS"),
    )
    sign(publishing.publications)
}

nmcpAggregation {
    centralPortal {
        username = System.getenv("PUBLISH_USER")
        password = System.getenv("PUBLISH_PASS")

        publishingType = "AUTOMATIC"
    }
}

// don't publish test fixtures
// see: https://github.com/vanniktech/gradle-maven-publish-plugin/issues/779
plugins.withId("org.gradle.java-test-fixtures") {
    val component = components["java"] as AdhocComponentWithVariants
    component.withVariantsFromConfiguration(configurations["testFixturesApiElements"]) { skip() }
    component.withVariantsFromConfiguration(configurations["testFixturesRuntimeElements"]) { skip() }
}
