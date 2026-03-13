plugins {
    application

    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

application {
    mainClass.set("net.aholbrook.paseto.vectorgen.MainKt")
}

dependencies {
    implementation(project(":paseto"))
    implementation(testFixtures(project(":paseto")))
    implementation(libs.bouncycastle)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.clikt)
}
