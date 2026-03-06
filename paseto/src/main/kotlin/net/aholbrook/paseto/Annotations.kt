package net.aholbrook.paseto

@DslMarker
internal annotation class PasetoDslMarker

@RequiresOptIn(
    message = "This is an internal Paseto API and subject to change without notice.",
    level = RequiresOptIn.Level.ERROR,
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.FIELD,
    AnnotationTarget.TYPEALIAS,
    AnnotationTarget.CONSTRUCTOR,
)
annotation class Annotations
