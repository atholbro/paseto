package net.aholbrook.paseto

import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.matchers.shouldBe
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.CsvSource
import java.time.Instant

class Rfc3339Tests {
    @ParameterizedTest(name = "{0}")
    @CsvSource(value = [
        "negative_zero_offset_basic,2026-02-09T14:30:00-00:00,2026-02-09T14:30:00Z",
        "negative_zero_offset_with_fraction_zero,2026-02-09T14:30:00.000-00:00,2026-02-09T14:30:00Z",
        "negative_zero_offset_high_precision_fraction,2026-02-09T14:30:00.123456789-00:00,2026-02-09T14:30:00.123456789Z",
        "leap_second_utc_z,2016-12-31T23:59:60Z,2016-12-31T23:59:60Z",
        "leap_second_utc_offset,2016-12-31T23:59:60+00:00,2016-12-31T23:59:60Z",
        "leap_second_negative_zero_offset,2026-06-30T23:59:60-00:00,2026-06-30T23:59:60Z",
    ])
    fun rfc3339InstantParse(name: String, rfc3339: String, iso8601: String) {
        shouldNotThrow<Throwable> {
            val expected = Instant.parse(iso8601)
            val actual = Instant.parse(rfc3339)
            actual shouldBe expected
        }
    }
}
