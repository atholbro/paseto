package net.aholbrook.paseto.test.common.utils;

import net.aholbrook.paseto.test.GlobalTestBuilders;

public class TestContext {
	private static TestBuilders TEST_BUILDERS = null;

	public static TestBuilders builders() {
		if (TEST_BUILDERS == null) {
			TEST_BUILDERS = new GlobalTestBuilders();
		}

		return TEST_BUILDERS;
	}
}