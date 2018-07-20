package net.aholbrook.paseto.test;

import org.reflections.Reflections;

import java.util.Set;

public class TestContext {
	private static TestBuilders TEST_BUILDERS = null;

	static TestBuilders builders() {
		if (TEST_BUILDERS == null) {
			Reflections reflections = new Reflections("net.aholbrook.paseto");
			Set<Class<?>> classes = reflections.getTypesAnnotatedWith(Provided.class);

			for (Class<?> clazz : classes) {
				if (TestBuilders.class.isAssignableFrom(clazz)) {
					try {
						TEST_BUILDERS = (TestBuilders) clazz.newInstance();
						return TEST_BUILDERS;
					} catch (Throwable e) {
						// ignore
					}
				}
			}

			throw new RuntimeException("Unable to locate TestBuilders. Please create a subclass of TestBuilders and"
					+ " mark it with @Provided.");
		}

		return TEST_BUILDERS;
	}
}
