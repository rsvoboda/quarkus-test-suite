package io.quarkus.ts.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.nio.file.Path;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Test;

import io.quarkus.test.bootstrap.RestService;
import io.quarkus.test.scenarios.QuarkusScenario;
import io.quarkus.test.scenarios.annotations.DisabledOnNative;
import io.quarkus.test.services.QuarkusApplication;

@QuarkusScenario
@DisabledOnNative
public class CycloneDxJvmIT {

    @QuarkusApplication
    static RestService app = new RestService().setAutoStart(false);

    @Test
    public void embededSBOM() throws Exception {
        // If (ever) multiple applications get tested in this module, the path to the jar would be
        // app.getServiceFolder().toAbsolutePath().resolve("mvn-build/target/quarkus-app/quarkus/generated-bytecode.jar");
        final Path generatedJar = Path.of("target/quarkus-app/quarkus/generated-bytecode.jar");
        assertThat(generatedJar.toFile()).exists();

        String resourceName = "META-INF/sbom/dependency.cdx.json";
        try (JarFile jar = new JarFile(generatedJar.toFile())) {
            JarEntry entry = jar.getJarEntry(resourceName);
            assertThat(entry)
                    .as("Expected resource %s in %s", resourceName, generatedJar.getFileName())
                    .isNotNull();

            try (InputStream is = jar.getInputStream(entry)) {
                Bom sbom = new JsonParser().parse(is);
                assertEmbeddedSbomComponents(sbom);
            }
        }
    }

    private static void assertEmbeddedSbomComponents(Bom bom) {
        assertThat(bom).isNotNull();
        assertThat(bom.getMetadata()).isNotNull();
        assertThat(bom.getMetadata().getComponent()).isNotNull();

        final List<Component> components = bom.getComponents();
        assertThat(components).isNotEmpty();

        assertComponent(components, "io.quarkus", "quarkus-rest");
        assertComponent(components, "io.quarkus", "quarkus-rest-deployment");
        assertComponent(components, "io.quarkus", "quarkus-rest-jackson");
        assertComponent(components, "io.quarkus", "quarkus-rest-jackson-deployment");
        assertComponent(components, "io.quarkus", "quarkus-cyclonedx");
        assertComponent(components, "io.quarkus", "quarkus-cyclonedx-deployment");
    }

    static void assertComponent(List<Component> components, String group, String name) {
        final Component component = components.stream()
                .filter(c -> group != null ? group.equals(c.getGroup()) && name.equals(c.getName()) : name.equals(c.getName()))
                .findFirst()
                .orElse(null);
        assertThat(component)
                .as("Expected component %s:%s in SBOM", group, name)
                .isNotNull();
    }

}
