package io.quarkus.ts.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Collectors;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.parsers.JsonParser;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkus.test.bootstrap.RestService;
import io.quarkus.test.scenarios.QuarkusScenario;
import io.quarkus.test.scenarios.annotations.DisabledOnNative;
import io.quarkus.test.scenarios.annotations.EnabledOnQuarkusVersion;
import io.quarkus.test.services.QuarkusApplication;
import io.quarkus.test.services.quarkus.model.QuarkusProperties;

@QuarkusScenario
@DisabledOnNative
@EnabledOnQuarkusVersion(version = ".*redhat.*", reason = "Needs product platform")
public class CycloneDxJvmProductCpeIT {

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
                Files.copy(is, Path.of("target/embedded-sbom.json"), StandardCopyOption.REPLACE_EXISTING);
            }

            String frameworkBomRef = "N/A";
            try (InputStream is = jar.getInputStream(entry)) {
                Bom sbom = new JsonParser().parse(is);
                frameworkBomRef = assertEmbeddedSbomFramework(sbom);
            }

            // Dependency class doesn't provide method to get "provides"
            try (InputStream is = jar.getInputStream(entry)) {
                assertFrameworkBomProvides(is, frameworkBomRef);
            }
        }
    }

    private static String assertEmbeddedSbomFramework(Bom bom) {
        assertThat(bom).isNotNull();
        assertThat(bom.getMetadata()).isNotNull();
        assertThat(bom.getMetadata().getComponent()).isNotNull();

        final List<Component> components = bom.getComponents();
        assertThat(components).isNotEmpty();

        List<Component> frameworkComponents = components.stream()
                .filter(c -> c.getType().equals(Component.Type.FRAMEWORK))
                .toList();

        /*
         * "type" : "framework",
         * "bom-ref" : "pkg:maven/com.redhat.quarkus.platform/quarkus-bom@3.39.3.temporary-redhat-00001?type=pom",
         * "group" : "com.redhat.quarkus.platform",
         * "name" : "quarkus-bom",
         * "version" : "3.39.3.temporary-redhat-00001",
         * "description" : "Red Hat Build of Quarkus - Kubernetes Native Java stack tailored for OpenJDK HotSpot and GraalVM",
         * "scope" : "excluded",
         */
        assertThat(frameworkComponents).size().isEqualTo(1);
        Component quarkusBomComponent = frameworkComponents.get(0);

        String frameworkBomRef = quarkusBomComponent.getBomRef();
        assertThat(frameworkBomRef).contains("/quarkus-bom@");
        assertThat(quarkusBomComponent.getGroup()).contains("quarkus.platform");
        assertThat(quarkusBomComponent.getName()).isEqualTo("quarkus-bom");
        assertThat(quarkusBomComponent.getVersion()).isEqualTo(QuarkusProperties.getVersion());
        assertThat(quarkusBomComponent.getDescription()).contains("Build of Quarkus");

        return frameworkBomRef;

    }

    private static void assertFrameworkBomProvides(InputStream is, String frameworkBomRef) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(is);
        JsonNode dependencies = root.get("dependencies");

        List<String> sbomDefinedDependenciesRefs = new ArrayList<>();
        List<String> frameworkBomProvidesRefs = new ArrayList<>();
        for (JsonNode item : dependencies) {
            if (item.get("ref").asText().equals(frameworkBomRef)) {
                assertThat(item.has("provides")).isTrue();

                JsonNode provides = item.get("provides");
                assertThat(provides).hasSizeGreaterThan(0);
                for (JsonNode enrty : provides) {
                    frameworkBomProvidesRefs.add(enrty.asText());
                }
            } else {
                sbomDefinedDependenciesRefs.add(item.get("ref").asText());
            }
        }

        List<String> dependenciesWithoutEntryInProvides = sbomDefinedDependenciesRefs.stream()
                .filter(dep -> !dep.equals("pkg:maven/io.quarkus.ts.qe/sbom-cyclonedx@1.0.0-SNAPSHOT?type=jar"))
                .filter(dep -> !frameworkBomProvidesRefs.contains(dep))
                .toList();

        List<String> providesEntriesWithoutEntryInDependencies = frameworkBomProvidesRefs.stream()
                .filter(dep -> !sbomDefinedDependenciesRefs.contains(dep)).toList();

        if (dependenciesWithoutEntryInProvides.size() > 0 && providesEntriesWithoutEntryInDependencies.size() > 0) {
            fail("There are dependencies not covered in 'provides' entry of quarkus-bom dependency\n" +
                    failureMessageFor(dependenciesWithoutEntryInProvides) + "\n" +
                    "There are entries defined in 'provides' of quarkus-bom but not covered in dependencies section\n" +
                    failureMessageFor(providesEntriesWithoutEntryInDependencies));
        } else if (dependenciesWithoutEntryInProvides.size() > 0) {
            fail("There are dependencies not covered in 'provides' entry of quarkus-bom dependency\n" +
                    failureMessageFor(dependenciesWithoutEntryInProvides));
        } else if (providesEntriesWithoutEntryInDependencies.size() > 0) {
            fail("There are entries defined in 'provides' of quarkus-bom but not covered in dependencies section\n" +
                    failureMessageFor(providesEntriesWithoutEntryInDependencies));
        }
    }

    private static @NonNull String failureMessageFor(List<String> list) {
        return "This is the list:\n" + list.stream()
                .map(s -> " - " + s)
                .collect(Collectors.joining("\n"));
    }

}
