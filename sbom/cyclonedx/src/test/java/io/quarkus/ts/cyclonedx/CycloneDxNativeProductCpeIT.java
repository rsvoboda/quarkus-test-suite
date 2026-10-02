package io.quarkus.ts.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.parsers.JsonParser;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.quarkus.deployment.util.ContainerRuntimeUtil;
import io.quarkus.test.bootstrap.RestService;
import io.quarkus.test.scenarios.QuarkusScenario;
import io.quarkus.test.scenarios.annotations.EnabledOnNative;
import io.quarkus.test.scenarios.annotations.EnabledOnQuarkusVersion;
import io.quarkus.test.services.QuarkusApplication;
import io.quarkus.test.services.quarkus.model.QuarkusProperties;

@QuarkusScenario
@EnabledOnNative
@EnabledOnQuarkusVersion(version = ".*redhat.*", reason = "Needs product platform")
public class CycloneDxNativeProductCpeIT {

    @QuarkusApplication
    static RestService app = new RestService().setAutoStart(false);

    @Test
    public void embededSBOM() throws Exception {

        // If (ever) multiple applications get tested in this module, the path to the jar would be
        // app.getServiceFolder().toAbsolutePath().resolve("mvn-build/target/sbom-cyclonedx-1.0.0-SNAPSHOT-runner");
        final Path generatedBinary = Path.of("target/sbom-cyclonedx-1.0.0-SNAPSHOT-runner");
        assertThat(generatedBinary.toFile()).exists();

        verifySbomWithSyft(generatedBinary);
    }

    /**
     * Uses the anchore/syft container image to extract the SBOM embedded in the
     * native executable and verifies it contains the expected components.
     */
    private void verifySbomWithSyft(Path nativeImage) throws Exception {
        final ContainerRuntimeUtil.ContainerRuntime containerRuntime = ContainerRuntimeUtil.detectContainerRuntime(false);
        Assumptions.assumeTrue(containerRuntime != ContainerRuntimeUtil.ContainerRuntime.UNAVAILABLE,
                "Skipping syft verification since no container runtime is available");

        final String runtime = containerRuntime.getExecutableName();
        final ProcessBuilder pb = new ProcessBuilder(
                runtime, "run", "--rm",
                "-v", nativeImage.toAbsolutePath() + ":/binary:ro,z",
                "anchore/syft",
                "/binary", "-o", "cyclonedx-json");
        pb.redirectError(ProcessBuilder.Redirect.DISCARD);

        final Process process = pb.start();
        final String output;
        try (InputStream is = process.getInputStream()) {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            is.transferTo(baos);
            output = baos.toString(StandardCharsets.UTF_8);
        }
        final int exitCode = process.waitFor();
        assertThat(exitCode)
                .as("syft exited with code %d", exitCode)
                .isZero();

        Files.writeString(Path.of("target/embedded-sbom-native.json"), output);

        final Bom syftBom = new JsonParser().parse(output.getBytes(StandardCharsets.UTF_8));
        assertThat(syftBom).isNotNull();

        String frameworkBomRef = assertEmbeddedSbomFramework(syftBom);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode root = mapper.readTree(output);
        assertFrameworkBomProvides(root, frameworkBomRef);
    }

    private static void assertFrameworkBomProvides(JsonNode root, String frameworkBomRef) throws IOException {
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

    private static String assertEmbeddedSbomFramework(Bom bom) {
        assertThat(bom).isNotNull();
        assertThat(bom.getMetadata()).isNotNull();
        assertThat(bom.getMetadata().getComponent()).isNotNull();

        final List<Component> components = bom.getComponents();
        assertThat(components).isNotEmpty();

        List<Component> frameworkComponents = components.stream()
                .filter(c -> c.getType().equals(Component.Type.FRAMEWORK))
                .toList();
        assertThat(frameworkComponents).size().as("Exactly one framework component is expected").isEqualTo(1);
        Component quarkusBomComponent = frameworkComponents.get(0);

        String frameworkBomRef = quarkusBomComponent.getBomRef();
        assertThat(frameworkBomRef).contains("/quarkus-bom@");
        assertThat(quarkusBomComponent.getGroup()).contains("quarkus.platform");
        assertThat(quarkusBomComponent.getName()).isEqualTo("quarkus-bom");
        assertThat(quarkusBomComponent.getVersion()).isEqualTo(QuarkusProperties.getVersion());
        assertThat(quarkusBomComponent.getDescription()).contains("Build of Quarkus");
        assertThat(quarkusBomComponent.getCpe()).contains("cpe:/a:redhat:quarkus:");
        assertThat(quarkusBomComponent.getPurl()).contains("pkg:maven/com.redhat.quarkus.platform/quarkus-bom@");

        return frameworkBomRef;
    }
}
