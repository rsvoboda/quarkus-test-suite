package io.quarkus.ts.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.parsers.JsonParser;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import io.quarkus.deployment.util.ContainerRuntimeUtil;
import io.quarkus.test.bootstrap.RestService;
import io.quarkus.test.scenarios.QuarkusScenario;
import io.quarkus.test.scenarios.annotations.EnabledOnNative;
import io.quarkus.test.services.QuarkusApplication;

@QuarkusScenario
@EnabledOnNative
public class CycloneDxNativeIT {

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

        final Bom syftBom = new JsonParser().parse(output.getBytes(StandardCharsets.UTF_8));
        assertThat(syftBom).isNotNull();
        final List<Component> syftComponents = syftBom.getComponents();
        assertThat(syftComponents).isNotEmpty();

        assertThat(syftComponents.stream()
                .filter(c -> "io.quarkus".equals(c.getGroup()) && "quarkus-rest".equals(c.getName()))
                .findFirst())
                .as("syft-extracted SBOM should contain quarkus-rest")
                .isPresent();
        assertThat(syftComponents.stream()
                .filter(c -> "io.quarkus".equals(c.getGroup()) && "quarkus-cyclonedx".equals(c.getName()))
                .findFirst())
                .as("syft-extracted SBOM should contain quarkus-cyclonedx")
                .isPresent();

    }

}
