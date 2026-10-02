package io.quarkus.ts.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

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
        try (Stream<Path> stream = Files.walk(Path.of("target"))) {
            stream.forEach(System.out::println);
        }

        // If (ever) multiple applications get tested in this module, the path to the jar would be
        // app.getServiceFolder().toAbsolutePath().resolve("mvn-build/target/sbom-cyclonedx-1.0.0-SNAPSHOT-runner");
        final Path generatedBinary = Path.of("target/sbom-cyclonedx-1.0.0-SNAPSHOT-runner");
        assertThat(generatedBinary.toFile()).exists();

        // TODO check the SBOM

    }

}
