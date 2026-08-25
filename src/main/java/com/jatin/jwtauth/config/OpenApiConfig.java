package com.jatin.jwtauth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenApiConfig — configures the OpenAPI 3 spec and Swagger UI.
 *
 * Key learning points:
 *  1. SecurityScheme "bearerAuth" tells Swagger UI to show the Authorize button.
 *  2. SecurityRequirement applies the scheme globally — every endpoint shows the lock icon.
 *  3. The JWT token entered in Swagger UI is sent as "Authorization: Bearer <token>"
 *     on every "Try it out" request automatically.
 *
 * After the app starts:
 *   Swagger UI  → http://localhost:8080/swagger-ui.html
 *   OpenAPI JSON → http://localhost:8080/api-docs
 */
@Configuration
public class OpenApiConfig {

    private static final String SECURITY_SCHEME_NAME = "bearerAuth";

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
                .info(apiInfo())
                .servers(List.of(
                        new Server().url("http://localhost:8080").description("Local development"),
                        new Server().url("http://localhost:8080").description("Docker (Nginx)")
                ))
                // Register the Bearer JWT security scheme
                .components(new Components()
                        .addSecuritySchemes(SECURITY_SCHEME_NAME, jwtSecurityScheme())
                )
                // Apply it globally — every endpoint requires Bearer by default
                // (public endpoints override this with @SecurityRequirements({}))
                .addSecurityItem(new SecurityRequirement().addList(SECURITY_SCHEME_NAME));
    }

    private Info apiInfo() {
        return new Info()
                .title("JWT Authentication API")
                .description("""
                        A production-ready stateless REST API with JWT-based authentication
                        and dynamic Role-Based Access Control (RBAC).

                        **How to use Swagger UI:**
                        1. Call `POST /api/auth/register` or `POST /api/auth/login`
                        2. Copy the `accessToken` from the response
                        3. Click the **Authorize 🔒** button at the top
                        4. Paste the token as: `Bearer <your_token>`
                        5. All subsequent requests will include the token automatically
                        """)
                .version("1.0.0")
                .contact(new Contact()
                        .name("Jatin Ghataliya")
                        .email("prajapati.jatin94@gmail.com")
                        .url("https://github.com/Jatinghataliya/JWT-Authentication-API"))
                .license(new License().name("MIT"));
    }

    private SecurityScheme jwtSecurityScheme() {
        return new SecurityScheme()
                .name(SECURITY_SCHEME_NAME)
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT")
                .description("Paste your JWT access token here (without the 'Bearer ' prefix — Swagger adds it automatically)");
    }
}
