package com.example.login.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.regex.Pattern;
import java.util.List;
import java.util.Random;

// Librerias para peticiones HTTP a Brevo
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*") 
public class LoginController {

    // 1. Definir la Expresión Regular
    // A) Debe contener el prefijo "DEV" al inicio
    // B) Debe contener 4 digitos despues del prefijo
    // C) Debe contener el apellido paterno del usuario empezando por mayuscula
    // D) Debe haber un guion ("-") despues de cada requisito exceptuando el ultimo
    // Ej. DEV-1234-Aguilar
    private static final String USUARIO_REGEX = "^DEV-[0-9]{4}-[A-Z][a-z]{1,12}$";
    private static final Pattern pattern = Pattern.compile(USUARIO_REGEX);

    // 2. Inyectamos JdbcTemplate a nivel de clase
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @PostMapping("/login")
    public ResponseEntity<String> procesarLogin(@RequestBody LoginRequest request) {


        //Validar Usuario por Expresión Regular
        if (request.usuario() == null || !pattern.matcher(request.usuario()).matches()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Fallo en Paso 1: El formato del usuario es inválido.");
        }

        // Validar Clave
        String consultaAuth = "SELECT claver FROM usuarios WHERE usuario = ? AND correo = ?";
        List<String> clavesBD = jdbcTemplate.queryForList(consultaAuth, String.class, request.usuario(), request.correo());

        // Se verifica que la consulta retorne la clave; de lo contrario el usuario, clave o correo no coinciden
        if (clavesBD.isEmpty() || !clavesBD.get(0).equals(request.clave())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Fallo en Paso 2: Usuario, clave o correo incorrectos.");
        }

        // Se genera y se guardada el código MFA
        String codigoMfa = String.format("%06d", new Random().nextInt(999999));
        
        //Se inserta el codigo creado en la bd
        String insertMfa = "INSERT INTO mfaCodigos (usuario_id, codigo, fecha_expiracion) VALUES (?, ?, NOW() + INTERVAL '5 minutes')";
        jdbcTemplate.update(insertMfa, request.usuario(), codigoMfa);

        // Envío de correo mediante API de Brevo
        String apiKey = "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";
        String jsonBody = "{"
                + "\"sender\":{\"name\":\"Seguridad App\",\"email\":\"aemauricio22@gmail.com\"},"
                + "\"to\":[{\"email\":\"" + request.correo() + "\"}],"
                + "\"subject\":\"Tu código de seguridad\","
                + "\"htmlContent\":\"<p>Tu código de acceso es: <strong>" + codigoMfa + "</strong><br>Expira en 5 minutos.</p>\""
                + "}";
        try {
            //Construir la petición HTTP
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .uri(URI.create("https://api.brevo.com/v3/smtp/email"))
                    .header("accept", "application/json")
                    .header("api-key", apiKey)
                    .header("content-type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            // Se envia la petición y se guarda la respuesta
            HttpResponse<String> response = HttpClient.newHttpClient().send(httpRequest, HttpResponse.BodyHandlers.ofString());
            
            //Se imprime el diagnóstico en la terminal de Render
            System.out.println("Código de estado Brevo: " + response.statusCode());
            System.out.println("Respuesta de Brevo: " + response.body());
            
        } catch (Exception e) {
            System.out.println("Error enviando API de correo: " + e.getMessage());
        }

        return ResponseEntity.ok("Código enviado al correo.");

    }

    @PostMapping("/verify")
    public ResponseEntity<String> verificarMfa(@RequestBody VerifyRequest request) {
        //Validación del código contra la base de datos
        String consultaMfa = "SELECT codigo FROM mfaCodigos WHERE usuario_id = ? AND codigo = ? AND fecha_expiracion > NOW()";
        List<String> validacion = jdbcTemplate.queryForList(consultaMfa, String.class, request.usuario(), request.codigo());

        if (validacion.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Código incorrecto o expirado.");
        }

        // Eliminación del código tras un uso exito
        jdbcTemplate.update("DELETE FROM mfaCodigos WHERE usuario_id = ?", request.usuario());

        return ResponseEntity.ok("Acceso final concedido.");
    }
}

// Estructura (DTO)
record LoginRequest(String usuario, String clave, String correo) {}
record VerifyRequest(String usuario, String codigo) {}

